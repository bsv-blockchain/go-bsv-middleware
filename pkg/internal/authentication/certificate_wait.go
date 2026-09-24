package authentication

import (
	"container/list"
	"context"
	"errors"
	"sync"
	"time"
)

// DefaultCertificateWaitTimeout mirrors the TS reference's
// DEFAULT_REQUEST_TIMEOUT_MS (auth-express-middleware's ExpressTransport,
// packages/middleware/auth-express-middleware/src/index.ts): the default
// window a protected general request will wait for a still-pending
// certificate exchange to complete before giving up with CERTIFICATE_TIMEOUT.
const DefaultCertificateWaitTimeout = 30 * time.Second

// defaultMaxCertificateWaiters bounds how many general requests can be
// parked in certificateWaitGate.wait at the same time, summed across every
// identity key. This mirrors the TS reference's own defence against
// unbounded concurrent-request resource consumption: ExpressTransport
// tracks its own equivalent of a parked wait (openNextHandlers) as part of
// the single pool assertPendingCapacity() bounds with
// DEFAULT_MAX_PENDING_REQUESTS (1_000), refusing new work with a 503
// ERR_AUTH_CAPACITY once the pool is full. This is deliberately a global
// bound, not a per-identity one: as documented on wait() below, an attacker
// can make go-sdk's Peer return auth.ErrNotAuthenticated - the only trigger
// for a wait() call - for an unbounded number of distinct, entirely
// attacker-chosen identity keys without ever proving ownership of any of
// them, so a per-key limit alone would not bound the number of parked
// goroutines/connections.
const defaultMaxCertificateWaiters = 1_000

// defaultMaxApprovedIdentities bounds how many identity keys
// certificateWaitGate.approved remembers as already certificate-approved.
// An identity key only needs to be remembered here for the short window
// between a notify() call and any wait() call racing it (see wait's doc
// comment for why that race exists): once go-sdk's Peer has marked a
// session authenticated, it stops returning auth.ErrNotAuthenticated for
// it, so GeneralRequestHandler never calls wait() for that identity again.
// Bounding this (as a bounded-LRU, oldest evicted first) prevents an
// attacker who drives an unbounded number of distinct, attacker-chosen
// identity keys through certificate approval from growing this map
// forever; genuine callers only ever need the most recent handful of
// entries to be present.
const defaultMaxApprovedIdentities = 10_000

// ErrCertificateWaitAtCapacity is returned by certificateWaitGate.wait when
// the gate already has defaultMaxCertificateWaiters requests parked across
// every identity key combined, mirroring the TS reference's
// ERR_AUTH_CAPACITY (auth-express-middleware's assertPendingCapacity /
// respondWithProtocolError).
var ErrCertificateWaitAtCapacity = errors.New("certificate wait gate is at capacity")

// certificateWaitGate lets a general request that arrived before its
// session's certificate exchange completed find out, from a different HTTP
// request's goroutine, the moment that exchange finishes - mirroring the TS
// reference's ExpressTransport#scheduleNextOrCertificateWait, which holds a
// protected-resource request open until either the application approves the
// peer's certificates (via its onCertificatesReceived callback) or
// requestTimeoutMs elapses (408 CERTIFICATE_TIMEOUT).
//
// It is only ever constructed when the server both requests certificates
// (Config.CertificatesToRequest needs them) and registers
// Config.OnCertificatesReceived - see NewMiddleware. A server that does
// neither never allocates or consults one, so this adds no behaviour change
// for the common case.
//
// Both of its maps are bounded (see defaultMaxCertificateWaiters and
// defaultMaxApprovedIdentities) rather than growing without limit, and
// wait() removes its own entry from waiters on every exit path (not only
// when notified) - see wait's doc comment for why an attacker-chosen,
// entirely unauthenticated identity key can reach this gate at all, which
// is exactly what makes both bounds necessary.
type certificateWaitGate struct {
	timeout     time.Duration
	maxWaiters  int
	maxApproved int

	mu sync.Mutex
	// approved is a bounded LRU (oldest evicted first) of identity keys
	// notify() has approved; approvedOrder tracks eviction order, front is
	// oldest. Each map value points at that identity key's node in
	// approvedOrder so both notify() and a matching wait() can refresh
	// recency in O(1).
	approved      map[string]*list.Element
	approvedOrder *list.List
	// waiters maps an identity key to the channels of every wait() call
	// currently parked for it. waiterCount is the total number of channels
	// across every key, maintained incrementally so wait() can check
	// capacity in O(1) instead of summing every slice's length.
	waiters     map[string][]chan struct{}
	waiterCount int
}

func newCertificateWaitGate(timeout time.Duration) *certificateWaitGate {
	return newBoundedCertificateWaitGate(timeout, defaultMaxCertificateWaiters, defaultMaxApprovedIdentities)
}

// newBoundedCertificateWaitGate is newCertificateWaitGate with explicit caps,
// for tests that need to exercise eviction/capacity behaviour without
// registering thousands of identities.
func newBoundedCertificateWaitGate(timeout time.Duration, maxWaiters, maxApproved int) *certificateWaitGate {
	return &certificateWaitGate{
		timeout:       timeout,
		maxWaiters:    maxWaiters,
		maxApproved:   maxApproved,
		approved:      make(map[string]*list.Element),
		approvedOrder: list.New(),
		waiters:       make(map[string][]chan struct{}),
	}
}

// notify records identityKey's certificate exchange as complete and wakes
// every request currently blocked in wait for it. Safe to call whether or
// not anything is waiting, and safe to call more than once for the same key.
func (g *certificateWaitGate) notify(identityKey string) {
	g.mu.Lock()
	g.markApprovedLocked(identityKey)
	waiters := g.waiters[identityKey]
	delete(g.waiters, identityKey)
	g.waiterCount -= len(waiters)
	g.mu.Unlock()

	for _, ch := range waiters {
		close(ch)
	}
}

// markApprovedLocked records identityKey as approved, moving it to the most
// recently used end of the eviction order if it is already present, and
// evicts the oldest entry/entries once the bound is exceeded. Must be
// called with g.mu held.
func (g *certificateWaitGate) markApprovedLocked(identityKey string) {
	if el, ok := g.approved[identityKey]; ok {
		g.approvedOrder.MoveToBack(el)
		return
	}
	el := g.approvedOrder.PushBack(identityKey)
	g.approved[identityKey] = el
	for g.approvedOrder.Len() > g.maxApproved {
		oldest := g.approvedOrder.Front()
		if oldest == nil {
			break
		}
		g.approvedOrder.Remove(oldest)
		delete(g.approved, oldest.Value.(string))
	}
}

// wait blocks until identityKey is notified, the gate's timeout elapses, or
// ctx is done - whichever happens first. It returns (true, nil) when woken
// by a notification (the caller should re-check whether it can now
// proceed), (false, nil) on timeout/cancellation, or (false,
// ErrCertificateWaitAtCapacity) when the gate is already at
// defaultMaxCertificateWaiters parked waiters and refuses to register
// another one. Checking g.approved first, under the same lock used to
// register the waiter, closes the gap between an already-past notify() and
// this call: nothing can be missed between the two.
//
// Callers should note that go-sdk's auth.Peer reports the specific
// condition this gate exists for - a general message arriving on a session
// whose required certificate exchange has not completed -
// (auth.ErrNotAuthenticated) *before* it verifies that general message's
// own BRC-104 signature (auth.Peer.handleGeneralMessage checks
// session.IsAuthenticated ahead of any signature parsing/verification), and
// a session can reach that not-yet-authenticated state from an entirely
// unsigned /.well-known/auth initialRequest (auth.Peer.handleInitialRequest
// performs no signature check at all - it only needs a syntactically valid,
// not-yet-replayed identityKey/initialNonce pair). So a caller reaching
// wait() has not necessarily proven ownership of identityKey's private key,
// and an attacker can drive an unbounded number of distinct, entirely
// self-chosen identity keys through this path for the cost of one extra
// handshake round trip each. That is a go-sdk behaviour this middleware
// cannot change from here (see auth.Peer.handleGeneralMessage / go-sdk's
// scope), so the defence applied at this layer is capacity, not identity:
// wait() bounds the number of concurrently parked callers regardless of how
// many distinct identity keys they claim (defaultMaxCertificateWaiters,
// mirroring the TS reference's own maxPendingRequests/
// assertPendingCapacity bound on concurrent in-flight requests), and every
// parked waiter is removed on every exit path so the bound is also true
// over time, not just at any single instant.
func (g *certificateWaitGate) wait(ctx context.Context, identityKey string) (bool, error) {
	g.mu.Lock()
	if el, ok := g.approved[identityKey]; ok {
		g.approvedOrder.MoveToBack(el)
		g.mu.Unlock()
		return true, nil
	}
	if g.waiterCount >= g.maxWaiters {
		g.mu.Unlock()
		return false, ErrCertificateWaitAtCapacity
	}
	ch := make(chan struct{})
	g.waiters[identityKey] = append(g.waiters[identityKey], ch)
	g.waiterCount++
	g.mu.Unlock()

	timer := time.NewTimer(g.timeout)
	defer timer.Stop()

	select {
	case <-ch:
		return true, nil
	case <-timer.C:
		g.removeWaiter(identityKey, ch)
		return false, nil
	case <-ctx.Done():
		g.removeWaiter(identityKey, ch)
		return false, nil
	}
}

// removeWaiter drops ch from identityKey's waiter list, decrementing
// waiterCount and deleting the map entry entirely once it is empty. It is a
// safe no-op if ch is not present (e.g. notify() already removed it,
// racing this call's timeout/ctx-cancellation path) since both this method
// and notify() only ever remove an entry they actually find, under the
// same lock, so a channel is never double-counted out of waiterCount.
func (g *certificateWaitGate) removeWaiter(identityKey string, ch chan struct{}) {
	g.mu.Lock()
	defer g.mu.Unlock()

	entries := g.waiters[identityKey]
	for i, c := range entries {
		if c == ch {
			entries = append(entries[:i], entries[i+1:]...)
			g.waiterCount--
			if len(entries) == 0 {
				delete(g.waiters, identityKey)
			} else {
				g.waiters[identityKey] = entries
			}
			return
		}
	}
}

// sizes reports the gate's current internal footprint, for tests asserting
// it does not grow without bound.
func (g *certificateWaitGate) sizes() (waiterKeys, waiterTotal, approved int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.waiters), g.waiterCount, len(g.approved)
}
