package authentication

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateWaitGate_WaitReturnsTrueWhenAlreadyApproved(t *testing.T) {
	gate := newCertificateWaitGate(time.Second)
	gate.notify("identity-a")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	start := time.Now()
	woken, err := gate.wait(ctx, "identity-a")
	require.NoError(t, err)
	assert.True(t, woken)
	assert.Less(t, time.Since(start), 100*time.Millisecond, "an already-approved identity should not block at all")
}

func TestCertificateWaitGate_WaitWokenByLaterNotify(t *testing.T) {
	gate := newCertificateWaitGate(2 * time.Second)

	type result struct {
		woken bool
		err   error
	}
	done := make(chan result, 1)
	go func() {
		woken, err := gate.wait(context.Background(), "identity-b")
		done <- result{woken, err}
	}()

	// Give the waiter time to register itself before notifying, so this
	// exercises the "notify while a waiter is registered" path rather than
	// the "already approved" fast path covered above.
	time.Sleep(20 * time.Millisecond)
	gate.notify("identity-b")

	select {
	case r := <-done:
		require.NoError(t, r.err)
		assert.True(t, r.woken)
	case <-time.After(time.Second):
		t.Fatal("wait did not return after notify")
	}
}

func TestCertificateWaitGate_WaitTimesOutWithoutNotify(t *testing.T) {
	gate := newCertificateWaitGate(50 * time.Millisecond)

	start := time.Now()
	woken, err := gate.wait(context.Background(), "identity-c")
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.False(t, woken)
	assert.GreaterOrEqual(t, elapsed, 50*time.Millisecond)
	// Generous upper bound to avoid flaking under load while still catching
	// a gate that forgot to time out at all.
	assert.Less(t, elapsed, 2*time.Second)
}

func TestCertificateWaitGate_WaitReturnsFalseOnContextCancellation(t *testing.T) {
	gate := newCertificateWaitGate(time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	woken, err := gate.wait(ctx, "identity-d")
	require.NoError(t, err)
	assert.False(t, woken)
}

func TestCertificateWaitGate_NotifyWithNoWaitersIsSafe(t *testing.T) {
	gate := newCertificateWaitGate(time.Second)
	assert.NotPanics(t, func() { gate.notify("nobody-waiting") })

	// A subsequent wait for the same key should still see it as approved.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	woken, err := gate.wait(ctx, "nobody-waiting")
	require.NoError(t, err)
	assert.True(t, woken)
}

func TestCertificateWaitGate_NotifyIsIdempotent(t *testing.T) {
	gate := newCertificateWaitGate(time.Second)
	gate.notify("identity-e")
	assert.NotPanics(t, func() { gate.notify("identity-e") })
}

// TestCertificateWaitGate_ConcurrentWaitersAllWake runs many concurrent
// waiters on the same identity and a single concurrent notify, under -race,
// asserting every waiter wakes (none are lost and none hang until timeout).
func TestCertificateWaitGate_ConcurrentWaitersAllWake(t *testing.T) {
	const waiters = 50
	gate := newCertificateWaitGate(3 * time.Second)

	var wg sync.WaitGroup
	results := make([]bool, waiters)
	errs := make([]error, waiters)
	for i := 0; i < waiters; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = gate.wait(context.Background(), "shared-identity")
		}(i)
	}

	time.Sleep(20 * time.Millisecond)
	gate.notify("shared-identity")

	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
	case <-time.After(3 * time.Second):
		t.Fatal("not all waiters returned")
	}

	for i, woken := range results {
		require.NoErrorf(t, errs[i], "waiter %d should not have errored", i)
		assert.Truef(t, woken, "waiter %d should have been woken by notify", i)
	}

	// notify() should have fully drained its waiters, leaving nothing behind.
	waiterKeys, waiterTotal, _ := gate.sizes()
	assert.Zero(t, waiterKeys, "no waiter keys should remain after notify")
	assert.Zero(t, waiterTotal, "no waiters should remain after notify")
}

// TestCertificateWaitGate_DistinctIdentitiesDoNotInterfere ensures notifying
// one identity never wakes a waiter registered under a different identity.
func TestCertificateWaitGate_DistinctIdentitiesDoNotInterfere(t *testing.T) {
	gate := newCertificateWaitGate(80 * time.Millisecond)

	type result struct {
		woken bool
		err   error
	}
	done := make(chan result, 1)
	go func() {
		woken, err := gate.wait(context.Background(), "identity-target")
		done <- result{woken, err}
	}()
	time.Sleep(20 * time.Millisecond)
	gate.notify("identity-other")

	select {
	case r := <-done:
		require.NoError(t, r.err)
		assert.False(t, r.woken, "notifying a different identity must not wake this waiter")
	case <-time.After(time.Second):
		t.Fatal("waiter never returned")
	}
}

func TestDefaultCertificateWaitTimeout_IsPositive(t *testing.T) {
	require.Greater(t, DefaultCertificateWaitTimeout, time.Duration(0))
}

// ── Leak/bound regression coverage ──────────────────────────────────────────
//
// These tests cover the certificateWaitGate leak this file's fix addresses:
// distinct, attacker-chosen identity keys must not grow g.waiters or
// g.approved without bound, whether the waiter exits by timeout,
// context cancellation, or notification.

// TestCertificateWaitGate_TimedOutWaitersDoNotAccumulate drives many
// timed-out waits from distinct identity keys and asserts the gate's
// internal maps are completely empty afterwards - i.e. every waiter really
// removed its own entry, rather than only notify() ever doing so.
func TestCertificateWaitGate_TimedOutWaitersDoNotAccumulate(t *testing.T) {
	const attempts = 200
	gate := newCertificateWaitGate(10 * time.Millisecond)

	for i := 0; i < attempts; i++ {
		woken, err := gate.wait(context.Background(), fmt.Sprintf("attacker-identity-%d", i))
		require.NoError(t, err)
		assert.False(t, woken)
	}

	waiterKeys, waiterTotal, _ := gate.sizes()
	assert.Zerof(t, waiterKeys, "waiters map should have no keys left after %d timed-out waits", attempts)
	assert.Zerof(t, waiterTotal, "waiter count should be zero after %d timed-out waits", attempts)
}

// TestCertificateWaitGate_CancelledWaitersDoNotAccumulate is the same
// regression as above but for ctx cancellation instead of the gate's own
// timeout, run concurrently (and under -race) to also prove removeWaiter's
// locking is correct under contention.
func TestCertificateWaitGate_CancelledWaitersDoNotAccumulate(t *testing.T) {
	const attempts = 200
	gate := newCertificateWaitGate(time.Minute) // long enough that only cancellation ends these waits

	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithCancel(context.Background())
			cancel() // already cancelled: wait must return immediately
			woken, err := gate.wait(ctx, fmt.Sprintf("attacker-identity-%d", i))
			assert.NoError(t, err)
			assert.False(t, woken)
		}(i)
	}
	wg.Wait()

	waiterKeys, waiterTotal, _ := gate.sizes()
	assert.Zerof(t, waiterKeys, "waiters map should have no keys left after %d cancelled waits", attempts)
	assert.Zerof(t, waiterTotal, "waiter count should be zero after %d cancelled waits", attempts)
}

// TestCertificateWaitGate_ApprovedIsBounded proves g.approved is a bounded
// LRU, not an ever-growing map: notifying more distinct identities than the
// configured cap evicts the oldest ones instead of retaining all of them.
func TestCertificateWaitGate_ApprovedIsBounded(t *testing.T) {
	const approvedCap = 10
	gate := newBoundedCertificateWaitGate(time.Second, defaultMaxCertificateWaiters, approvedCap)

	for i := 0; i < approvedCap*5; i++ {
		gate.notify(fmt.Sprintf("identity-%d", i))
	}

	_, _, approved := gate.sizes()
	assert.LessOrEqualf(t, approved, approvedCap, "approved set should never exceed its configured capacity")

	// The oldest identities should have been evicted...
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	woken, err := gate.wait(ctx, "identity-0")
	require.NoError(t, err)
	assert.False(t, woken, "the oldest approved identity should have been evicted by the bound")

	// ...while the most recently approved identity should still be
	// remembered.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel2()
	woken2, err2 := gate.wait(ctx2, fmt.Sprintf("identity-%d", approvedCap*5-1))
	require.NoError(t, err2)
	assert.True(t, woken2, "the most recently approved identity should still be remembered")
}

// TestCertificateWaitGate_WaitAtCapacityFailsFast proves the gate refuses to
// register more than its configured maximum number of concurrently parked
// waiters - the actual fix for "distinct, attacker-chosen identity keys grow
// g.waiters without bound": even though each identity key is unique here
// (so nothing would ever notify them and removeWaiter's own cleanup would
// only fire much later, on timeout), the gate must not let the number of
// concurrently parked goroutines grow past its cap.
func TestCertificateWaitGate_WaitAtCapacityFailsFast(t *testing.T) {
	const maxWaiters = 5
	gate := newBoundedCertificateWaitGate(time.Minute, maxWaiters, defaultMaxApprovedIdentities)

	var wg sync.WaitGroup
	started := make(chan struct{}, maxWaiters)
	stop := make(chan struct{})
	for i := 0; i < maxWaiters; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			started <- struct{}{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				<-stop
				cancel()
			}()
			_, _ = gate.wait(ctx, fmt.Sprintf("legit-identity-%d", i))
		}(i)
	}
	for i := 0; i < maxWaiters; i++ {
		<-started
	}
	// Give each goroutine a moment to actually register its waiter (started
	// only proves the goroutine is running, not that wait() has taken the
	// lock and appended its channel yet).
	require.Eventually(t, func() bool {
		_, waiterTotal, _ := gate.sizes()
		return waiterTotal == maxWaiters
	}, time.Second, time.Millisecond, "all %d waiters should register", maxWaiters)

	// The gate is now full: one more distinct identity must be refused
	// immediately with ErrCertificateWaitAtCapacity, not parked.
	overflowCtx, overflowCancel := context.WithTimeout(context.Background(), time.Second)
	defer overflowCancel()
	start := time.Now()
	woken, err := gate.wait(overflowCtx, "attacker-overflow-identity")
	elapsed := time.Since(start)

	assert.False(t, woken)
	require.ErrorIsf(t, err, ErrCertificateWaitAtCapacity, "capacity error, got %v", err)
	assert.Lessf(t, elapsed, 100*time.Millisecond, "an at-capacity wait should fail fast, not park until a timeout")

	close(stop)
	wg.Wait()

	// Once the legitimate waiters have drained, capacity should free back up.
	waiterKeys, waiterTotal, _ := gate.sizes()
	assert.Zero(t, waiterKeys)
	assert.Zero(t, waiterTotal)
}

func TestErrCertificateWaitAtCapacity_IsDistinctSentinel(t *testing.T) {
	assert.NotErrorIs(t, ErrCertificateWaitAtCapacity, ErrCertificateTimeout)
}
