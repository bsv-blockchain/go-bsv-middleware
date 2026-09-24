// Package auth_test runs the pinned ts-stack auth/brc31-handshake.json
// conformance vectors against the real go-bsv-middleware BRC-103/BRC-104
// HTTP auth server (pkg/internal/authentication + pkg/middleware), unlike the
// TS reference dispatcher (conformance/runner/ts/dispatchers/auth.ts), which
// has no server of its own to exercise (@bsv/sdk is a client-side library)
// and therefore only checks that each vector's own documented fields are
// internally consistent. Since go-bsv-middleware DOES have a real server,
// these tests drive it with real HTTP requests (a real handshake through
// go-sdk's Peer/AuthFetch where one is needed) and assert its observable
// behaviour against each vector's `expected`.
package auth_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/authpayload"
	"github.com/bsv-blockchain/go-sdk/auth/brc104"
	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	clients "github.com/bsv-blockchain/go-sdk/auth/clients/authhttp"
	"github.com/bsv-blockchain/go-sdk/auth/transports"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/go-softwarelab/common/pkg/to"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/conformance"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/testabilities"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/testabilities/testusers"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware"
)

// TestBRC31HandshakeConformance runs every vector in auth/brc31-handshake.json
// against a real server built from this repo's auth middleware.
func TestBRC31HandshakeConformance(t *testing.T) {
	file := conformance.Load(t, "auth/brc31-handshake.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		switch v.ID {
		case "auth.brc31-handshake.1", "auth.brc31-handshake.2":
			testInitialRequestShape(t, v)
		case "auth.brc31-handshake.3":
			testWellKnownAuthFieldError(t, v)
		case "auth.brc31-handshake.4":
			testWellKnownAuthFieldError(t, v)
		case "auth.brc31-handshake.5":
			testAuthenticatedGeneralRequest(t, v)
		case "auth.brc31-handshake.6":
			testAuthenticatedGeneralRequest(t, v)
		case "auth.brc31-handshake.7":
			testMissingGeneralSignatureHeader(t, v)
		case "auth.brc31-handshake.8":
			testBadGeneralSignature(t, v)
		case "auth.brc31-handshake.9":
			testAllowUnauthenticatedPassthrough(t, v)
		case "auth.brc31-handshake.10":
			testCertificateTimeout(t, v)
		case "auth.brc31-handshake.11":
			testRequestedCertificatesInResponse(t, v)
		case "auth.brc31-handshake.12":
			testAuthMessageSchema(t, v)
		case "auth.brc31-handshake.13":
			testRequestIDFormat(t, v)
		case "auth.brc31-handshake.14":
			testInitialRequestReplayPrevention(t, v)
		case "auth.brc31-handshake.15":
			testPubKeyHexFormat(t, v)
		case "auth.brc31-handshake.16":
			testResponseSigningFailure(t, v)
		case "auth.brc31-handshake.17", "auth.brc31-handshake.18", "auth.brc31-handshake.19",
			"auth.brc31-handshake.20", "auth.brc31-handshake.21":
			testResponsePreimage(t, v)
		default:
			t.Fatalf("unhandled vector %s: add a case to the dispatch switch", v.ID)
		}
	})
}

// ── Shared helpers ──────────────────────────────────────────────────────────

// decodeJSONObject decodes an expected/input map that may use bracket-style
// keys from the vector JSON (e.g. "body_shape") straight into map[string]any.
func decodeJSONObject(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	return m
}

func asObject(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()
	v, ok := m[key]
	require.Truef(t, ok, "expected key %q to be present", key)
	obj, ok := v.(map[string]any)
	require.Truef(t, ok, "expected key %q to be an object, got %T", key, v)
	return obj
}

func asString(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	v, ok := m[key]
	require.Truef(t, ok, "expected key %q to be present", key)
	s, ok := v.(string)
	require.Truef(t, ok, "expected key %q to be a string, got %T", key, v)
	return s
}

func asInt(t *testing.T, m map[string]any, key string) int {
	t.Helper()
	v, ok := m[key]
	require.Truef(t, ok, "expected key %q to be present", key)
	f, ok := v.(float64)
	require.Truef(t, ok, "expected key %q to be a number, got %T", key, v)
	return int(f)
}

// assertBodyShape checks a decoded JSON response body against a vector's
// body_shape spec: a value of "string"/"array"/"object" is a type
// descriptor, anything else (e.g. a literal messageType/version) is the
// exact expected value.
func assertBodyShape(t *testing.T, body map[string]any, shape map[string]any) {
	t.Helper()
	for key, spec := range shape {
		val, ok := body[key]
		if !assert.Truef(t, ok, "response body missing key %q", key) {
			continue
		}
		specStr, _ := spec.(string)
		switch specStr {
		case "string":
			assert.IsTypef(t, "", val, "field %q should be a string, got %T", key, val)
		case "array":
			_, isArray := val.([]any)
			assert.Truef(t, isArray, "field %q should be a JSON array, got %T", key, val)
		case "object":
			_, isObject := val.(map[string]any)
			assert.Truef(t, isObject, "field %q should be a JSON object, got %T", key, val)
		default:
			assert.Equalf(t, spec, val, "field %q should equal %v, got %v", key, spec, val)
		}
	}
}

// postRawJSON POSTs a raw JSON body directly (bypassing go-sdk's client) so
// tests can send exactly the bytes a vector documents, including
// deliberately incomplete ones.
func postRawJSON(t *testing.T, serverURL *url.URL, path string, body map[string]any) *http.Response {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err)

	target := *serverURL
	target.Path = path

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target.String(), bytes.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// doRawRequest issues a request with exactly the given headers (no auth
// computed), mirroring a vector's input.headers verbatim.
func doRawRequest(t *testing.T, serverURL *url.URL, method, path string, headers map[string]string, body []byte) *http.Response {
	t.Helper()
	target := *serverURL
	target.Path = path

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, target.String(), bodyReader)
	require.NoError(t, err)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// assertErrorResponse checks the BRC-103/104 wire error shape this
// middleware now emits: {"status":"error","code":"..."}. The caller owns
// closing resp.Body.
func assertErrorResponse(t *testing.T, resp *http.Response, expectedStatus int, expectedCode string) {
	t.Helper()

	assert.Equalf(t, expectedStatus, resp.StatusCode, "unexpected status code")

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body), "error response body should be JSON")
	assert.Equal(t, "error", body["status"])
	assert.Equal(t, expectedCode, body["code"])
}

// ── Vectors 1 & 2: initialRequest -> initialResponse shape ──────────────────

func testInitialRequestShape(t *testing.T, v conformance.Vector) {
	input := decodeJSONObject(t, v.Input)
	expected := decodeJSONObject(t, v.Expected)

	given := testabilities.Given(t)
	authMiddleware := given.Middleware().NewAuth()
	cleanup := given.Server().WithMiddleware(authMiddleware).
		WithRoute("/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }).
		Started()
	defer cleanup()

	reqBody := asObject(t, input, "body")
	resp := postRawJSON(t, given.Server().URL(), asString(t, input, "path"), reqBody)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, asInt(t, expected, "status"), resp.StatusCode)

	var respBody map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&respBody))

	bodyShape := asObject(t, expected, "body_shape")
	assertBodyShape(t, respBody, bodyShape)

	// The root cause bug this whole conformance pass exists for: @bsv/sdk 2.8's
	// strict AuthMessageValidation requires requestedCertificates.certifiers
	// and .types as lowercase keys (never Go's exported "Certifiers"/
	// "CertificateTypes").
	requestedCertificates, ok := respBody["requestedCertificates"].(map[string]any)
	if assert.True(t, ok, "requestedCertificates should be a JSON object") {
		_, hasCertifiers := requestedCertificates["certifiers"]
		_, hasTypes := requestedCertificates["types"]
		assert.True(t, hasCertifiers, "requestedCertificates must have a lowercase 'certifiers' key")
		assert.True(t, hasTypes, "requestedCertificates must have a lowercase 'types' key")
	}
}

// ── Vectors 3 & 4: missing identityKey/initialNonce on /.well-known/auth ────

func testWellKnownAuthFieldError(t *testing.T, v conformance.Vector) {
	input := decodeJSONObject(t, v.Input)
	expected := decodeJSONObject(t, v.Expected)

	given := testabilities.Given(t)
	authMiddleware := given.Middleware().NewAuth()
	cleanup := given.Server().WithMiddleware(authMiddleware).
		WithRoute("/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }).
		Started()
	defer cleanup()

	reqBody := asObject(t, input, "body")
	resp := postRawJSON(t, given.Server().URL(), asString(t, input, "path"), reqBody)
	defer func() { _ = resp.Body.Close() }()

	expectedBody := asObject(t, expected, "body")
	assertErrorResponse(t, resp, asInt(t, expected, "status"), asString(t, expectedBody, "code"))
}

// ── Vector 14: replay prevention on the /.well-known/auth handshake ────────

// testInitialRequestReplayPrevention exercises a real BRC-103 initialRequest
// nonce replay end to end (the same initialNonce submitted twice) and
// asserts this vector's own `expected` (401/ERR_AUTH_FAILED).
//
// Maintainer decision (superseding this test's round-2 version, which
// instead asserted 500/ERR_INTERNAL_SERVER_ERROR): the conformance vector is
// the source of truth for what go-bsv-middleware must do, even where the
// live TS reference's own behaviour is inconsistent between its two auth
// paths. Reading the TS reference confirms that inconsistency exists:
//   - On the *general* (already-authenticated data request) message path,
//     auth-express-middleware's handleGeneralMessage classifies a replayed
//     nonce as 401/ERR_AUTH_FAILED via a regex over the error message
//     (/nonce|signature|session|auth version/i - see the same package's
//     ExpressTransportHardening.test.ts "maps peer processing failures to
//     stable public errors" table). This is exactly this vector's expected
//     status/code.
//   - On the /.well-known/auth *handshake* path, though,
//     handleWellKnownAuth's messageCallback .catch() unconditionally
//     responds 500/ERR_INTERNAL_SERVER_ERROR for any handshake failure at
//     all, doing no message-based classification (confirmed directly by the
//     same test file's "cleans handshake state when listener setup or peer
//     processing fails" case) - so a replayed initialRequest, which only
//     ever reaches the handshake path, gets 500 in the live TS reference
//     today, not the 401 its own general-message path would give the same
//     underlying failure.
//
// go-bsv-middleware's toHTTPError therefore maps auth.ErrReplayedNonce to
// 401/ERR_AUTH_FAILED uniformly on both paths (see middleware.go), matching
// this vector rather than reproducing the TS reference's own upstream
// inconsistency.
func testInitialRequestReplayPrevention(t *testing.T, v conformance.Vector) {
	input := decodeJSONObject(t, v.Input)
	expected := decodeJSONObject(t, v.Expected)

	given := testabilities.Given(t)
	authMiddleware := given.Middleware().NewAuth()
	cleanup := given.Server().WithMiddleware(authMiddleware).
		WithRoute("/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }).
		Started()
	defer cleanup()

	reqBody := asObject(t, input, "body")

	first := postRawJSON(t, given.Server().URL(), asString(t, input, "path"), reqBody)
	require.Equalf(t, http.StatusOK, first.StatusCode, "the first delivery of this initialRequest nonce should succeed")
	_ = first.Body.Close()

	replay := postRawJSON(t, given.Server().URL(), asString(t, input, "path"), reqBody)
	defer func() { _ = replay.Body.Close() }()

	expectedBody := asObject(t, expected, "body")
	assertErrorResponse(t, replay, asInt(t, expected, "status"), asString(t, expectedBody, "code"))
}

// ── Vectors 5 & 6: authenticated GET/POST via a real handshake ──────────────

func testAuthenticatedGeneralRequest(t *testing.T, v conformance.Vector) {
	input := decodeJSONObject(t, v.Input)
	expected := decodeJSONObject(t, v.Expected)

	given := testabilities.Given(t)
	authMiddleware := given.Middleware().NewAuth()
	cleanup := given.Server().WithMiddleware(authMiddleware).
		WithRoute("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			_ = r.Body.Close()
		}).
		Started()
	defer cleanup()

	alice := testusers.NewAlice(t)
	capture := &captureTransport{}
	httpClient := clients.New(alice.Wallet(), clients.WithHttpClient(&http.Client{Transport: capture}))

	serverURL := given.Server().URL()
	serverURL.Path = asString(t, input, "path")

	opts := &clients.SimplifiedFetchRequestOptions{
		Method:       asString(t, input, "method"),
		RetryCounter: to.Ptr(1),
	}
	if bodyRaw, ok := input["body"]; ok {
		body, err := json.Marshal(bodyRaw)
		require.NoError(t, err)
		opts.Body = body
		opts.Headers = map[string]string{"Content-Type": "application/json"}
	}

	resp, err := httpClient.Fetch(t.Context(), serverURL.String(), opts)
	require.NoError(t, err, "authenticated fetch should succeed")
	assert.Equal(t, asInt(t, expected, "status"), resp.StatusCode)
	_ = resp.Body.Close()

	// The vector's response_headers_required describes the real wire response
	// the server sends, not go-sdk AuthFetch's own reconstructed
	// *http.Response (which is rebuilt from the signed application payload
	// alone and never carries the x-bsv-auth-* transport headers).
	wireHeaders := capture.lastResponseHeaders()
	require.NotNil(t, wireHeaders, "expected to capture the real HTTP response")

	requiredHeadersRaw, ok := expected["response_headers_required"].([]any)
	require.True(t, ok, "expected.response_headers_required should be an array")
	require.NotEmpty(t, requiredHeadersRaw)
	for _, h := range requiredHeadersRaw {
		name, ok := h.(string)
		require.True(t, ok)
		assert.NotEmptyf(t, wireHeaders.Get(name), "response should have header %s", name)
	}
}

// ── Vector 7: general request with no signature header at all ───────────────

func testMissingGeneralSignatureHeader(t *testing.T, v conformance.Vector) {
	input := decodeJSONObject(t, v.Input)
	expected := decodeJSONObject(t, v.Expected)

	given := testabilities.Given(t)
	authMiddleware := given.Middleware().NewAuth()
	cleanup := given.Server().WithMiddleware(authMiddleware).
		WithRoute("/", func(w http.ResponseWriter, _ *http.Request) {
			assert.Fail(t, "protected handler should not run for an incomplete auth attempt")
		}).
		Started()
	defer cleanup()

	headers := map[string]string{}
	for k, val := range asObject(t, input, "headers") {
		headers[k] = val.(string)
	}

	resp := doRawRequest(t, given.Server().URL(), asString(t, input, "method"), asString(t, input, "path"), headers, nil)

	expectedBody := asObject(t, expected, "body")
	assert.Equal(t, asInt(t, expected, "status"), resp.StatusCode)
	var respBody map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&respBody))
	_ = resp.Body.Close()
	assert.Equal(t, asString(t, expectedBody, "status"), respBody["status"])
	// The vector only asserts body.status; this middleware also returns a
	// concrete code for the same "incomplete authentication attempt" family.
	assert.Equal(t, "UNAUTHORIZED", respBody["code"])
}

// ── Vector 8: general request with a well-formed but cryptographically
//    invalid signature ────────────────────────────────────────────────────

// captureTransport snapshots the last outgoing request's method/URL/headers,
// and the last raw response's headers, at the real HTTP wire level - i.e.
// before go-sdk's AuthFetch verifies and unwraps the general-message
// response into a synthetic *http.Response reconstructed only from the
// signed application payload (which never carries the x-bsv-auth-* wire
// headers). Vectors 5/6/8 need to see what the server actually put on the
// wire, and vector 8 needs to replay a mutated copy of a real, successfully
// authenticated request directly (bypassing go-sdk's client, which would
// refuse to send an invalid signature itself).
type captureTransport struct {
	mu         sync.Mutex
	req        *http.Request
	respHead   http.Header
	respStatus int
	respBody   []byte
}

func (c *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	resp, err := http.DefaultTransport.RoundTrip(req)

	c.mu.Lock()
	c.req = clone
	if resp != nil {
		c.respHead = resp.Header.Clone()
		c.respStatus = resp.StatusCode
		// Buffer the body here, at the real HTTP transport layer, and hand the
		// caller (e.g. go-sdk's AuthFetch) an equivalent replacement reader.
		// This lets a test inspect the exact wire response even when AuthFetch
		// itself errors out trying to interpret it (e.g. a general-message
		// response with no x-bsv-auth-* envelope, which AuthFetch reports as
		// its own transport-level error rather than surfacing the raw body -
		// see auth/transports/simplified_http_transport.go's
		// authMessageFromGeneralMessageResponse).
		if resp.Body != nil {
			bodyBytes, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr == nil {
				c.respBody = bodyBytes
			}
			resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	}
	c.mu.Unlock()

	return resp, err
}

func (c *captureTransport) last() *http.Request {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.req
}

func (c *captureTransport) lastResponseHeaders() http.Header {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.respHead
}

// lastRawResponse returns the status code and body of the most recent real
// HTTP response this transport observed, captured before go-sdk's AuthFetch
// gets a chance to interpret (and potentially reject) it.
func (c *captureTransport) lastRawResponse() (status int, body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.respStatus, c.respBody
}

// unrelatedButWellFormedSignature produces a genuine, structurally valid
// DER-encoded ECDSA signature from an unrelated throwaway key over unrelated
// data. Bit-flipping a real signature's bytes risks landing outside the
// curve's valid range, which fails EC verification with an *error* (mapped
// to 500) rather than a clean Valid:false (mapped to 401 ERR_AUTH_FAILED);
// a fresh, independently valid signature parses and verifies cleanly while
// still not matching the expected payload/key, giving a well-formed but
// wrong signature - exactly what vector 8 describes.
func unrelatedButWellFormedSignature(t *testing.T) string {
	t.Helper()
	key, err := ec.NewPrivateKey()
	require.NoError(t, err)
	hash := sha256.Sum256([]byte("conformance test: unrelated payload"))
	sig, err := key.Sign(hash[:])
	require.NoError(t, err)
	return hex.EncodeToString(sig.Serialize())
}

func testBadGeneralSignature(t *testing.T, v conformance.Vector) {
	expected := decodeJSONObject(t, v.Expected)

	given := testabilities.Given(t)
	authMiddleware := given.Middleware().NewAuth()
	cleanup := given.Server().WithMiddleware(authMiddleware).
		WithRoute("/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }).
		Started()
	defer cleanup()

	alice := testusers.NewAlice(t)
	capture := &captureTransport{}
	httpClient := clients.New(alice.Wallet(), clients.WithHttpClient(&http.Client{Transport: capture}))

	serverURL := given.Server().URL()
	serverURL.Path = "/api/resource"

	resp, err := httpClient.Fetch(t.Context(), serverURL.String(), &clients.SimplifiedFetchRequestOptions{
		Method:       http.MethodGet,
		RetryCounter: to.Ptr(1),
	})
	require.NoError(t, err, "the legitimate request used as a base should succeed")
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	_ = resp.Body.Close()

	legit := capture.last()
	require.NotNil(t, legit, "expected the client's real authenticated request to have been captured")
	signature := legit.Header.Get(brc104.HeaderSignature)
	require.NotEmpty(t, signature)

	badReq, err := http.NewRequestWithContext(t.Context(), legit.Method, legit.URL.String(), nil)
	require.NoError(t, err)
	badReq.Header = legit.Header.Clone()
	badReq.Header.Set(brc104.HeaderSignature, unrelatedButWellFormedSignature(t))

	badResp, err := http.DefaultClient.Do(badReq)
	require.NoError(t, err)
	defer func() { _ = badResp.Body.Close() }()

	expectedBody := asObject(t, expected, "body")
	assertErrorResponse(t, badResp, asInt(t, expected, "status"), asString(t, expectedBody, "code"))
}

// ── Vector 9: allowUnauthenticated passthrough ──────────────────────────────

func testAllowUnauthenticatedPassthrough(t *testing.T, v conformance.Vector) {
	input := decodeJSONObject(t, v.Input)
	expected := decodeJSONObject(t, v.Expected)

	given := testabilities.Given(t)
	authMiddleware := given.Middleware().NewAuth(middleware.WithAuthAllowUnauthenticated())

	var capturedIdentity *ec.PublicKey
	var capturedErr error
	cleanup := given.Server().WithMiddleware(authMiddleware).
		WithRoute("/", func(w http.ResponseWriter, r *http.Request) {
			capturedIdentity, capturedErr = middleware.ShouldGetIdentity(r.Context())
			w.WriteHeader(http.StatusOK)
		}).
		Started()
	defer cleanup()

	headers := map[string]string{}
	for k, val := range asObject(t, input, "headers") {
		headers[k] = val.(string)
	}

	resp := doRawRequest(t, given.Server().URL(), asString(t, input, "method"), asString(t, input, "path"), headers, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, asInt(t, expected, "status"), resp.StatusCode)
	require.NoError(t, capturedErr, "handler should be able to read an identity from the request context")
	assert.True(t, middleware.IsUnknownIdentity(capturedIdentity),
		"expected the unauthenticated passthrough identity (Go's equivalent of the TS 'unknown' sentinel)")
}

// ── Vector 10: certificate wait -> 408 CERTIFICATE_TIMEOUT ──────────────────

// testCertificateTimeout exercises go-bsv-middleware's opt-in certificate-wait
// behaviour (pkg/internal/authentication/certificate_wait.go), added to
// mirror the TS reference's certificate-wait logic (auth-express-middleware's
// ExpressTransport#scheduleNextOrCertificateWait): when the server both
// requires certificates (CertificatesToRequest) and registers an
// OnCertificatesReceived listener (middleware.WithAuthCertificatesReceivedListener),
// a general request that arrives before its session's certificate exchange
// completes is held open rather than rejected immediately, and fails with
// 408 CERTIFICATE_TIMEOUT once the configured wait elapses with no exchange
// completing. A server that does not register a listener is unaffected
// (see the "no listener" case in TestBRC31HandshakeConformance's other
// vectors, none of which configure one).
//
// This is driven with a bare go-sdk auth.Peer client rather than go-sdk's
// AuthFetch: AuthFetch automatically answers a server's certificate request
// via its own ListenForCertificatesRequested handler (authhttp.go), which
// would satisfy the exchange this test needs to leave pending. A bare Peer
// with no certificate listeners registered completes the initial handshake
// normally - the client side never gates on IsAuthenticated, only the
// server does (see auth.Peer.handleGeneralMessage) - but never sends a
// certificateResponse, exactly matching this vector's own documented
// scenario: "client never provides them".
func testCertificateTimeout(t *testing.T, v conformance.Vector) {
	expected := decodeJSONObject(t, v.Expected)

	const waitTimeout = 150 * time.Millisecond
	certType := wallet.CertificateType{}

	given := testabilities.Given(t)
	authMiddleware := given.Middleware().NewAuth(
		middleware.WithAuthCertificatesToRequest(&utils.RequestedCertificateSet{
			CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{certType: []string{"name"}},
		}),
		middleware.WithAuthCertificatesReceivedListener(func(context.Context, *ec.PublicKey, []*certificates.VerifiableCertificate) error {
			t.Error("OnCertificatesReceived should never be invoked: this client never sends a certificateResponse")
			return nil
		}),
		middleware.WithAuthCertificateWaitTimeout(waitTimeout),
	)
	cleanup := given.Server().WithMiddleware(authMiddleware).
		WithRoute("/", func(http.ResponseWriter, *http.Request) {
			assert.Fail(t, "protected handler should not run while certificates are still pending")
		}).
		Started()
	defer cleanup()

	capture := &captureTransport{}
	clientTransport, err := transports.NewSimplifiedHTTPTransport(&transports.SimplifiedHTTPTransportOptions{
		BaseURL: given.Server().URL().String(),
		Client:  &http.Client{Transport: capture},
	})
	require.NoError(t, err)

	clientKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	clientWallet, err := wallet.NewCompletedProtoWallet(clientKey)
	require.NoError(t, err)

	clientPeer := auth.NewPeer(&auth.PeerOptions{
		Wallet:         clientWallet,
		Transport:      clientTransport,
		SessionManager: auth.NewSessionManager(),
	})
	// Without a registered listener, go-sdk's Peer.sendCertificates falls
	// back to auto-generating certificates via utils.GetVerifiableCertificates
	// and sending them unprompted (see auth/peer.go). Registering a no-op
	// listener suppresses that default and is what actually produces this
	// vector's documented scenario: "client never provides them".
	clientPeer.ListenForCertificatesRequested(func(context.Context, *ec.PublicKey, utils.RequestedCertificateSet) error {
		return nil
	})

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "/api/resource", nil)
	require.NoError(t, err)
	requestID := make([]byte, brc104.RequestIDLength)
	_, err = rand.Read(requestID)
	require.NoError(t, err)
	payload, err := authpayload.FromHTTPRequest(requestID, req)
	require.NoError(t, err)

	// maxWaitTime here only bounds the handshake (initialRequest/
	// initialResponse) that ToPeer performs before sending the general
	// message; it completes immediately over the loopback connection. The
	// certificate wait itself is bounded by the server's waitTimeout above,
	// enforced independently of this value.
	sendErr := clientPeer.ToPeer(t.Context(), payload, nil, 5000)
	require.Error(t, sendErr, "go-sdk's client-side transport should fail to interpret a CERTIFICATE_TIMEOUT error body as a valid general-message envelope")

	status, body := capture.lastRawResponse()
	var respBody map[string]any
	require.NoError(t, json.Unmarshal(body, &respBody), "error response body should be JSON")

	expectedBody := asObject(t, expected, "body")
	assert.Equal(t, asInt(t, expected, "status"), status)
	assert.Equal(t, "error", respBody["status"])
	assert.Equal(t, asString(t, expectedBody, "code"), respBody["code"])
}

// ── Vector 11: requestedCertificates reflects server configuration ─────────

func testRequestedCertificatesInResponse(t *testing.T, v conformance.Vector) {
	input := decodeJSONObject(t, v.Input)
	expected := decodeJSONObject(t, v.Expected)

	certifierKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	certSet := &utils.RequestedCertificateSet{
		Certifiers:       []*ec.PublicKey{certifierKey.PubKey()},
		CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{},
	}

	given := testabilities.Given(t)
	authMiddleware := given.Middleware().NewAuth(middleware.WithAuthCertificatesToRequest(certSet))
	cleanup := given.Server().WithMiddleware(authMiddleware).
		WithRoute("/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }).
		Started()
	defer cleanup()

	reqBody := asObject(t, input, "body")
	resp := postRawJSON(t, given.Server().URL(), asString(t, input, "path"), reqBody)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, asInt(t, expected, "status"), resp.StatusCode)

	var respBody map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&respBody))

	includes := asObject(t, expected, "response_body_includes")
	assert.Equal(t, "present", includes["requestedCertificates"])

	requestedCertificates, ok := respBody["requestedCertificates"].(map[string]any)
	require.True(t, ok, "requestedCertificates should be present as a JSON object")
	certifiers, ok := requestedCertificates["certifiers"].([]any)
	require.True(t, ok, "requestedCertificates.certifiers should be a JSON array")
	assert.NotEmpty(t, certifiers, "requestedCertificates.certifiers should reflect the configured certifier")
}

// ── Vector 12: AuthMessage schema (structural, no HTTP) ─────────────────────

func testAuthMessageSchema(t *testing.T, v conformance.Vector) {
	input := decodeJSONObject(t, v.Input)
	expected := decodeJSONObject(t, v.Expected)

	require.True(t, input["_schema_check"].(bool))
	assert.Equal(t, "initialRequest", asString(t, input, "messageType"))
	assert.IsType(t, "", input["version"])
	assert.Regexp(t, pubKeyHexPattern, asString(t, input, "identityKey"))

	if nonce, ok := input["initialNonce"].(string); ok && nonce != "" {
		assert.Regexp(t, base64Pattern, nonce)
	}

	validTypesRaw, ok := expected["valid_message_types"].([]any)
	require.True(t, ok)
	validTypes := toStringSlice(t, validTypesRaw)
	assert.Contains(t, validTypes, "initialRequest")
	assert.Contains(t, validTypes, "initialResponse")
	assert.Contains(t, validTypes, "general")

	requiredFieldsRaw, ok := expected["required_fields"].([]any)
	require.True(t, ok)
	requiredFields := toStringSlice(t, requiredFieldsRaw)
	assert.Contains(t, requiredFields, "messageType")
	assert.Contains(t, requiredFields, "version")
	assert.Contains(t, requiredFields, "identityKey")

	for _, field := range requiredFields {
		assert.NotNilf(t, input[field], "input should define required field %q", field)
	}
}

// ── Vector 13: requestId is 32 bytes, base64-encoded (44 chars) ─────────────

func testRequestIDFormat(t *testing.T, v conformance.Vector) {
	input := decodeJSONObject(t, v.Input)
	expected := decodeJSONObject(t, v.Expected)

	lengthBytes := asInt(t, input, "requestId_length_bytes")
	assert.Equal(t, 32, lengthBytes)

	expectedBase64Length := asInt(t, expected, "requestId_base64_length")
	assert.Equal(t, 44, expectedBase64Length)

	computed := ((lengthBytes + 2) / 3) * 4
	assert.Equal(t, expectedBase64Length, computed)

	example := asString(t, input, "requestId_example")
	assert.Regexp(t, base64Pattern, example)
	decoded, err := decodeBase64(example)
	require.NoError(t, err)
	assert.Len(t, decoded, lengthBytes)
	assert.Len(t, example, expectedBase64Length)
}

// ── Vector 15: PubKeyHex format ──────────────────────────────────────────────

func testPubKeyHexFormat(t *testing.T, v conformance.Vector) {
	input := decodeJSONObject(t, v.Input)
	expected := decodeJSONObject(t, v.Expected)

	require.True(t, input["_schema_check"].(bool))

	pattern := asString(t, expected, "pattern")
	assert.Equal(t, "^0[23][0-9a-fA-F]{64}$", pattern)
	re := regexp.MustCompile(pattern)

	validRaw, ok := input["valid_examples"].([]any)
	require.True(t, ok)
	for _, ex := range toStringSlice(t, validRaw) {
		assert.Truef(t, re.MatchString(ex), "expected %q to match %s", ex, pattern)
	}

	invalidRaw, ok := input["invalid_examples"].([]any)
	require.True(t, ok)
	for _, ex := range toStringSlice(t, invalidRaw) {
		assert.Falsef(t, re.MatchString(ex), "expected %q not to match %s", ex, pattern)
	}
}

// ── Vector 16: server-side response signing failure -> 500 ─────────────────

func testResponseSigningFailure(t *testing.T, v conformance.Vector) {
	expected := decodeJSONObject(t, v.Expected)

	key, err := ec.NewPrivateKey()
	require.NoError(t, err)
	proto, err := wallet.NewCompletedProtoWallet(key)
	require.NoError(t, err)
	serverWallet := wallet.NewTestWalletFromWallet(t, proto)

	// Only the server's outgoing GENERAL-message response signing must fail,
	// not its handshake signing (the initialResponse's own signature). go-sdk's
	// auth.Peer distinguishes these at the call site: ToPeer (used by
	// GeneralRequestHandler to sign a general response) passes originator
	// "auth-peer" to wallet.CreateSignature, while handleInitialRequest (the
	// handshake's initialResponse signature) passes "" (see go-sdk auth/peer.go).
	// Failing only "auth-peer" lets a single fresh client complete its
	// handshake normally and reach the general-message phase in one shot, so
	// the general request's nonce is never reused - avoiding go-sdk's BRC-103
	// anti-replay nonce claim (auth.ErrReplayedNonce), which would otherwise
	// reject a second delivery of the very same nonce with an unrelated error
	// before the response is ever signed.
	var failSigning atomic.Bool
	serverWallet.OnCreateSignature().Do(func(ctx context.Context, args wallet.CreateSignatureArgs, originator string) (*wallet.CreateSignatureResult, error) {
		if originator == "auth-peer" && failSigning.Load() {
			return nil, assert.AnError
		}
		return proto.CreateSignature(ctx, args, originator)
	})
	failSigning.Store(true)

	given := testabilities.Given(t)
	authMiddleware := middleware.NewAuth(serverWallet)
	cleanup := given.Server().WithMiddleware(authMiddleware).
		WithRoute("/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }).
		Started()
	defer cleanup()

	alice := testusers.NewAlice(t)
	capture := &captureTransport{}
	httpClient := clients.New(alice.Wallet(), clients.WithHttpClient(&http.Client{Transport: capture}))

	serverURL := given.Server().URL()
	serverURL.Path = "/api/resource"

	// A single fresh handshake + general request: the handshake signs fine,
	// then the general response fails to sign. go-sdk's AuthFetch itself
	// reports this as its own transport-level error (a general-message
	// response with no x-bsv-auth-* envelope doesn't parse as an AuthMessage -
	// see simplified_http_transport.go's authMessageFromGeneralMessageResponse),
	// so this test asserts on the real wire response captured by captureTransport
	// at the HTTP layer, not on AuthFetch's own return value.
	fetchResp, fetchErr := httpClient.Fetch(t.Context(), serverURL.String(), &clients.SimplifiedFetchRequestOptions{
		Method:       http.MethodGet,
		RetryCounter: to.Ptr(1),
	})
	if fetchResp != nil {
		_ = fetchResp.Body.Close()
	}
	require.Error(t, fetchErr, "AuthFetch should fail to interpret a signing-failure response as a valid general-message envelope")

	legit := capture.last()
	require.NotNil(t, legit)
	assert.Equal(t, "/api/resource", legit.URL.Path)
	assert.NotEmpty(t, legit.Header.Get(brc104.HeaderSignature), "expected to capture the real signed general request")

	status, body := capture.lastRawResponse()
	var respBody map[string]any
	require.NoError(t, json.Unmarshal(body, &respBody), "error response body should be JSON")

	expectedBody := asObject(t, expected, "body")
	assert.Equal(t, asInt(t, expected, "status"), status)
	assert.Equal(t, "error", respBody["status"])
	assert.Equal(t, asString(t, expectedBody, "code"), respBody["code"])
}

// ── Vectors 17-21: BRC-104 response preimage wire encoding ──────────────────

func testResponsePreimage(t *testing.T, v conformance.Vector) {
	input := decodeJSONObject(t, v.Input)
	expected := decodeJSONObject(t, v.Expected)

	requestID, err := hex.DecodeString(asString(t, input, "request_id_hex"))
	require.NoError(t, err)

	bodyHex, _ := input["body_hex"].(string)
	body, err := hex.DecodeString(bodyHex)
	require.NoError(t, err)

	// This exercises the exact same go-sdk call this middleware's own
	// GeneralRequestHandler.Handle makes (pkg/internal/authentication/request_handler.go)
	// to build the payload it hands to peer.ToPeer for signing.
	payload, err := authpayload.FromResponse(requestID, authpayload.SimplifiedHttpResponse{
		StatusCode: asInt(t, input, "status"),
		Header:     http.Header{},
		Body:       body,
	})
	require.NoError(t, err)

	assert.Equal(t, asString(t, expected, "payload_hex"), hex.EncodeToString(payload))
}

// ── Small shared utils ───────────────────────────────────────────────────────

var (
	pubKeyHexPattern = regexp.MustCompile(`^0[23][0-9a-fA-F]{64}$`)
	base64Pattern    = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
)

func toStringSlice(t *testing.T, raw []any) []string {
	t.Helper()
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		require.True(t, ok)
		out = append(out, s)
	}
	return out
}

func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
