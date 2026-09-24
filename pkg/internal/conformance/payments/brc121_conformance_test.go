package payments_test

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/conformance"
)

// brc121RequiredPaymentHeaders mirrors BRC121_REQUIRED_PAYMENT_HEADERS in the
// TS reference dispatcher: the client -> server headers on the paid retry.
var brc121RequiredPaymentHeaders = []string{
	"x-bsv-beef",
	"x-bsv-sender",
	"x-bsv-nonce",
	"x-bsv-time",
	"x-bsv-vout",
}

// hasAllPaymentHeaders mirrors the TS reference's hasAllPaymentHeaders.
func hasAllPaymentHeaders(headers map[string]string) bool {
	for _, h := range brc121RequiredPaymentHeaders {
		if headers[h] == "" {
			return false
		}
	}
	return true
}

// dispatchBRC121Schema mirrors the TS reference's dispatchBRC121Schema.
func dispatchBRC121Schema(t *testing.T, input, expected map[string]any) bool {
	t.Helper()

	_, hasNonce := input["x_bsv_nonce"]
	_, hasTime := input["x_bsv_time"]
	_, hasSender := input["x_bsv_sender"]
	schemaCheck := getBool(input, "_schema_check")

	if schemaCheck && hasNonce && hasTime && !hasSender {
		nonce := getString(input, "x_bsv_nonce")
		timeStr := getString(input, "x_bsv_time")
		// derivationSuffix = base64(time string)
		derivationSuffix := base64.StdEncoding.EncodeToString([]byte(timeStr))
		invoiceNumber := fmt.Sprintf("2-3241645161d8-%s %s", nonce, derivationSuffix)

		assert.Equal(t, getString(expected, "invoice_number"), invoiceNumber)
		assert.Equal(t, nonce, getString(expected, "derivation_prefix"))
		assert.Equal(t, derivationSuffix, getString(expected, "derivation_suffix"))
		return true
	}

	_, hasValidExamples := input["valid_examples"]
	_, hasInvalidExamples := input["invalid_examples"]
	if schemaCheck && hasValidExamples && hasInvalidExamples {
		pattern := getString(expected, "pattern")
		re := regexp.MustCompile(pattern)

		for _, ex := range getStringSlice(t, input, "valid_examples") {
			assert.True(t, re.MatchString(ex), "expected %q to match %s", ex, pattern)
		}
		for _, ex := range getStringSlice(t, input, "invalid_examples") {
			assert.False(t, re.MatchString(ex), "expected %q not to match %s", ex, pattern)
		}
		return true
	}

	if schemaCheck && hasNonce && hasTime && hasSender {
		nonce := getString(input, "x_bsv_nonce")
		timeStr := getString(input, "x_bsv_time")
		sender := getString(input, "x_bsv_sender")
		derivationSuffix := base64.StdEncoding.EncodeToString([]byte(timeStr))

		if remittanceRaw, ok := expected["remittance_shape"]; ok {
			remittance, ok := remittanceRaw.(map[string]any)
			require.True(t, ok, "remittance_shape must be an object")
			assert.Equal(t, nonce, getString(remittance, "derivationPrefix"))
			assert.Equal(t, derivationSuffix, getString(remittance, "derivationSuffix"))
			assert.Equal(t, sender, getString(remittance, "senderIdentityKey"))
		}
		return true
	}

	if expected["status"] == float64(402) && getBool(expected, "body_empty") {
		assert.True(t, getBool(expected, "body_empty"))
		return true
	}

	if _, ok := expected["auto_retry_safe"]; ok {
		assert.Equal(t, false, expected["auto_retry_safe"])
		assert.NotEmpty(t, getString(expected, "double_spend_risk"))
		return true
	}

	return false
}

// dispatchPaymentRequired mirrors the TS reference's dispatchPaymentRequired
// (the input._scenario/typeof-headers branch it also runs is a tautology in
// JS that never fails, so it carries no observable behaviour to port).
func dispatchPaymentRequired(t *testing.T, expected map[string]any) {
	t.Helper()

	if includesRaw, ok := expected["response_headers_includes"]; ok {
		includes, ok := includesRaw.(map[string]any)
		require.True(t, ok, "response_headers_includes must be an object")
		exposeHeaders := getString(includes, "access-control-expose-headers")
		assert.Regexp(t, "x-bsv-sats", exposeHeaders)
		assert.Regexp(t, "x-bsv-server", exposeHeaders)
	}

	statusFloat, ok := expected["status"].(float64)
	require.True(t, ok, "expected status to be a number")
	assert.Equal(t, 402, int(statusFloat))
}

// dispatchPaymentResponseHeaders mirrors the TS reference's
// dispatchPaymentResponseHeaders.
func dispatchPaymentResponseHeaders(t *testing.T, expected map[string]any) {
	t.Helper()

	headers := getStringMap(expected, "response_headers")
	sats, hasSats := headers["x-bsv-sats"]
	server, hasServer := headers["x-bsv-server"]
	require.True(t, hasSats, "expected response_headers to have x-bsv-sats")
	require.True(t, hasServer, "expected response_headers to have x-bsv-server")

	satsValue, err := strconv.Atoi(sats)
	require.NoError(t, err, "x-bsv-sats must be numeric")
	assert.Positive(t, satsValue)
	assert.True(t, isCompressedPubKeyHex(server))
}

// dispatchSuccessfulPayment mirrors the TS reference's
// dispatchSuccessfulPayment.
func dispatchSuccessfulPayment(t *testing.T, input map[string]any) {
	t.Helper()

	headers := getStringMap(input, "headers")
	assert.True(t, hasAllPaymentHeaders(headers))
	assert.True(t, isCompressedPubKeyHex(headers["x-bsv-sender"]))
	assert.True(t, isBase64(headers["x-bsv-nonce"]))
}

// dispatchBRC121 mirrors the TS reference's dispatchBRC121.
func dispatchBRC121(t *testing.T, input, expected map[string]any) {
	t.Helper()

	if dispatchBRC121Schema(t, input, expected) {
		return
	}

	status, hasStatus := expected["status"]
	_, hasResponseHeaders := expected["response_headers"]

	switch {
	case status == float64(402):
		dispatchPaymentRequired(t, expected)
	case !hasStatus && hasResponseHeaders:
		dispatchPaymentResponseHeaders(t, expected)
	case status == float64(200):
		dispatchSuccessfulPayment(t, input)
	case status == float64(500):
		if bodyRaw, ok := expected["body"]; ok {
			body, ok := bodyRaw.(map[string]any)
			require.True(t, ok, "body must be an object")
			_, hasError := body["error"]
			assert.True(t, hasError, "expected body to have an error field")
		}
	}
}

// TestBRC121Conformance runs every vector in payments/brc121.json, mirroring
// exactly what ts-stack's payments dispatcher asserts for each one (see the
// package doc comment for why that means schema/structural checks rather
// than driving a live HTTP round trip: no BRC-121 402-pay server exists in
// this repo or in the TS reference's own conformance harness).
func TestBRC121Conformance(t *testing.T) {
	file := conformance.Load(t, "payments/brc121.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var input map[string]any
		var expected map[string]any
		v.DecodeInput(t, &input)
		v.DecodeExpected(t, &expected)

		dispatchBRC121(t, input, expected)
	})
}
