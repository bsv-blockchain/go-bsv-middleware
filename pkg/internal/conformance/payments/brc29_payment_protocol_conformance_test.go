package payments_test

import (
	"encoding/json"
	"fmt"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/conformance"
)

// dispatchInvoiceSchema mirrors the TS reference's dispatchInvoiceSchema: the
// BRC-42/BRC-29 invoice number format "2-3241645161d8-{prefix} {suffix}".
func dispatchInvoiceSchema(t *testing.T, input, expected map[string]any) {
	t.Helper()

	prefix := getString(input, "derivationPrefix")
	suffix := getString(input, "derivationSuffix")
	wantInvoice := getString(expected, "invoice_number")
	if wantInvoice != "" {
		assert.Equal(t, wantInvoice, fmt.Sprintf("2-3241645161d8-%s %s", prefix, suffix))
	}

	if wantProtocol, ok := expected["protocol_id"].([]any); ok {
		require.Len(t, wantProtocol, 2)
		protocolNum, ok := wantProtocol[0].(float64)
		require.True(t, ok, "protocol_id[0] must be a number")
		assert.Equal(t, 2, int(protocolNum))
		assert.Equal(t, "3241645161d8", wantProtocol[1])
	}
}

// dispatchEncodingSchema mirrors the TS reference's dispatchEncodingSchema.
func dispatchEncodingSchema(t *testing.T, input, expected map[string]any) {
	t.Helper()

	if getString(expected, "encoding") == "base64" {
		for _, ex := range getStringSlice(t, input, "valid_examples") {
			assert.True(t, isBase64(ex), "expected %q to be valid base64", ex)
		}
	}
	assert.NotEmpty(t, getString(expected, "scope"))
}

// dispatchSenderKeySchema mirrors the TS reference's dispatchSenderKeySchema.
func dispatchSenderKeySchema(t *testing.T, input, expected map[string]any) {
	t.Helper()

	pattern := getString(expected, "pattern")
	if pattern == "" {
		return
	}
	re := regexp.MustCompile(pattern)
	for _, ex := range getStringSlice(t, input, "valid_examples") {
		assert.True(t, re.MatchString(ex), "expected %q to match %s", ex, pattern)
	}
}

// dispatchTxidSchema mirrors the TS reference's dispatchTxidSchema.
func dispatchTxidSchema(t *testing.T, input, expected map[string]any) {
	t.Helper()

	re := regexp.MustCompile(getString(expected, "pattern"))
	for _, txid := range getStringSlice(t, input, "valid_txids") {
		assert.True(t, re.MatchString(txid))
	}
}

// assertInternalizeActionArgsRoundTrip goes beyond the TS reference's own
// (structural-only) check: go-bsv-middleware's payment middleware builds a
// wallet.InternalizeActionArgs (owned by go-sdk) from an incoming BRC-29
// payment, so this also round-trips the vector's raw JSON through that real
// production dependency to prove it decodes/encodes the exact wire shape
// the vector pins (lowercase/camelCase field names, "tx" as a byte array,
// not base64).
func assertInternalizeActionArgsRoundTrip(t *testing.T, raw map[string]any) {
	t.Helper()

	data, err := json.Marshal(raw)
	require.NoError(t, err, "re-marshal internalizeActionArgs fixture")

	var args wallet.InternalizeActionArgs
	require.NoError(t, json.Unmarshal(data, &args), "decode internalizeActionArgs via wallet.InternalizeActionArgs")

	wantOutputs, _ := raw["outputs"].([]any)
	assert.Len(t, args.Outputs, len(wantOutputs))
	assert.Equal(t, getString(raw, "description"), args.Description)

	roundTripped, err := json.Marshal(&args)
	require.NoError(t, err, "re-encode internalizeActionArgs via wallet.InternalizeActionArgs")

	var roundTrippedRaw map[string]any
	require.NoError(t, json.Unmarshal(roundTripped, &roundTrippedRaw))
	for _, key := range []string{"tx", "outputs", "description"} {
		assert.Contains(t, roundTrippedRaw, key, "wallet.InternalizeActionArgs must re-emit %q", key)
	}
}

// dispatchBRC29Schema mirrors the TS reference's dispatchBRC29Schema.
func dispatchBRC29Schema(t *testing.T, input, expected map[string]any, channel string) bool {
	t.Helper()

	if msgRaw, ok := input["message"]; ok && channel == "" {
		msg, _ := msgRaw.(map[string]any)
		assertRequiredFields(t, msg, expected)
		assert.True(t, getBool(expected, "valid"))
		return true
	}

	_, hasPrefix := input["derivationPrefix"]
	_, hasSuffix := input["derivationSuffix"]
	_, hasMessage := input["message"]
	if hasPrefix && hasSuffix && !hasMessage {
		dispatchInvoiceSchema(t, input, expected)
		return true
	}

	if argsRaw, ok := input["internalizeActionArgs"]; ok {
		args, _ := argsRaw.(map[string]any)
		assertRequiredFields(t, args, expected)
		assert.True(t, getBool(expected, "valid"))
		assertInternalizeActionArgsRoundTrip(t, args)
		return true
	}

	_, hasValidExamples := input["valid_examples"]
	_, hasNote := input["_note"]
	if hasValidExamples && hasNote {
		dispatchEncodingSchema(t, input, expected)
		return true
	}
	if hasValidExamples {
		dispatchSenderKeySchema(t, input, expected)
		return true
	}

	if descRaw, ok := input["output_descriptor"]; ok {
		desc, _ := descRaw.(map[string]any)
		assertRequiredFields(t, desc, expected)
		assert.True(t, getBool(expected, "valid"))
		return true
	}

	if getString(input, "_schema_note") == "deprecated" {
		assert.True(t, getBool(expected, "deprecated"))
		assert.NotEmpty(t, getString(expected, "use_instead"))
		return true
	}

	if _, ok := input["transaction_encoding"]; ok {
		assert.Equal(t, "base64", getString(expected, "transport_encoding"))
		assert.Regexp(t, "Atomic BEEF", getString(expected, "format"))
		return true
	}

	if _, ok := input["valid_txids"]; ok {
		dispatchTxidSchema(t, input, expected)
		return true
	}

	return false
}

// assertPaymentAckShape mirrors the TS reference's assertPaymentAckShape.
func assertPaymentAckShape(t *testing.T, msg map[string]any) {
	t.Helper()
	_, ok := msg["accepted"].(bool)
	assert.True(t, ok, "expected \"accepted\" to be a boolean")
}

// dispatchBRC29Channel mirrors the TS reference's dispatchBRC29Channel.
func dispatchBRC29Channel(t *testing.T, input, expected map[string]any, channel string) {
	t.Helper()

	msgRaw, hasMessage := input["message"]
	var msg map[string]any
	if hasMessage {
		msg, _ = msgRaw.(map[string]any)
	}

	if channel == "payment/send" && hasMessage {
		_, hasDerivationPrefix := msg["derivationPrefix"]
		_, hasTransaction := msg["transaction"]
		assert.True(t, hasDerivationPrefix, "expected message to have derivationPrefix")
		assert.True(t, hasTransaction, "expected message to have transaction")
		assert.True(t, getBool(expected, "valid"))
		return
	}

	if channel == "payment/acknowledge" && hasMessage {
		assertPaymentAckShape(t, msg)
		assertRequiredFields(t, msg, expected)
		assert.True(t, getBool(expected, "valid"))
		return
	}

	if getBool(expected, "valid") && hasMessage {
		assertRequiredFields(t, msg, expected)
	}
}

// dispatchBRC29PaymentProtocol mirrors the TS reference's
// dispatchBRC29PaymentProtocol.
func dispatchBRC29PaymentProtocol(t *testing.T, input, expected map[string]any) {
	t.Helper()

	channel := getString(input, "channel")

	if getBool(input, "_schema_check") && dispatchBRC29Schema(t, input, expected, channel) {
		return
	}
	dispatchBRC29Channel(t, input, expected, channel)
}

// TestBRC29PaymentProtocolConformance runs every vector in
// payments/brc29-payment-protocol.json, mirroring exactly what ts-stack's
// payments dispatcher asserts for each one. Where a vector's shape overlaps
// a real go-sdk wallet type that go-bsv-middleware's payment package
// depends on (wallet.InternalizeActionArgs), it is additionally round
// tripped through that type.
func TestBRC29PaymentProtocolConformance(t *testing.T) {
	file := conformance.Load(t, "payments/brc29-payment-protocol.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var input map[string]any
		var expected map[string]any
		v.DecodeInput(t, &input)
		v.DecodeExpected(t, &expected)

		dispatchBRC29PaymentProtocol(t, input, expected)
	})
}
