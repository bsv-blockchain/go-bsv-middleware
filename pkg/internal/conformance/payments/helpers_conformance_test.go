// Package payments_test runs the pinned ts-stack conformance vectors for the
// BRC-121 HTTP 402 payment flow and the BRC-29 P2P payment protocol.
//
// The TS reference dispatcher for these vectors
// (ts-stack/conformance/runner/ts/dispatchers/payments.ts) is itself a pure
// schema/structural checker: it pins field names, encodings, regular
// expressions and protocol-specified constants (such as the BRC-29
// invoice-number format) directly against the vector JSON, rather than
// driving a live @bsv/402-pay server or wallet. The files in this package
// are a line-for-line port of that dispatcher so Go renders the same
// pass/fail verdict TS does for every vector, plus (where a Go production
// type exists to exercise) a same-shape round trip through it.
package payments_test

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	base64SyntaxPattern     = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	compressedPubKeyPattern = regexp.MustCompile(`^(02|03)[0-9a-fA-F]{64}$`)
)

// isBase64 mirrors the TS reference's isBase64: a syntax-only check, not a
// canonical round-trip check.
func isBase64(s string) bool {
	return base64SyntaxPattern.MatchString(s) && len(s)%4 == 0
}

// isCompressedPubKeyHex mirrors the TS reference's isCompressedPubKeyHex.
func isCompressedPubKeyHex(s string) bool {
	return compressedPubKeyPattern.MatchString(s)
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getBool(m map[string]any, key string) bool {
	v, ok := m[key]
	return ok && v == true
}

func getStringSlice(t *testing.T, m map[string]any, key string) []string {
	t.Helper()
	raw, ok := m[key]
	if !ok {
		return nil
	}
	items, ok := raw.([]any)
	require.True(t, ok, "%s must be an array", key)
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		require.True(t, ok, "%s entries must be strings", key)
		out = append(out, s)
	}
	return out
}

func getStringMap(m map[string]any, key string) map[string]string {
	raw, ok := m[key]
	if !ok {
		return map[string]string{}
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		return map[string]string{}
	}
	out := make(map[string]string, len(obj))
	for k, v := range obj {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// assertRequiredFields mirrors the TS reference's assertRequiredFields: for
// every name listed in expected["required_fields"], value must carry that
// key (a structural presence check, not a value check).
func assertRequiredFields(t *testing.T, value map[string]any, expected map[string]any) {
	t.Helper()
	raw, ok := expected["required_fields"]
	if !ok {
		return
	}
	fields, ok := raw.([]any)
	require.True(t, ok, "required_fields must be an array")
	for _, f := range fields {
		field, ok := f.(string)
		require.True(t, ok, "required_fields entries must be strings")
		_, present := value[field]
		assert.True(t, present, "expected field %q to be present", field)
	}
}
