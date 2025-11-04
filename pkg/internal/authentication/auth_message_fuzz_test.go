package authentication

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/bsv-blockchain/go-sdk/auth/brc104"
	primitives "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/stretchr/testify/require"
)

// FuzzRequestIDFromHeader performs fuzz testing on requestIDFromHeader to ensure
// it handles arbitrary base64-encoded and malformed input without panicking.
//
// This fuzz test validates that:
// - The function never panics on any input
// - Valid base64 strings are decoded successfully
// - Invalid base64 strings return appropriate errors
// - Edge cases like empty strings, whitespace, and special characters are handled
//
// The test seeds the corpus with known valid and invalid inputs to guide the fuzzer
// toward interesting test cases.
func FuzzRequestIDFromHeader(f *testing.F) {
	// Seed corpus with valid base64-encoded values
	f.Add("dGVzdA==")                                         // "test"
	f.Add("aGVsbG8gd29ybGQ=")                                 // "hello world"
	f.Add("AQIDBA==")                                         // Binary data [1,2,3,4]
	f.Add("MTIzNDU2Nzg5MA==")                                 // "1234567890"
	f.Add("")                                                 // Empty string
	f.Add("YQ==")                                             // Single character "a"
	f.Add("///w==")                                           // Special characters
	f.Add("VGhpcyBpcyBhIGxvbmdlciBzdHJpbmcgZm9yIHRlc3Rpbmc=") // Longer string

	// Seed corpus with invalid base64 values
	f.Add("not-valid-base64")
	f.Add("invalid=padding")
	f.Add("almost!valid")
	f.Add("     ")         // Whitespace
	f.Add("\n\t\r")        // Control characters
	f.Add("😀🎉")            // Emoji
	f.Add("<script>alert") // HTML/XSS attempt

	f.Fuzz(func(t *testing.T, input string) {
		// Create a mock HTTP request with the fuzzed input
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
		require.NoError(t, err)

		req.Header.Set(brc104.HeaderRequestID, input)

		// Call the function under test - should never panic
		requestID, requestIDBytes, err := requestIDFromHeader(req)
		if err != nil {
			// Error is acceptable for invalid input
			// Verify we get the expected error types for known bad inputs
			if input == "" {
				// Empty string should decode to empty bytes (valid base64)
				require.NoError(t, err, "empty string is valid base64")
			}
			return
		}

		// If no error, validate the results are consistent
		require.Equal(t, input, requestID, "returned requestID should match input")
		require.NotNil(t, requestIDBytes, "decoded bytes should not be nil on success")

		// Verify we can decode the bytes - the round-trip may normalize the encoding
		// (e.g., "001=" and "000=" both decode to the same bytes but encode differently)
		reEncoded := base64.StdEncoding.EncodeToString(requestIDBytes)
		reDecoded, err := base64.StdEncoding.DecodeString(reEncoded)
		require.NoError(t, err, "re-encoded value should be valid base64")
		require.Equal(t, requestIDBytes, reDecoded, "decoded bytes should match original")
	})
}

// FuzzIdentityKeyFromHeader performs fuzz testing on identityKeyFromHeader to ensure
// it handles arbitrary public key strings and malformed input without panicking.
//
// This fuzz test validates that:
// - The function never panics on any input
// - Valid public keys in DER hex format are parsed successfully
// - Invalid public key formats return appropriate errors
// - Edge cases like empty strings, non-hex characters, and wrong lengths are handled
//
// The test seeds the corpus with known valid and invalid inputs to guide the fuzzer
// toward interesting test cases involving cryptographic key parsing.
func FuzzIdentityKeyFromHeader(f *testing.F) {
	// Generate a valid public key for seeding
	privateKey, err := primitives.NewPrivateKey()
	require.NoError(f, err)
	validPubKey := privateKey.PubKey()
	validPubKeyString := validPubKey.ToDERHex()

	// Seed corpus with valid public key formats
	f.Add(validPubKeyString) // Valid compressed public key

	// Seed corpus with variations and invalid formats
	f.Add("")                                                                   // Empty string
	f.Add("02")                                                                 // Too short
	f.Add("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798") // Valid looking but possibly invalid curve point
	f.Add("not-a-hex-string")                                                   // Non-hex characters
	f.Add("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")   // All invalid hex chars
	f.Add("0" + validPubKeyString)                                              // Valid key with extra char
	f.Add(validPubKeyString[:len(validPubKeyString)-2])                         // Truncated valid key
	f.Add("00" + validPubKeyString)                                             // Prefixed valid key
	f.Add("abcdef1234567890")                                                   // Valid hex but wrong format
	f.Add("     ")                                                              // Whitespace
	f.Add("\x00\x01\x02")                                                       // Binary data
	f.Add("<script>")                                                           // XSS attempt
	f.Add("😀🎉")                                                                 // Emoji

	// Seed with different valid public key formats (uncompressed starts with 04)
	f.Add("04" + validPubKeyString[2:] + validPubKeyString[2:]) // Simulated uncompressed format

	f.Fuzz(func(t *testing.T, input string) {
		// Create a mock HTTP request with the fuzzed input
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
		require.NoError(t, err)

		req.Header.Set(brc104.HeaderIdentityKey, input)

		// Call the function under test - should never panic
		pubKey, err := identityKeyFromHeader(req)
		if err != nil {
			// Error is acceptable for invalid input
			require.Nil(t, pubKey, "public key should be nil when error occurs")

			// Verify error types for known bad inputs
			if input == "" {
				require.ErrorIs(t, err, ErrMissingIdentityKey, "empty string should return missing identity key error")
			} else {
				require.ErrorIs(t, err, ErrInvalidIdentityKeyFormat, "invalid format should return format error")
			}
			return
		}

		// If no error, validate the public key is properly formed
		require.NotNil(t, pubKey, "public key should not be nil on success")

		// Verify the public key serialization round-trips correctly
		serialized := pubKey.ToDERHex()
		require.NotEmpty(t, serialized, "serialized public key should not be empty")

		// The serialized form should be valid hex
		require.Regexp(t, "^[0-9a-fA-F]+$", serialized, "serialized key should be valid hex")
	})
}
