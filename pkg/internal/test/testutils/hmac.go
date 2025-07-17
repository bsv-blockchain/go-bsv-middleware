package testutils

func StringAsHMAC(s string) [32]byte {
	if len(s) > 32 {
		panic("input string is too long")
	}
	var result [32]byte
	copy(result[:], s)
	return result
}

func BytesAsHMAC(b []byte) [32]byte {
	if len(b) > 32 {
		panic("input string is too long")
	}
	var result [32]byte
	copy(result[:], b)
	return result
}
