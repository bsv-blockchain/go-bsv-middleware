package utils

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"strings"
)

// WriteVarIntNum writes a variable-length integer to a buffer
func WriteVarIntNum(writer *bytes.Buffer, num int) {
	if num < 0 {
		writer.WriteByte(0xff) // Representing -1
	} else {
		writer.WriteByte(byte(num)) // Simplified, extendable for larger numbers
	}
}

// ExtractHeaders extracts required headers based on conditions
func ExtractHeaders(headers http.Header) [][]string {
	var includedHeaders [][]string
	for k, v := range headers {
		k = strings.ToLower(k)
		if (strings.HasPrefix(k, "x-bsv-") || k == "content-type" || k == "authorization") &&
			!strings.HasPrefix(k, "x-bsv-auth") {
			includedHeaders = append(includedHeaders, []string{k, v[0]})
		}
	}
	return includedHeaders
}

// WriteBodyToBuffer writes the request body into a buffer
func WriteBodyToBuffer(req *http.Request, buf *bytes.Buffer) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		log.Printf("Failed to read request body: %v", err)
		WriteVarIntNum(buf, -1)
		return
	}

	if len(body) > 0 {
		WriteVarIntNum(buf, len(body))
		buf.Write(body)
	} else {
		WriteVarIntNum(buf, -1)
	}
}
