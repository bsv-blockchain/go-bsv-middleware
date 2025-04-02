package utils

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

// WriteVarIntNum writes a variable-length integer to a buffer
// integer is converted to fixed size int32
func WriteVarIntNum(writer *bytes.Buffer, num int) {
	err := binary.Write(writer, binary.LittleEndian, int32(num))
	if err != nil {
		fmt.Println("Error writing number:", err)
	}
}

// ReadVarIntNum reads a variable-length integer from a buffer
func ReadVarIntNum(reader *bytes.Reader) (int32, error) {
	var intByte int32
	err := binary.Read(reader, binary.LittleEndian, &intByte)

	if err != nil {
		return 0, fmt.Errorf("error reading intByte: %w", err)
	}

	if intByte == -1 {
		return -1, nil
	}

	return intByte, nil
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
	if req.Body == nil {
		WriteVarIntNum(buf, -1)
		return
	}

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
