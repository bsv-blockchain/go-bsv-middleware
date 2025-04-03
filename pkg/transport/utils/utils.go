package utils

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"strings"
)

// WriteVarIntNum writes a variable-length integer to a buffer
// integer is converted to fixed size int64
func WriteVarIntNum(writer *bytes.Buffer, num int) error {
	err := binary.Write(writer, binary.LittleEndian, int64(num))
	if err != nil {
		return errors.New("failed to write varint number")
	}
	return nil
}

// ReadVarIntNum reads a variable-length integer from a buffer
func ReadVarIntNum(reader *bytes.Reader) (int64, error) {
	var intByte int64
	err := binary.Read(reader, binary.LittleEndian, &intByte)
	if err != nil {
		return 0, errors.New("failed to read varint number")
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
func WriteBodyToBuffer(req *http.Request, buf *bytes.Buffer) error {
	if req.Body == nil {
		err := WriteVarIntNum(buf, -1)
		if err != nil {
			return errors.New("failed to write -1 for empty body")
		}
		return nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		//WriteVarIntNum(buf, -1)
		return errors.New("failed to read request body")
	}

	if len(body) > 0 {
		err = WriteVarIntNum(buf, len(body))
		if err != nil {
			return errors.New("failed to write body length")
		}
		buf.Write(body)
		return nil
	}

	err = WriteVarIntNum(buf, -1)
	if err != nil {
		return errors.New("failed to write -1 for empty body")
	}
	return nil
}
