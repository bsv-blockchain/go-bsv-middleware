package util

import "github.com/bsv-blockchain/go-sdk/util"

// WrappedSdkWriter - this is temporary solution, until go-sdk and ts-sdk will agreed on handling -1 bytes as 0
// TODO: replace with plain writer when go-sdk will be changed
type WrappedSdkWriter struct {
	*util.Writer
}

func NewWriter() *WrappedSdkWriter {
	return &WrappedSdkWriter{
		Writer: util.NewWriter(),
	}
}

func (w *WrappedSdkWriter) WriteOptionalString(s string) {
	if s == "" {
		w.writeZero()
		return
	}
	w.WriteVarInt(uint64(len(s)))
	w.WriteBytes([]byte(s))
}

func (w *WrappedSdkWriter) WriteIntBytesOptional(b []byte) {
	if len(b) == 0 {
		w.writeZero()
	} else {
		w.WriteIntBytes(b)
	}
}

func (w *WrappedSdkWriter) writeZero() {
	w.Writer.WriteVarInt(0)
}
