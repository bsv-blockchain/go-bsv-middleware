package logging_test

import (
	"github.com/4chain-ag/go-bsv-middleware/pkg/internal/logging"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNopIfNil(t *testing.T) {
	// when:
	logger := logging.DefaultIfNil(nil)

	// then:
	require.NotNil(t, logger)
}
