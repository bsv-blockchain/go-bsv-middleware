package logging_test

import (
	"testing"

	"github.com/4chain-ag/go-bsv-middleware/pkg/internal/logging"
	"github.com/stretchr/testify/require"
)

func TestNopIfNil(t *testing.T) {
	// when:
	logger := logging.DefaultIfNil(nil)

	// then:
	require.NotNil(t, logger)
}
