package typescript_test

import (
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/regressiontests/internal/typescript"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckTypescriptAuthFetchCaller(t *testing.T) {
	t.Skip("used for auth fetch caller development purposes")

	response := typescript.AuthFetch(t, "http://localhost:8100")
	assert.NoError(t, err)
	require.NotNil(t, response)
	assert.NotEmpty(t, response.Status)
	assert.NotEmpty(t, response.StatusText)
	assert.NotEmpty(t, response.Headers)
	assert.NotEmpty(t, response.Body)
}
