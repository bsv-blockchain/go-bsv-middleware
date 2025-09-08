package testabilities

import (
	"log/slog"
	"net/http"
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/logging"
	"github.com/go-softwarelab/common/pkg/to"
	"github.com/stretchr/testify/require"
)

type BSVMiddlewareTestsFixture interface {
	Server() ServerFixture
	Middleware() MiddlewareFixture
	Client() ClientFixture
}

type BSVMiddlewareTestsAssertion interface {
	Request(*http.Request) RequestAssertion
	Response(*http.Response) ResponseAssertion
}

func New(t testing.TB, opts ...func(*Options)) (BSVMiddlewareTestsFixture, BSVMiddlewareTestsAssertion) {
	return Given(t, opts...), Then(t)
}

func Given(t testing.TB, opts ...func(*Options)) BSVMiddlewareTestsFixture {
	f := &bsvMiddlewareTestsFixture{
		TB: t,
	}

	options := to.OptionsWithDefault(Options{
		logger: logging.NewTestLogger(f),
	}, opts...)

	f.logger = options.logger
	f.serverFixture = NewServerFixture(f)
	f.middlewareFixture = NewMiddlewareFixture(f, WithMiddlewareLogger(f.logger))

	return f
}

func Then(t testing.TB) BSVMiddlewareTestsAssertion {
	return &bsvMiddlewareTestsAssertion{
		TB: t,
	}
}

type bsvMiddlewareTestsFixture struct {
	testing.TB
	serverFixture     ServerFixture
	middlewareFixture MiddlewareFixture
	logger            *slog.Logger
}

func (f *bsvMiddlewareTestsFixture) Server() ServerFixture {
	return f.serverFixture
}

func (f *bsvMiddlewareTestsFixture) Middleware() MiddlewareFixture {
	return f.middlewareFixture
}

func (f *bsvMiddlewareTestsFixture) Client() ClientFixture {
	return newClientFixture(f, WithClientLogger(f.logger))
}

type bsvMiddlewareTestsAssertion struct {
	testing.TB
}

func (a *bsvMiddlewareTestsAssertion) Request(request *http.Request) RequestAssertion {
	return NewRequestAssertion(a, request)
}

func (a *bsvMiddlewareTestsAssertion) Response(response *http.Response) ResponseAssertion {
	a.Helper()
	require.NotNil(a, response, "response should not be nil")

	return NewResponseAssertion(a, response)
}
