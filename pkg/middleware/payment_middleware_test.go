package middleware_test

import (
	"net/http"
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/testabilities"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/testabilities/testusers"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware"
	clients "github.com/bsv-blockchain/go-sdk/auth/clients/authhttp"
	"github.com/go-softwarelab/common/pkg/to"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPaymentMiddlewareErrors(t *testing.T) {
	t.Run("should return error when payment middleware is setup without auth middleware", func(t *testing.T) {
		// given:
		given, then := testabilities.New(t)

		// and:
		paymentMiddleware := given.Middleware().NewPayment()

		// and:
		cleanup := given.Server().
			WithMiddleware(paymentMiddleware).
			WithRoute("/", func(w http.ResponseWriter, r *http.Request) {
				assert.Fail(t, "handler shouldn't be called when auth middleware is missing")
			}).
			Started()
		defer cleanup()

		// and:
		unauthenticatedClient := &http.Client{}

		// when:
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, given.Server().URL().String(), nil)
		require.NoError(t, err)
		response, err := unauthenticatedClient.Do(req)

		// then:
		require.NoError(t, err)
		defer func() { _ = response.Body.Close() }()
		then.Response(response).HasStatus(http.StatusInternalServerError)
	})
}

func TestPaymentMiddlewareSuccess(t *testing.T) {
	t.Run("pass request to handler without payment when calculated payment for request is 0", func(t *testing.T) {
		// given:
		given, then := testabilities.New(t)

		// and:
		alice := testusers.NewAlice(t)

		// and:
		zeroPrice := func(_ *http.Request) (int, error) { return 0, nil }
		paymentMiddleware := given.Middleware().NewPayment(middleware.WithRequestPriceCalculator(zeroPrice))

		// and:
		authMiddleware := given.Middleware().NewAuth()

		// and:
		cleanup := given.Server().
			WithMiddleware(authMiddleware).
			WithMiddleware(paymentMiddleware).
			WithRoute("/", func(w http.ResponseWriter, r *http.Request) {
				// then: (request assertions)
				then.Request(r).
					HasMethod(http.MethodGet).
					HasPath("").
					HasIdentityOfUser(alice)

				// and: payment info should be present with 0 paid
				info, err := middleware.ShouldGetPaymentInfo(r.Context())
				assert.NoError(t, err, "should be able to get payment info from request context")
				assert.Equal(t, 0, info.SatoshisPaid, "payment info should have 0 satoshis paid")

				_, err = w.Write([]byte("Pong!"))
				assert.NoError(t, err)
			}).
			Started()
		defer cleanup()

		// and:
		httpClient, cleanupClient := given.Client().ForUser(alice)
		defer cleanupClient()

		// when:
		response, err := httpClient.Fetch(t.Context(), given.Server().URL().String(), &clients.SimplifiedFetchRequestOptions{
			Method:       http.MethodGet,
			RetryCounter: to.Ptr(1),
		})

		// then:
		require.NoError(t, err, "fetch should succeed")
		defer func() { _ = response.Body.Close() }()

		// and:
		then.Response(response).
			HasStatus(http.StatusOK).
			HasBody("Pong!")

		// and: no payment acknowledgment header should be present for zero price
		assert.Empty(t, response.Header.Get(middleware.HeaderPaymentPaid))
	})

	t.Run("require payment when calculated payment for request is higher than 0", func(t *testing.T) {
		// Skip this test when running with race detector due to unfixable race in go-sdk v1.2.11
		// The AuthFetch client has unprotected concurrent map access in its callbacks and peers maps.
		// When automatic payment retry occurs (402 -> create payment -> retry), multiple goroutines
		// within the same Fetch() call access these maps without synchronization.
		// This race is internal to go-sdk's AuthFetch.handlePaymentAndRetry() and cannot be worked
		// around without modifying the library itself to add proper mutex protection.
		// See: https://github.com/bsv-blockchain/go-sdk/blob/v1.2.11/auth/clients/authhttp/authhttp.go#L328
		// and: https://github.com/bsv-blockchain/go-sdk/blob/v1.2.11/auth/clients/authhttp/authhttp.go#L389
		if RaceEnabled {
			t.Skip("Skipping due to known race condition in go-sdk v1.2.11 AuthFetch.handlePaymentAndRetry()")
		}

		// given:
		given, then := testabilities.New(t)

		// and:
		alice := testusers.NewAlice(t)

		// and:
		price := 42
		priceFunc := func(_ *http.Request) (int, error) { return price, nil }
		paymentMiddleware := given.Middleware().NewPayment(middleware.WithRequestPriceCalculator(priceFunc))

		// and:
		authMiddleware := given.Middleware().NewAuth()

		// and:
		cleanup := given.Server().
			WithMiddleware(authMiddleware).
			WithMiddleware(paymentMiddleware).
			WithRoute("/", func(w http.ResponseWriter, r *http.Request) {
				// then: (request assertions)
				then.Request(r).
					HasMethod(http.MethodGet).
					HasPath("").
					HasIdentityOfUser(alice)

				// and: payment info should be present with 0 paid
				info, err := middleware.ShouldGetPaymentInfo(r.Context())
				assert.NoError(t, err, "should be able to get payment info from request context")
				assert.Equal(t, price, info.SatoshisPaid, "payment info should have calculated price")

				_, err = w.Write([]byte("Pong!"))
				assert.NoError(t, err)
			}).
			Started()
		defer cleanup()

		// and:
		httpClient, cleanupClient := given.Client().ForUser(alice)
		defer cleanupClient()

		// when:
		response, err := httpClient.Fetch(t.Context(), given.Server().URL().String(), &clients.SimplifiedFetchRequestOptions{
			Method: http.MethodGet,
		})

		// then:
		require.NoError(t, err)
		defer func() { _ = response.Body.Close() }()

		// and:
		then.Response(response).HasStatus(http.StatusOK).HasBody("Pong!").HasHeader(middleware.HeaderPaymentPaid)
	})
}
