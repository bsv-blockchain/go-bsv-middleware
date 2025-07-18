package typescript

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/go-softwarelab/common/pkg/seq"
	"github.com/go-softwarelab/common/pkg/seq2"
	"github.com/go-softwarelab/common/pkg/to"
	"github.com/stretchr/testify/require"
)

type Options struct {
	url     string
	body    string
	headers []string
	method  string
}

func (o *Options) toArgs() []string {
	args := []string{
		"--url", o.url,
		"--method", o.method,
		"--body", o.body,
	}

	for _, header := range o.headers {
		args = append(args, "--header", header)
	}

	return args
}

func WithMethod(method string) func(*Options) {
	if !slices.Contains(validMethods, method) {
		panic(fmt.Errorf("invalid http method: %s", method))
	}

	return func(options *Options) {
		options.method = method
	}
}

func WithBody(body any) func(*Options) {
	if body == nil {
		return func(options *Options) {}
	}

	return func(options *Options) {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			panic(fmt.Errorf("not jsonable body: %w", err))
		}
		options.body = string(bodyBytes)
	}
}

func WithHeaders(headers map[string]string) func(*Options) {
	return func(options *Options) {
		options.headers = seq.Collect(seq2.MapTo(seq2.FromMap(headers), func(key string, value string) string {
			return key + ":" + value
		}))
	}
}

var validMethods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

const resultIndicator = "==================RESULT==============="

type AuthFetchResponse struct {
	Status     int               `json:"status"`
	StatusText string            `json:"statusText"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
}

func AuthFetch(t testing.TB, url string, opts ...func(*Options)) *AuthFetchResponse {
	options := to.OptionsWithDefault(Options{
		url:    url,
		method: http.MethodGet,
	}, opts...)

	command, args := authFetchCommand()
	args = append(args, options.toArgs()...)

	cmd := exec.CommandContext(t.Context(), command, args...) //nolint:gosec // should be used only in tests
	cmd.Dir = getCurrentFileDir()

	outputBytes, err := cmd.CombinedOutput()
	output := string(outputBytes)

	split := strings.SplitN(output, resultIndicator, 2)

	result := split[0]
	log := output

	if len(split) == 2 {
		log = split[0]
		result = split[1]
	}

	t.Log(log)

	require.NoErrorf(t, err, "Failed to run auth fetch command\n%s", output)

	var response AuthFetchResponse
	err = json.Unmarshal([]byte(result), &response)
	require.NoErrorf(t, err, "Result from js script must be json with response\n%s", result)

	return &response
}

func authFetchCommand() (string, []string) {
	return "npm", []string{"run", "--silent", "authFetch", "--", "-v"}
}

func getCurrentFileDir() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	return filepath.Dir(filename)
}
