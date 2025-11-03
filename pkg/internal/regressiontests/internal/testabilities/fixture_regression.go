package testabilities

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/regressiontests/internal/typescript"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/testabilities"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/testmode"
	"github.com/go-softwarelab/common/pkg/is"
	"github.com/go-softwarelab/common/pkg/seq"
	"github.com/go-softwarelab/common/pkg/slogx"
	"github.com/go-softwarelab/common/pkg/testingx"
	"github.com/go-softwarelab/common/pkg/to"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/log"
	"github.com/testcontainers/testcontainers-go/wait"
)

// serverMinPort is the lowest port number that we want to use for regression tests go server.
const serverMinPort int = 55000

// regressionTestServerPorts is a list (range) of ports that we allow regression test go server to listen to.
// This is an important part because on Linux host.docker.internal is not working.
// But instead, testcontainers allow setting a list of host ports that are accessible from docker container.
// Unfortunately, this list must be provided upfront (when creating a docker container).
// But often, we are creating single docker container with TypeScript grpc server,
// and in each subtest (t.Run), we are creating a new Go test server,
// and we know the port only after the Go test server is created.
// So thanks to that list and special way of starting the Go test server,
// based on the list of ports, we can:
// - provide the same list to testcontainers - so it's available to access from docker container
// - start the server on first available port from the list, so in case of multiple parallel tests
// (which is the case in regression tests), we won't get port conflict (hopefully).
//
// So in case, when there are too many parallel regression tests, just increase the list of ports,
// although 200 ports seems more than enough to me.
var regressionTestServerPorts = seq.Collect(seq.Range(serverMinPort, serverMinPort+200))

type (
	ServerFixture     = testabilities.ServerFixture
	MiddlewareFixture = testabilities.MiddlewareFixture
)

type creationOptions struct {
	parentGiven *regressionTestFixture
}

func WithBeforeAll(givenBeforeAll RegressionTestFixture) func(options *creationOptions) {
	return func(options *creationOptions) {
		if parent, ok := givenBeforeAll.(*regressionTestFixture); ok {
			options.parentGiven = parent
		}
	}
}

type RegressionTestFixture interface {
	TypescriptGrpcServerStarted() (cleanupGrpcServer func())
	Client() ClientFixture
	Port() int
	Server() ServerFixture
	Middleware() MiddlewareFixture
}

type regressionTestFixture struct {
	testing.TB
	testabilities.BSVMiddlewareTestsFixture
	initialized bool
	host        string
	port        int
}

func (f *regressionTestFixture) Port() int {
	return f.port
}

func Given(t testing.TB, opts ...func(*creationOptions)) RegressionTestFixture {
	options := to.Options[creationOptions](opts...)

	if options.parentGiven != nil {
		return &regressionTestFixture{
			TB:                        t,
			BSVMiddlewareTestsFixture: testabilities.Given(t, testabilities.WithServerPorts(regressionTestServerPorts)),
			initialized:               options.parentGiven.initialized,
			host:                      options.parentGiven.host,
			port:                      options.parentGiven.port,
		}
	}

	return &regressionTestFixture{
		TB:                        t,
		BSVMiddlewareTestsFixture: testabilities.Given(t, testabilities.WithServerPorts(regressionTestServerPorts)),
	}
}

func (f *regressionTestFixture) Client() ClientFixture {
	if !f.initialized {
		f.Fatal("invalid test setup: GRPC server must be started before creating the client, use TypescriptGrpcServerStarted()")
	}
	return newClientFixture(f, typescript.WithHost(f.host), typescript.WithPort(f.port))
}

func (f *regressionTestFixture) TypescriptGrpcServerStarted() (cleanupGrpcServer func()) {
	mode := testmode.GetGrpcServerMode()
	if mode.ModeName() == testmode.GrpcLocalMode {
		return f.usingLocalGrpc(testmode.Unwrap[testmode.LocalGrpcMode](mode))
	}
	return f.startGrpcServerFromDocker(testmode.Unwrap[testmode.DockerGrpcMode](mode))
}

func (f *regressionTestFixture) startGrpcServerFromDocker(mode testmode.DockerGrpcMode) (cleanupGrpcServer func()) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("cannot get current file")
	}
	contextPath := filepath.Join(filepath.Dir(filename), "../typescript")

	req := testcontainers.ContainerRequest{
		// this is very important part:
		// as those settings allow to access the Go test server from our typescript grpc docker container.
		// see docs of regressionTestServerPorts for more details.
		Env: map[string]string{
			"FETCH_LOCALHOST_REPLACEMENT": "host.testcontainers.internal",
		},
		HostAccessPorts: regressionTestServerPorts,

		WaitingFor: wait.ForLog("gRPC server is running"),
		LogConsumerCfg: &testcontainers.LogConsumerConfig{
			Consumers: []testcontainers.LogConsumer{
				&containerLogsConsumer{t: f},
			},
		},
	}

	if mode.Build {
		req.FromDockerfile = testcontainers.FromDockerfile{
			Context:    contextPath,
			Dockerfile: "Dockerfile",
			// We're creating an image for each test that is starting the container
			// (which by convention is the upper most test)
			// and we're replacing those images every time we run the tests.
			Repo: mode.Repo + "/" + f.Name(),
			Tag:  mode.Tag,
			// By default we're removing the image after the test is finished.
			// But it can be overridden by setting mode env variable see testmode.DockerGrpcMode
			KeepImage: mode.KeepImage,

			// this prints build logs in tests
			BuildLogWriter: slogx.NewTestingTBWriter(f),
		}
	} else {
		req.Image = mode.Repo + ":" + mode.Tag
	}

	container, err := testcontainers.GenericContainer(f.Context(), testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
		Logger:           log.TestLogger(f),
	})
	require.NoError(f, err, "Failed to start docker container with typescript grpc server")

	port, err := container.MappedPort(f.Context(), "50050/tcp")
	if err != nil {
		f.Fatalf("cannot get mapped port: %v", err)
	}

	f.host = "localhost"
	f.port = port.Int()
	f.initialized = true

	return func() {
		err := container.Terminate(f.Context())
		if err != nil {
			require.NoError(f, err, "Failed to terminate docker container with typescript grpc server")
		}
		f.onServerCleanup()
	}
}

func (f *regressionTestFixture) usingLocalGrpc(mode testmode.LocalGrpcMode) (cleanupGrpcServer func()) {
	warningMsg := "USING LOCAL GRPC SERVER MODE - ENSURE TO START THE SERVER BEFORE RUNNING THE TESTS"

	fmt.Println(strings.Repeat("!", len(warningMsg)))
	fmt.Println(warningMsg)
	fmt.Println(strings.Repeat("!", len(warningMsg)))

	f.host = mode.Host
	f.port = mode.Port

	f.initialized = true

	return f.onServerCleanup
}

func (f *regressionTestFixture) onServerCleanup() {
	f.initialized = false
	f.host = ""
	f.port = 0
}

const logsAggregationBoundarySign = "----------------"

// containerLogsConsumer is a container log consumer
type containerLogsConsumer struct {
	t              testingx.TB
	logsAggregator strings.Builder
}

func (c *containerLogsConsumer) Accept(log testcontainers.Log) {
	// notice: we have a special custom logic to make the logs printed in grpc server more readable in go console.
	logContent := string(log.Content)

	if c.logsAggregator.Len() == 0 && strings.HasPrefix(logContent, logsAggregationBoundarySign) {
		// starting new log lines aggregation
		c.logsAggregator.WriteString(logContent)
		return
	}

	if c.logsAggregator.Len() == 0 {
		// aggregation not starting - log without aggregation
		// and skip blanks
		if is.BlankString(logContent) {
			return
		}
		c.t.Log(logContent)
		return
	}

	if c.logsAggregator.Len() > 0 {
		// aggregation of log lines started
		c.logsAggregator.WriteString(logContent)
	}

	if strings.HasPrefix(logContent, logsAggregationBoundarySign) {
		// Log lines aggregation finished
		c.t.Log(c.logsAggregator.String())
		c.logsAggregator.Reset()
	}
}
