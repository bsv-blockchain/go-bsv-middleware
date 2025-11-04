package testmode

import (
	"errors"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/go-softwarelab/common/pkg/to"
)

var ErrFailedToDetermineGrpcServerMode = errors.New("failed to determine grpc server mode based on env")

const (
	grpcModeEnvVar                 = "TEST_GRPC_MODE"
	GrpcDockerMode                 = "docker"
	GrpcLocalMode                  = "local"
	localGrpcModePortEnvKey        = "TEST_GRPC_LOCAL_MODE_PORT"
	localGrpcModeHostEnvKey        = "TEST_GRPC_LOCAL_MODE_HOST"
	dockerGrpcModeBuildImageEnvKey = "TEST_GRPC_DOCKER_MODE_BUILD_IMAGE"
	dockerGrpcModeImageRepoEnvKey  = "TEST_GRPC_DOCKER_MODE_IMAGE_REPO"
	dockerGrpcModeImageTagEnvKey   = "TEST_GRPC_DOCKER_MODE_IMAGE_TAG"
	dockerGrpcModeKeepImageEnvKey  = "TEST_GRPC_DOCKER_MODE_KEEP_IMAGE"
)

type Mode interface {
	ModeName() string
}

type GrpcMode interface {
	LocalGrpcMode | DockerGrpcMode
}

// WithPort sets the port of the local grpc server
func WithPort(port int) func(t testing.TB) {
	return func(t testing.TB) {
		t.Setenv(localGrpcModePortEnvKey, fmt.Sprintf("%d", port))
	}
}

// WithHost sets the host of the local grpc server
func WithHost(host string) func(t testing.TB) {
	return func(t testing.TB) {
		t.Setenv(localGrpcModeHostEnvKey, host)
	}
}

// WithBuildImage sets whether to build the docker image or not
func WithBuildImage(build bool) func(t testing.TB) {
	return func(t testing.TB) {
		t.Setenv(dockerGrpcModeBuildImageEnvKey, fmt.Sprintf("%t", build))
	}
}

// WithImageRepo sets the image repo (the image name without the tag)
func WithImageRepo(repo string) func(t testing.TB) {
	return func(t testing.TB) {
		t.Setenv(dockerGrpcModeImageRepoEnvKey, repo)
	}
}

// WithImageTag sets the image tag
func WithImageTag(tag string) func(t testing.TB) {
	return func(t testing.TB) {
		t.Setenv(dockerGrpcModeImageTagEnvKey, tag)
	}
}

// WithKeepImage sets whether to keep the docker image after the test
func WithKeepImage(keep bool) func(t testing.TB) {
	return func(t testing.TB) {
		t.Setenv(dockerGrpcModeKeepImageEnvKey, fmt.Sprintf("%t", keep))
	}
}

// DevelopmentOnly_SetLocalGrpcMode sets the grpc server test mode to use actual grpc server with typescript started locally.
func DevelopmentOnly_SetLocalGrpcMode(t testing.TB, opts ...func(t testing.TB)) {
	t.Setenv(grpcModeEnvVar, GrpcLocalMode)
	for _, opt := range opts {
		opt(t)
	}
}

// DevelopmentOnly_SetDockerGrpcMode sets the grpc server test mode to use docker.
func DevelopmentOnly_SetDockerGrpcMode(t testing.TB, opts ...func(t testing.TB)) {
	t.Setenv(grpcModeEnvVar, GrpcDockerMode)
	for _, opt := range opts {
		opt(t)
	}
}

// Unwrap unwraps the mode to the expected type
func Unwrap[M GrpcMode](mode Mode) M {
	if mode == nil {
		panic("mode to unwrap cannot be nil")
	}
	if m, ok := mode.(M); ok {
		return m
	}
	panic("mode to unwrap is not of expected type")
}

// LocalGrpcMode is the mode to use a grpc server with typescript started locally.
type LocalGrpcMode struct {
	Host string
	Port int
}

// ModeName returns the mode name
func (m LocalGrpcMode) ModeName() string {
	return GrpcLocalMode
}

func (m LocalGrpcMode) read() Mode {
	modeName := os.Getenv(grpcModeEnvVar)
	if modeName != m.ModeName() {
		return nil
	}

	m.Host = os.Getenv(localGrpcModeHostEnvKey)
	if m.Host == "" {
		m.Host = "localhost"
	}

	m.Port = 50050
	port := os.Getenv(localGrpcModePortEnvKey)
	if port != "" {
		var err error
		m.Port, err = to.Int(port)
		if err != nil {
			panic(fmt.Errorf("invalid port number %s set on %s environment variable: %w", port, localGrpcModePortEnvKey, err))
		}
	}

	return m
}

// DockerGrpcMode is the mode to start in docker a grpc server with typescript.
type DockerGrpcMode struct {
	Build     bool
	Repo      string
	Tag       string
	KeepImage bool
}

func (m DockerGrpcMode) ModeName() string {
	return GrpcDockerMode
}

func (m DockerGrpcMode) read() Mode {
	modeName := os.Getenv(grpcModeEnvVar)
	if modeName != "" && modeName != m.ModeName() {
		return nil
	}

	buildStr := os.Getenv(dockerGrpcModeBuildImageEnvKey)
	if buildStr != "" {
		var err error
		m.Build, err = to.BoolFromString(buildStr)
		if err != nil {
			panic(fmt.Errorf("invalid build value %s set on %s environment variable: %w", buildStr, dockerGrpcModeBuildImageEnvKey, err))
		}
	} else {
		m.Build = true
	}

	m.Repo = os.Getenv(dockerGrpcModeImageRepoEnvKey)
	if m.Repo == "" {
		m.Repo = "go-middleware-regression-test-grpc-server"
	}

	m.Tag = os.Getenv(dockerGrpcModeImageTagEnvKey)
	if m.Tag == "" {
		m.Tag = "latest"
	}

	keepStr := os.Getenv(dockerGrpcModeKeepImageEnvKey)
	if keepStr != "" {
		var err error
		m.KeepImage, err = to.BoolFromString(keepStr)
		if err != nil {
			panic(fmt.Errorf("invalid keep image value %s set on %s environment variable: %w", keepStr, dockerGrpcModeKeepImageEnvKey, err))
		}
	} else {
		m.KeepImage = false
	}
	return m
}

// GetGrpcServerMode returns the test grpc server mode
func GetGrpcServerMode() Mode {
	mode := LocalGrpcMode{}.read()
	if mode != nil {
		return mode
	}

	mode = DockerGrpcMode{}.read()
	if mode != nil {
		return mode
	}

	log.Fatalf("%s: %s=%s", ErrFailedToDetermineGrpcServerMode, grpcModeEnvVar, os.Getenv(grpcModeEnvVar))
	return nil
}
