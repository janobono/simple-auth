package client_test

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/janobono/simple-auth/simple-auth-service/internal/config"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	HttpPort   nat.Port
	MailConfig *config.MailConfig
	mailHog    tc.Container
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	var err error
	mailHog, MailConfig, err = StartMailHogContainer(ctx)
	if err != nil {
		log.Fatalf("could not start MailHog: %v", err)
	}

	code := m.Run()

	_ = mailHog.Terminate(ctx)
	os.Exit(code)
}

func StartMailHogContainer(ctx context.Context) (tc.Container, *config.MailConfig, error) {
	req := tc.ContainerRequest{
		Image:        "mailhog/mailhog:latest",
		ExposedPorts: []string{"1025/tcp", "8025/tcp"},
		WaitingFor:   wait.ForHTTP("/api/v2/messages").WithPort("8025").WithStartupTimeout(45 * time.Second),
	}
	c, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, nil, err
	}

	host, err := c.Host(ctx)
	if err != nil {
		return nil, nil, err
	}

	smtpPort, err := c.MappedPort(ctx, nat.Port("1025/tcp"))
	if err != nil {
		return nil, nil, err
	}

	httpPort, err := c.MappedPort(ctx, nat.Port("8025/tcp"))
	if err != nil {
		return nil, nil, err
	}
	HttpPort = httpPort

	return c, &config.MailConfig{
		Host:        host,
		Port:        smtpPort.Int(),
		User:        "",
		Password:    "",
		AuthEnabled: false,
		TlsEnabled:  false,
	}, nil
}
