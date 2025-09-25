package repository_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/janobono/simple-auth/simple-auth-service/internal/config"
	"github.com/janobono/simple-auth/simple-auth-service/internal/db"

	"github.com/docker/go-connections/nat"
	_ "github.com/jackc/pgx/v5/stdlib"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	DataSource *db.DataSource
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	postgres, cfg, err := StartPostgresContainer(ctx)
	if err != nil {
		log.Fatalf("could not start container: %v", err)
	}

	DataSource = db.NewDataSource(cfg)
	defer DataSource.Close()

	ctxPing, cancelPing := context.WithTimeout(ctx, 10*time.Second)
	defer cancelPing()
	for i := 0; i < 50; i++ {
		if err := DataSource.Pool.Ping(ctxPing); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	code := m.Run()

	_ = postgres.Terminate(ctx)

	os.Exit(code)
}

func StartPostgresContainer(ctx context.Context) (tc.Container, *config.DbConfig, error) {
	req := tc.ContainerRequest{
		Image:        "public.ecr.aws/docker/library/postgres:alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_PASSWORD": "app",
			"POSTGRES_USER":     "app",
			"POSTGRES_DB":       "app",
		},
		WaitingFor: wait.ForSQL("5432/tcp", "pgx", func(host string, port nat.Port) string {
			return fmt.Sprintf("host=%s port=%s user=app password=app dbname=app sslmode=disable", host, port.Port())
		}).WithStartupTimeout(30 * time.Second),
	}

	postgres, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, nil, err
	}

	host, err := postgres.Host(ctx)
	if err != nil {
		return nil, nil, err
	}
	p, err := postgres.MappedPort(ctx, "5432")
	if err != nil {
		return nil, nil, err
	}

	return postgres, &config.DbConfig{
		Url:            fmt.Sprintf("%s:%s/app", host, p.Port()),
		User:           "app",
		Password:       "app",
		MaxConnections: 5,
		MinConnections: 2,
		MigrationsUrl:  "file://../../migrations",
	}, nil
}
