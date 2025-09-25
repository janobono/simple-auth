package server_test

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/janobono/go-util/security"
	"github.com/janobono/simple-auth/simple-auth-service/internal/config"
	"github.com/janobono/simple-auth/simple-auth-service/internal/db"
	"github.com/janobono/simple-auth/simple-auth-service/internal/repository"
	"github.com/janobono/simple-auth/simple-auth-service/internal/server"
	"github.com/janobono/simple-auth/simple-auth-service/internal/service"
	"github.com/janobono/simple-auth/simple-auth-service/test"
	"golang.org/x/crypto/bcrypt"

	"github.com/docker/go-connections/nat"
	_ "github.com/jackc/pgx/v5/stdlib"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	initializer    server.Initializer
	mailClient     *test.TstMailClient
	captchaService *test.TstCaptchaService
	Server         *server.Server
	baseURL        string
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	freePort, err := getFreePort()
	if err != nil {
		log.Fatalf("could not get free port: %v", err)
	}

	postgres, dbConfig, err := StartPostgresContainer(ctx)
	if err != nil {
		log.Fatalf("could not start container: %v", err)
	}

	serverConfig := &config.ServerConfig{
		Prod:        false,
		HTTPAddress: freePort,
		ContextPath: "/api",
		DbConfig:    dbConfig,
		MailConfig: &config.MailConfig{
			Host:        "host",
			Port:        25,
			User:        "",
			Password:    "",
			AuthEnabled: false,
			TlsEnabled:  false,
		},
		SecurityConfig: &config.SecurityConfig{
			ReadAuthorities:          []string{"manager"},
			WriteAuthorities:         []string{"admin"},
			DefaultUsername:          "simple@auth.org",
			DefaultPassword:          "$2a$10$gRKMsjTON2A4b5PDIgjej.EZPvzVaKRj52Mug/9bfQBzAYmVF0Cae",
			TokenIssuer:              "simple",
			AccessTokenExpiresIn:     time.Duration(30) * time.Minute,
			AccessTokenJwkExpiresIn:  time.Duration(720) * time.Minute,
			RefreshTokenExpiresIn:    time.Duration(10080) * time.Minute,
			RefreshTokenJwkExpiresIn: time.Duration(20160) * time.Minute,
			ContentTokenExpiresIn:    time.Duration(10080) * time.Minute,
			ContentTokenJwkExpiresIn: time.Duration(20160) * time.Minute,
		},
		CaptchaConfig: &config.CaptchaConfig{
			Characters: "abcdefghijklmnopqrstuvwxyz0123456789",
			TextLength: 8,
			Width:      200,
			Height:     70,
			NoiseLines: 8,
			Font:       "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
			FontSize:   32,
		},
		CorsConfig: &config.CorsConfig{
			AllowedOrigins:   []string{"http://localhost", "http://localhost:3000"},
			AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE"},
			AllowedHeaders:   []string{"Origin", "Content - Type", "Accept", "Authorization"},
			ExposedHeaders:   []string{"Content - length"},
			AllowCredentials: true,
			MaxAge:           time.Duration(12) * time.Hour,
		},
		AppConfig: &config.AppConfig{
			ConfirmationWebUrl:            "http://localhost:3000",
			ConfirmationPath:              "/confirm?token=",
			SignUpConfirmationMailEnabled: true,
			PasswordCharacters:            "abcdefghijklmnopqrstuvwxyz0123456789",
			PasswordLength:                8,
			MandatoryUserAttributes:       map[string]string{},
			MandatoryUserAuthorities:      []string{},
		},
	}

	initializer = &testInitializer{}

	Server = server.NewServer(serverConfig, initializer)

	baseURL = fmt.Sprintf("http://localhost%s%s", freePort, serverConfig.ContextPath)

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

func ResetDB(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := initializer.Repositories(nil).UserRepository.DeleteAll(ctx)
	if err != nil {
		t.Fatalf("failed to delete users: %v", err)
	}

	err = initializer.Repositories(nil).JwkRepository.DeleteAll(ctx)
	if err != nil {
		t.Fatalf("failed to delete jwks: %v", err)
	}

	err = initializer.Repositories(nil).AttributeRepository.DeleteAll(ctx)
	if err != nil {
		t.Fatalf("failed to delete attributes: %v", err)
	}

	err = initializer.Repositories(nil).AuthorityRepository.DeleteAll(ctx)
	if err != nil {
		t.Fatalf("failed to delete authorities: %v", err)
	}
}

func getFreePort() (string, error) {
	var port string
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return "", err
	}
	defer l.Close()

	addr := l.Addr().(*net.TCPAddr)
	port = fmt.Sprintf(":%d", addr.Port)
	return port, nil
}

type testInitializer struct {
	rwMutex      sync.RWMutex
	repositories *server.Repositories
	utils        *server.Utils
	clients      *server.Clients
	services     *server.Services
}

func (t *testInitializer) Repositories(dataSource *db.DataSource) *server.Repositories {
	t.rwMutex.Lock()
	defer t.rwMutex.Unlock()

	if t.repositories == nil {
		t.repositories = &server.Repositories{
			AttributeRepository: repository.NewAttributeRepository(dataSource),
			AuthorityRepository: repository.NewAuthorityRepository(dataSource),
			JwkRepository:       repository.NewJwkRepository(dataSource),
			UserRepository:      repository.NewUserRepository(dataSource),
		}
	}

	return t.repositories
}

func (t *testInitializer) Utils(serverConfig *config.ServerConfig) *server.Utils {
	t.rwMutex.Lock()
	defer t.rwMutex.Unlock()

	if t.utils == nil {
		t.utils = &server.Utils{
			PasswordEncoder: security.NewPasswordEncoder(bcrypt.DefaultCost),
			RandomString:    security.NewRandomString(serverConfig.AppConfig.PasswordCharacters, serverConfig.AppConfig.PasswordLength),
		}
	}

	return t.utils
}

func (t *testInitializer) Clients(serverConfig *config.ServerConfig) *server.Clients {
	t.rwMutex.Lock()
	defer t.rwMutex.Unlock()

	mailClient = &test.TstMailClient{}

	if t.clients == nil {
		t.clients = &server.Clients{
			MailClient: mailClient,
		}
	}

	return t.clients
}

func (t *testInitializer) Services(serverConfig *config.ServerConfig, repositories *server.Repositories, utils *server.Utils, clients *server.Clients) *server.Services {
	t.rwMutex.Lock()
	defer t.rwMutex.Unlock()

	if t.services == nil {

		jwtService := service.NewJwtService(serverConfig.SecurityConfig, repositories.JwkRepository)

		captchaService = &test.TstCaptchaService{}

		t.services = &server.Services{
			AttributeService: service.NewAttributeService(repositories.AttributeRepository),
			AuthService: service.NewAuthService(
				serverConfig.AppConfig,
				serverConfig.MailConfig,
				utils.PasswordEncoder,
				utils.RandomString,
				clients.MailClient,
				jwtService,
				captchaService,
				repositories.AttributeRepository,
				repositories.AuthorityRepository,
				repositories.UserRepository,
			),
			AuthorityService: service.NewAuthorityService(repositories.AuthorityRepository),
			CaptchaService:   captchaService,
			JwkService:       service.NewJwkService(repositories.JwkRepository),
			JwtService:       jwtService,
			UserService: service.NewUserService(
				utils.PasswordEncoder,
				utils.RandomString,
				repositories.AttributeRepository,
				repositories.AuthorityRepository,
				repositories.UserRepository,
			),
		}
	}

	return t.services
}
