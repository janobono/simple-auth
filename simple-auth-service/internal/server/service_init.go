package server

import (
	"github.com/janobono/go-util/security"
	"github.com/janobono/simple-auth/simple-auth-service/internal/config"
	"github.com/janobono/simple-auth/simple-auth-service/internal/db"
	"github.com/janobono/simple-auth/simple-auth-service/internal/repository"
	"github.com/janobono/simple-auth/simple-auth-service/internal/service"
	"github.com/janobono/simple-auth/simple-auth-service/internal/service/client"
	"golang.org/x/crypto/bcrypt"
)

type Repositories struct {
	AttributeRepository repository.AttributeRepository
	AuthorityRepository repository.AuthorityRepository
	JwkRepository       repository.JwkRepository
	UserRepository      repository.UserRepository
}

type Utils struct {
	PasswordEncoder *security.PasswordEncoder
	RandomString    *security.RandomString
}

type Clients struct {
	MailClient client.MailClient
}

type Services struct {
	AttributeService *service.AttributeService
	AuthService      *service.AuthService
	AuthorityService *service.AuthorityService
	CaptchaService   service.CaptchaService
	JwkService       *service.JwkService
	JwtService       *service.JwtService
	UserService      *service.UserService
}

type Initializer interface {
	Repositories(dataSource *db.DataSource) *Repositories
	Utils(serverConfig *config.ServerConfig) *Utils
	Clients(serverConfig *config.ServerConfig) *Clients
	Services(serverConfig *config.ServerConfig, repositories *Repositories, utils *Utils, clients *Clients) *Services
}

type defaultInitializer struct {
}

var _ Initializer = (*defaultInitializer)(nil)

func NewInitializer() Initializer {
	return &defaultInitializer{}
}

func (di *defaultInitializer) Repositories(dataSource *db.DataSource) *Repositories {
	return &Repositories{
		repository.NewAttributeRepository(dataSource),
		repository.NewAuthorityRepository(dataSource),
		repository.NewJwkRepository(dataSource),
		repository.NewUserRepository(dataSource),
	}
}

func (di *defaultInitializer) Utils(serverConfig *config.ServerConfig) *Utils {
	return &Utils{
		security.NewPasswordEncoder(bcrypt.DefaultCost),
		security.NewRandomString(serverConfig.AppConfig.PasswordCharacters, serverConfig.AppConfig.PasswordLength),
	}
}

func (di *defaultInitializer) Clients(serverConfig *config.ServerConfig) *Clients {
	return &Clients{
		MailClient: client.NewMailClient(serverConfig.MailConfig),
	}
}

func (di *defaultInitializer) Services(serverConfig *config.ServerConfig, repositories *Repositories, utils *Utils, clients *Clients) *Services {
	jwtService := service.NewJwtService(serverConfig.SecurityConfig, repositories.JwkRepository)

	captchaService := service.NewCaptchaService(serverConfig.CaptchaConfig, utils.PasswordEncoder, jwtService)

	return &Services{
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
