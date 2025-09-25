package server

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/janobono/simple-auth/simple-auth-service/generated/openapi"
	"github.com/janobono/simple-auth/simple-auth-service/internal/config"
	"github.com/janobono/simple-auth/simple-auth-service/internal/server/impl"
)

type HttpServer struct {
	config   *config.ServerConfig
	services *Services
}

func NewHttpServer(config *config.ServerConfig, services *Services) *HttpServer {
	return &HttpServer{config, services}
}

func (s *HttpServer) Start() *http.Server {
	slog.Info("Starting http server...")

	handleFunctions := openapi.ApiHandleFunctions{
		AttributeControllerAPI: impl.NewAttributeController(s.services.AttributeService),
		AuthControllerAPI:      impl.NewAuthController(s.services.AuthService),
		AuthorityControllerAPI: impl.NewAuthorityController(s.services.AuthorityService),
		CaptchaControllerAPI:   impl.NewCaptchaController(s.services.CaptchaService),
		HealthControllerAPI:    impl.NewHealthController(),
		JwksControllerAPI:      impl.NewJwksController(s.services.JwkService),
		UserControllerAPI:      impl.NewUserController(s.services.UserService),
	}
	router := impl.NewRouter(impl.RouterContext{
		HandleFunctions:  handleFunctions,
		ContextPath:      s.config.ContextPath,
		ReadAuthorities:  s.config.SecurityConfig.ReadAuthorities,
		WriteAuthorities: s.config.SecurityConfig.WriteAuthorities,
		HttpHandlers:     impl.NewHttpHandlers(s.services.JwtService, s.services.UserService),
	})

	router.Use(cors.New(cors.Config{
		AllowOrigins:     s.config.CorsConfig.AllowedOrigins,
		AllowMethods:     s.config.CorsConfig.AllowedMethods,
		AllowHeaders:     s.config.CorsConfig.AllowedHeaders,
		ExposeHeaders:    s.config.CorsConfig.ExposedHeaders,
		AllowCredentials: s.config.CorsConfig.AllowCredentials,
		MaxAge:           s.config.CorsConfig.MaxAge,
	}))

	httpServer := &http.Server{
		Addr:    s.config.HTTPAddress,
		Handler: router,
	}

	// Start server in goroutine
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Failed to serve", "error", err)
			panic(err)
		}
	}()

	slog.Info("Http server started", "port", s.config.HTTPAddress)
	return httpServer
}
