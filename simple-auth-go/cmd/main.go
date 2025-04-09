package main

import (
	"github.com/janobono/simple-auth/simple-auth-go/cmd/api"
	"github.com/janobono/simple-auth/simple-auth-go/pkg/config"
	"github.com/janobono/simple-auth/simple-auth-go/pkg/db"
	"log"
)

func main() {
	appConfig := config.InitConfig()

	pool := db.InitDb(appConfig.DbConfig)
	defer pool.Close()

	server := api.NewAPIServer(appConfig.ServerConfig.Addr)
	if err := server.Run(appConfig.ServerConfig.ContextPath); err != nil {
		log.Fatal(err)
	}
}
