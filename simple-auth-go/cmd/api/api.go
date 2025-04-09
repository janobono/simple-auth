package api

import (
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type APIServer struct {
	addr string
}

func NewAPIServer(addr string) *APIServer {
	return &APIServer{
		addr: addr,
	}
}

func (s *APIServer) Run(contextPath string) error {
	router := chi.NewRouter()

	router.Use(middleware.Logger)

	router.Get(fmt.Sprintf("%s/users/{userId}", contextPath), func(writer http.ResponseWriter, request *http.Request) {
		userId := request.PathValue("userId")
		writer.Write([]byte("User id: " + userId))
	})

	server := http.Server{
		Addr:    s.addr,
		Handler: router,
	}

	log.Printf("Server has started %s", s.addr)

	return server.ListenAndServe()
}
