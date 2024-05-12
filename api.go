package main

import (
	"log"
	"net/http"
)

type APIServer struct {
	addr string
}

func NewAPIServer(addr string) *APIServer {
	return &APIServer{addr: addr}
}

func (s *APIServer) Run() error {
	router := http.NewServeMux()
	router.HandleFunc("GET /users/{userId}", func(w http.ResponseWriter, r *http.Request) {
		userId := r.PathValue("userId")
		w.Write([]byte("UserId : " + userId))

	})
	router.HandleFunc("PUT /api/v1/users/{userId}", func(w http.ResponseWriter, r *http.Request) {
		userId := r.PathValue("userId")
		w.Write([]byte("UserId : " + userId))

	})

	router.HandleFunc("GET /api/v1/users/{userId}", func(w http.ResponseWriter, r *http.Request) {
		userId := r.PathValue("userId")
		w.Write([]byte("UserId : " + userId))

	})

	v1 := http.NewServeMux()
	v1.Handle("/api/v1/", http.StripPrefix("/api/v1", router))

	// server := http.Server{Addr: s.addr,Handler: RequireAuthMiddleware(RequestLoggerMiddleware(router))}
	middlewareChain := MiddlewareChain(RequestLoggerMiddleware, RequireAuthMiddleware)
	// server := http.Server{Addr: s.addr, Handler: MiddlewareChain(RequestLoggerMiddleware, RequireAuthMiddleware)(router)}

	server := http.Server{Addr: s.addr, Handler: middlewareChain(router)}
	log.Printf("Server has started: %s", s.addr)
	return server.ListenAndServe()
}

func RequestLoggerMiddleware(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Method : %s, Path : %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	}

}

func RequireAuthMiddleware(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token != "Bearer token" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	}
}

type Middleware func(http.Handler) http.HandlerFunc

func MiddlewareChain(middlewares ...Middleware) Middleware {
	return func(next http.Handler) http.HandlerFunc {
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}
		return next.ServeHTTP
	}
}
