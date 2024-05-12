package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"reflect"
	"strings"

	_ "github.com/denisenkom/go-mssqldb"
	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Id    int    `json:"id" form:"id"`
	Email string `json:"email" form:"email"`
	// Password string `json:"password" form:"password"`
	IsAdmin bool `json:"is_admin" form:"is_admin"`
}
type UserBody struct {
	Email    string `validate:"required,email"`
	Password string `validate:"required"`
	IsAdmin  bool   `validate:"omitempty"`
}
type APIServer struct {
	addr string
}

func NewAPIServer(addr string) *APIServer {
	return &APIServer{addr: addr}
}

func (s *APIServer) Run() error {
	db, _ := sql.Open("sqlserver", "sqlserver://sa:123456789@localhost:1433?database=MYDATABASE&connection+timeout=30")
	router := http.NewServeMux()
	router.HandleFunc("GET /users/{userId}", func(w http.ResponseWriter, r *http.Request) {
		userId := r.PathValue("userId")
		json.NewEncoder(w).Encode(map[string]any{"userId": userId, "status": 200})
	})
	router.HandleFunc("POST /users", func(w http.ResponseWriter, r *http.Request) {
		validate := validator.New(validator.WithRequiredStructEnabled())
		validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
			name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
			if name == "-" {
				return ""
			}
			return name
		})
		var user UserBody
		var u User
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]any{"message": "INVALID BODY"})
			return
		}

		if err := validate.Struct(user); err != nil {
			var errors []string
			for _, err := range err.(validator.ValidationErrors) {
				errors = append(errors, err.Field()+": "+err.Tag())
			}
			errorResponse := map[string]interface{}{"errors": errors}
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(errorResponse)
			return
		}

		oneRow, err := db.Query("select top 1 email from Users where email=@email", sql.Named("email", user.Email))
		if err != nil {
			json.NewEncoder(w).Encode(map[string]any{"message": "FIND ONE ERROR", "error": err.Error()})
			return
		}
		var email string
		for oneRow.Next() {
			oneRow.Scan(&email)
		}
		oneRow.Close()
		if user.Email == email {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{"message": "Email already exits"})
			return
		} else {
			password := []byte(user.Password)
			hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]any{"message": "HASHED PASSWORD ERROR"})
				return
			}
			row, err := db.Query("INSERT INTO Users(email, password, isAdmin) VALUES (@email, @password, @isAdmin);select ID = convert(bigint, SCOPE_IDENTITY())", sql.Named("email", user.Email), sql.Named("password", hashedPassword), sql.Named("isAdmin", user.IsAdmin))
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]any{"message": "QUERY ERROR", "error": err.Error()})
				return
			}
			var lastInsertId int64
			for row.Next() {
				row.Scan(&lastInsertId)
			}
			u.Id = int(lastInsertId)
			u.Email = user.Email
			u.IsAdmin = user.IsAdmin
			row.Close()
			json.NewEncoder(w).Encode(map[string]any{"user": u})
		}
	})
	middlewareChain := MiddlewareChain(RequestLoggerMiddleware)
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
