package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/denisenkom/go-mssqldb"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Id       int    `json:"id" form:"id"`
	Email    string `json:"email" form:"email"`
	Password string `json:"password" form:"password"`
	IsAdmin  bool   `json:"is_admin" form:"is_admin"`
}
type UserBody struct {
	Email    string `validate:"required,email"`
	Password string `validate:"required"`
	IsAdmin  bool   `validate:"omitempty"`
}

type UserResult struct {
	Id      int
	Email   string
	IsAdmin bool
}

type APIServer struct {
	addr string
}

func NewAPIServer(addr string) *APIServer {
	return &APIServer{addr: addr}
}

func hashPassword(password string) string {
	rounds, _ := strconv.Atoi(os.Getenv("ROUNDS"))
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), rounds)
	return string(hash)
}
func comparePassword(hashedPassword string, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return err
	}
	return nil
}

func getAllUser(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("sqlserver", os.Getenv("DB_URI"))
	var listUser []UserResult
	rows, _ := db.Query("select id, email, isAdmin from Users")
	for rows.Next() {
		var user UserResult
		rows.Scan(&user.Id, &user.Email, &user.IsAdmin)
		listUser = append(listUser, user)
	}
	rows.Close()
	json.NewEncoder(w).Encode(map[string]any{"users": listUser})
}

func (s *APIServer) Run() error {
	db, _ := sql.Open("sqlserver", os.Getenv("DB_URI"))
	router := http.NewServeMux()

	getAllUserHandler := http.HandlerFunc(getAllUser)
	router.Handle("GET /users", VerifyToken(getAllUserHandler))

	router.HandleFunc("POST /register", func(w http.ResponseWriter, r *http.Request) {
		validate := validator.New(validator.WithRequiredStructEnabled())
		var user UserBody
		var u User
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
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

	router.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		validate := validator.New(validator.WithRequiredStructEnabled())
		var user UserBody

		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
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
		oneRow, err := db.Query("select top 1 id, email, password, isAdmin from Users where email=@email", sql.Named("email", user.Email))
		var findUser User
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{"message": "FIND ONE ERROR", "error": err.Error()})
			return
		}
		for oneRow.Next() {
			oneRow.Scan(&findUser.Id, &findUser.Email, &findUser.Password, &findUser.IsAdmin)

		}
		oneRow.Close()
		err = bcrypt.CompareHashAndPassword([]byte(findUser.Password), []byte(user.Password))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{"message": "Wrong password"})
			return
		}

		userId := strconv.Itoa(findUser.Id)
		claims := &jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        userId,
			Issuer:    findUser.Email,
			Subject:   strconv.FormatBool(findUser.IsAdmin),
		}
		mysecret := []byte(os.Getenv("ACCESS_TOKEN_SECRET"))
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString(mysecret)

		var userResult UserResult
		userResult.Id = findUser.Id
		userResult.Email = findUser.Email
		userResult.IsAdmin = findUser.IsAdmin

		json.NewEncoder(w).Encode(map[string]any{"user": userResult, "accessToken": tokenString})
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
		tokenString := r.Header.Get("Authorization")

		if tokenString != "Bearer token" {
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

func VerifyToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		} else {
			token := strings.Split(tokenString, " ")[1]
			if token == "" {
				http.Error(w, "Token not found", http.StatusNotFound)
				return
			}
			valid, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
				return []byte(os.Getenv("ACCESS_TOKEN_SECRET")), nil
			})

			if valid.Valid {
				next.ServeHTTP(w, r)
			} else if ve, ok := err.(*jwt.ValidationError); ok {
				if ve.Errors&jwt.ValidationErrorMalformed != 0 {
					json.NewEncoder(w).Encode(map[string]any{
						"status":  "failure",
						"message": "Token is not valid"})
					return
				} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
					json.NewEncoder(w).Encode(map[string]any{
						"status":  "failure",
						"message": "Token is expired"})
					return
				} else {
					json.NewEncoder(w).Encode(map[string]any{
						"status":  "failure",
						"message": "Couldn't handle this token"})
					return
				}
			} else {
				json.NewEncoder(w).Encode(map[string]any{
					"status":  "failure",
					"message": "Couldn't handle this token"})
				return
			}
		}
	})
}
