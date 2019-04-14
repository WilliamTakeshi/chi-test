package main

import (
	"crypto/rsa"
	"database/sql"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
	"github.com/golang-migrate/migrate"
	"github.com/golang-migrate/migrate/database/postgres"
	_ "github.com/golang-migrate/migrate/source/file"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// location of the files used for signing and verification
const (
	privKeyPath = "keys/app.rsa"     // openssl genrsa -out app.rsa 2048
	pubKeyPath  = "keys/app.rsa.pub" // openssl rsa -in app.rsa -pubout > app.rsa.pub
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)

type App struct {
	db *sqlx.DB
}

type Teacher struct {
	ID           int64  `db:"id"`
	Username     string `db:"username"`
	FullName     string `db:"full_name"`
	Email        string `db:"email"`
	PasswordHash string `db:"password_hash"`
	IsDisabled   bool   `db:"is_disabled"`
	CreatedAt    string `db:"created_at"`
	UpdatedAt    string `db:"updated_at"`
}

type CustomClaimsExample struct {
	*jwt.StandardClaims
	TokenType       string
	TeacherID       int64
	TeacherUsername string
}

type TeacherRequest struct {
	Username string `json:"username"`
	FullName string `json:"full_name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.URLFormat)
	r.Use(render.SetContentType(render.ContentTypeJSON))

	signBytes, err := ioutil.ReadFile(privKeyPath)
	fatal(err)

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	fatal(err)

	verifyBytes, err := ioutil.ReadFile(pubKeyPath)
	fatal(err)

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	fatal(err)

	db, err := sqlx.Connect("postgres", "user=william password= william dbname=chi-test sslmode=require")
	if err != nil {
		log.Fatal(err)
	}

	app := newAppResource(db)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello world"))
	})
	r.Get("/migrate", func(w http.ResponseWriter, r *http.Request) {
		MakeMigration(1)
	})
	r.Get("/rollback", func(w http.ResponseWriter, r *http.Request) {
		MakeMigration(-1)
	})
	// r.Get("/list_people", ListPeople(app))
	r.Post("/teacher", CreateTeacher(app))
	r.Post("/login", Login(app))
	r.Post("/restricted", RestrictedHandler(app))
	http.ListenAndServe(":3333", r)
}

func MakeMigration(steps int) {
	db, err := sql.Open("postgres", "postgres://william:william@localhost:5432/chi-test?sslmode=require")
	defer db.Close()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	m, err := migrate.NewWithDatabaseInstance(
		"file://migrations",
		"postgres", driver)
	m.Steps(steps)
}

// func ListPeople(app *App) http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		people := []Person{}
// 		app.db.Select(&people, "SELECT * FROM person ORDER BY first_name ASC")
// 		jason, john := people[0], people[1]

// 		fmt.Printf("%#v\n%#v", jason, john)

// 		fmt.Fprintf(w, "%#v\n%#v", jason, john)
// 	}
// }

// HashAndSalt a string password
func HashAndSalt(pwd string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	if err != nil {
		log.Println(err)
	}

	// GenerateFromPassword returns a byte slice so we need to
	// convert the bytes to a string and return it
	return string(hash)
}

func ComparePasswords(hashedPwd string, plainPwd string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPwd), []byte(plainPwd))
	if err != nil {
		log.Println(err)
		return false
	}

	return true
}

// CreateTeacher create a teacher and put on database
func CreateTeacher(app *App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		teacher := &TeacherRequest{}
		if err := render.Bind(r, teacher); err != nil {
			render.Render(w, r, ErrInvalidRequest(err))
			return
		}

		dbNewTeacher(app, teacher)
		// TODO add a response
	}
}

// Login teather
func Login(app *App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		login := &LoginRequest{}
		if err := render.Bind(r, login); err != nil {
			render.Render(w, r, ErrInvalidRequest(err))
			return
		}
		fmt.Println("tsra")
		teacher := dbGetTeacherByUsername(app, login.Username)
		if !ComparePasswords(teacher.PasswordHash, login.Password) {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, "Wrong info")
			return
		}
		fmt.Println("ts5ra")

		tokenString, err := CreateToken(teacher)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "Sorry, error while Signing Token!")
			log.Printf("Token Signing error: %v\n", err)
			return
		}
		fmt.Println("t4sra")
		fmt.Println(tokenString)

		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, tokenString)
	}
}

// CreateToken creates a JWToken
func CreateToken(teacher Teacher) (string, error) {
	t := jwt.New(jwt.GetSigningMethod("RS256"))

	// set our claims
	t.Claims = &CustomClaimsExample{
		&jwt.StandardClaims{
			// set the expire time
			// see http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4.1.4
			ExpiresAt: time.Now().Add(time.Minute * 1).Unix(),
		},
		"level1",
		teacher.ID,
		teacher.Username,
	}

	return t.SignedString(signKey)
}

func RestrictedHandler(app *App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get token from request
		token, err := request.ParseFromRequestWithClaims(r, request.OAuth2Extractor, &CustomClaimsExample{}, func(token *jwt.Token) (interface{}, error) {
			// since we only use the one private key to sign the tokens,
			// we also only use its public counter part to verify
			return verifyKey, nil
		})

		fmt.Println(token)
		fmt.Println(err)

		// If the token is missing or invalid, return error
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, "Invalid token:", err)
			return
		}

		// Token is valid
		fmt.Fprintln(w, "Welcome,", token.Claims.(*CustomClaimsExample).TeacherUsername)
		return
	}
}

func dbNewTeacher(app *App, teacher *TeacherRequest) (string, error) {
	tt, err := app.db.NamedExec("INSERT INTO teachers (username, full_name, email, password_hash) VALUES (:username, :fullname, :email, :password)",
		teacher)

	fmt.Println(tt)
	fmt.Println(err)

	return "article.ID", nil
}

func dbGetTeacherByUsername(app *App, username string) Teacher {
	tt := Teacher{}

	err := app.db.Get(&tt, "SELECT * FROM teachers WHERE username = $1", username)

	if err != nil {
		log.Fatal(err)
	}

	return tt
}

// Bind on teacher will run after the unmarshalling is complete
// This verify if the fields are filled and hash the password
func (t *TeacherRequest) Bind(r *http.Request) error {
	if t.Username == "" || t.FullName == "" || t.Email == "" || t.Password == "" {
		return errors.New("missing required teacher fields")
	}
	t.Password = HashAndSalt(t.Password)
	return nil
}

// Bind on teacher will run after the unmarshalling is complete
// This verify if the fields are filled and hash the password
func (t *LoginRequest) Bind(r *http.Request) error {
	if t.Username == "" || t.Password == "" {
		return errors.New("missing required teacher fields")
	}
	return nil
}

func newAppResource(db *sqlx.DB) *App {
	return &App{
		db: db,
	}
}

func ErrInvalidRequest(err error) render.Renderer {
	return &ErrResponse{
		Err:            err,
		HTTPStatusCode: 400,
		StatusText:     "Invalid request.",
		ErrorText:      err.Error(),
	}
}

type ErrResponse struct {
	Err            error `json:"-"` // low-level runtime error
	HTTPStatusCode int   `json:"-"` // http response status code

	StatusText string `json:"status"`          // user-level status message
	AppCode    int64  `json:"code,omitempty"`  // application-specific error code
	ErrorText  string `json:"error,omitempty"` // application-level error message, for debugging
}

func (e *ErrResponse) Render(w http.ResponseWriter, r *http.Request) error {
	render.Status(r, e.HTTPStatusCode)
	return nil
}

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
