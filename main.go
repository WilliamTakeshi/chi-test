package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"golang.org/x/crypto/bcrypt"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
	"github.com/golang-migrate/migrate"
	"github.com/golang-migrate/migrate/database/postgres"
	_ "github.com/golang-migrate/migrate/source/file"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
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

		teacher := dbGetTeacherByUsername(app, login.Username)
		result := ComparePasswords(teacher.PasswordHash, login.Password)
		fmt.Println(result)
		fmt.Println(teacher)
		// TODO add a response
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
