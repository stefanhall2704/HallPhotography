package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"text/template"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"

	"github.com/stefanhall2704/GoPhotography/db"
	"github.com/stefanhall2704/GoPhotography/middleware"
	"github.com/stefanhall2704/GoPhotography/model"
)

func serverErrorHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "404 not found", http.StatusNotFound)
}

var store = sessions.NewCookieStore([]byte("secret"))

func unauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	// Parse form data

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form data", http.StatusBadRequest)
		return
	}
	// Get username and password from form
	username := r.Form.Get("username")
	first_name := r.Form.Get("first_name")
	last_name := r.Form.Get("last_name")
	password := r.Form.Get("password")
	verified_password := r.Form.Get("verify_password")
	phone_number := r.Form.Get("phone_number")
	if password != verified_password {
		unauthorizedHandler(w, r)
		return
	}
	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}
	// Save user to the database
	user := model.User{
		FirstName:    first_name,
		LastName:     last_name,
		Username:     username,
		PasswordHash: string(hashedPassword),
		PhoneNumber:  phone_number,
		Email:        r.Form.Get("email"),
	}

	database := db.ConnectDatabase()
	if err := database.Create(&user).Error; err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}
	// Redirect or respond with success message
	loginHandler(w, r)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Enforce HTTPS
	if r.TLS == nil {
		http.Error(w, "HTTPS is required", http.StatusUpgradeRequired)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form data", http.StatusBadRequest)
		return
	}

	// CSRF token validation (implement your CSRF protection here)

	// Get username and password from form
	username := r.Form.Get("username")
	password := r.Form.Get("password")

	// Prevent logging of sensitive information like passwords
	log.Printf("Login attempt for username: %s", username)

	// Query user from the database by username
	var user model.User
	database := db.ConnectDatabase()
	if err := database.Where("username = ?", username).First(&user).Error; err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Compare hashed password with provided password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		// Implement rate limiting or account lockout here
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Create session
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Error getting session", http.StatusInternalServerError)
		return
	}
	session.Values["user"] = username
	session.Values["userID"] = user.ID // Store user ID as well

	// Secure cookie flags
	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600, // 1 hour
		HttpOnly: true,
		Secure:   true, // Ensure this is true for HTTPS
	}

	// Save the session
	if err := session.Save(r, w); err != nil {
		http.Error(w, "Error saving session", http.StatusInternalServerError)
		return
	}

	// Log session creation
	fmt.Println("Session created successfully for user:", username)

	// Redirect to the home page or any other desired page
	http.Redirect(w, r, "/", http.StatusFound)
}

// Logout Handler
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Clear session
	session, _ := store.Get(r, "session-name")
	delete(session.Values, "user")
	if err := session.Save(r, w); err != nil {
		http.Error(w, "Error saving session", http.StatusInternalServerError)
		return
	}
	// Redirect to login page
	http.Redirect(w, r, "/login", http.StatusFound)
}

// Authentication Middleware
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Retrieve session
		session, err := store.Get(r, "session-name")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Check session for authentication
		if _, ok := session.Values["user"]; !ok {
			// Redirect to login page if user is not authenticated
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}

func helloWorld(w http.ResponseWriter, r *http.Request) {
	cwd, _ := os.Getwd() // Gets the current working directory
	// Adjust the template path to be relative to the project root
	templatePath := filepath.Join(cwd, "templates", "hello_world.html")

	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		log.Printf("Error parsing template: %s", err)
		serverErrorHandler(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, nil); err != nil {
		log.Printf("Error executing template: %s", err)
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	cwd, _ := os.Getwd()
	templatePath := filepath.Join(cwd, "templates", "login.html")

	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		log.Printf("Error parsing template: %s", err)
		serverErrorHandler(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, nil); err != nil {
		log.Printf("Error executing template: %s", err)
	}
}

func signup(w http.ResponseWriter, r *http.Request) {
	cwd, _ := os.Getwd()
	templatePath := filepath.Join(cwd, "templates", "signup.html")

	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		log.Printf("Error parsing template: %s", err)
		serverErrorHandler(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, nil); err != nil {
		log.Printf("Error executing template: %s", err)
	}
}

func main() {
	// Register handlers
	http.Handle("/", logRequest(authMiddleware(http.HandlerFunc(helloWorld))))
	// http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	// 	if r.URL.Path != "/" {
	// 		notFoundHandler(w, r)
	// 		return
	// 	}
	// 	helloWorld(w, r)
	// })
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		login(w, r)
	})
	http.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) {
		signup(w, r)
	})
	http.HandleFunc("/login/process", loginHandler)
	http.Handle("/logout", logRequest(authMiddleware(http.HandlerFunc(logoutHandler))))
	http.HandleFunc("/register/process", registerHandler)

	// Create a new handler that applies the logging middleware
	loggedHandler := middleware.LoggingMiddleware(http.DefaultServeMux)

	log.Println("Starting server on :8080")
	// if err := http.ListenAndServe(":8080", loggedHandler); err != nil {
	// 	log.Fatalf("could not start server: %s", err)
	// }
	if err := http.ListenAndServeTLS(":8080", "server.crt", "server.key", loggedHandler); err != nil {
		log.Fatalf("could not start server: %s", err)
	}
}

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		next.ServeHTTP(w, r)
	})
}
