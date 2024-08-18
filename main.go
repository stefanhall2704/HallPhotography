package main

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth/gothic"

	"github.com/stefanhall2704/GoPhotography/auth"
	"github.com/stefanhall2704/GoPhotography/db"
	"github.com/stefanhall2704/GoPhotography/middleware"
	"github.com/stefanhall2704/GoPhotography/model"
)

func serverErrorHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}

// func notFoundHandler(w http.ResponseWriter, r *http.Request) {
// 	http.Error(w, "404 not found", http.StatusNotFound)
// }

var store = sessions.NewCookieStore([]byte("secret"))

func home(w http.ResponseWriter, r *http.Request) {
	// Retrieve session
	session, err := store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error retrieving session: %v", err)
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	// Get user session values
	userID, _ := session.Values["userID"].(uint)
	email, _ := session.Values["email"].(string)
	firstName, _ := session.Values["firstName"].(string)
	lastName, _ := session.Values["lastName"].(string)

	var fullName string
	if firstName != "" && lastName != "" {
		fullName = firstName + " " + lastName
	}

	// Create data for the template
	data := map[string]interface{}{
		"UserID":        userID,
		"Email":         email,
		"Name":          fullName,
		"Authenticated": userID != 0, // Checks if the user is logged in
	}

	// Parse and execute the template
	t, err := template.ParseFiles("templates/home.html")
	if err != nil {
		log.Printf("Error parsing template: %v", err)
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}

	if err := t.Execute(w, data); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Error rendering page", http.StatusInternalServerError)
	}
}

func userPofile(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error retrieving session: %v", err)
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	firstName, _ := session.Values["firstName"].(string)
	lastName, _ := session.Values["lastName"].(string)
	email, _ := session.Values["email"].(string)

	fullName := firstName + " " + lastName

	data := map[string]interface{}{
		"Name":  fullName,
		"Email": email,
	}

	t, err := template.ParseFiles("templates/user_profile.html")
	if err != nil {
		log.Printf("Error parsing template: %v", err)
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}

	if err := t.Execute(w, data); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Error rendering page", http.StatusInternalServerError)
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
	auth.Google_auth_consent()

	database := db.ConnectDatabase()

	if err := database.AutoMigrate(&model.User{}); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}
	log.Println("Database migrated successfully")

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		home(w, r)
	})
	// mux.Handle("/", logRequest(auth.AuthMiddleware(http.HandlerFunc(home))))
	mux.Handle("/profile", logRequest(auth.AuthMiddleware(http.HandlerFunc(userPofile))))
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		login(w, r)
	})
	mux.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) {
		signup(w, r)
	})
	mux.HandleFunc("/login/process", auth.LoginHandler)
	// mux.Handle("/logout", logRequest(auth.AuthMiddleware(http.HandlerFunc(auth.LogoutHandler))))

	mux.HandleFunc("/logout", auth.LogoutHandler)
	mux.HandleFunc("/register/process", auth.RegisterHandler)

	mux.HandleFunc(
		"/auth/google/callback",
		auth.GoogleAuthCallbackHandler,
	)
	mux.HandleFunc("/auth/google", func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), "provider", "google"))
		gothic.BeginAuthHandler(w, r)
	})

	loggedHandler := middleware.LoggingMiddleware(mux)

	log.Println("Starting server on :8080")
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
