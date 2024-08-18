package main

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
	"golang.org/x/crypto/bcrypt"

	"github.com/stefanhall2704/GoPhotography/db"
	"github.com/stefanhall2704/GoPhotography/middleware"
	"github.com/stefanhall2704/GoPhotography/model"
)

func loadEnv() {
	// Load .env file in development
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, proceeding without it")
	}
}

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

	// Get username and password from form
	username := r.Form.Get("username")
	password := r.Form.Get("password")

	// Query user from the database by username
	var user model.User
	database := db.ConnectDatabase()
	if err := database.Where("username = ?", username).First(&user).Error; err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Compare hashed password with provided password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
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
	session.Values["userID"] = user.ID

	// Secure cookie flags
	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600, // 1 hour
		HttpOnly: true,
		Secure:   true, // Ensure HTTPS
	}

	// Save the session
	if err := session.Save(r, w); err != nil {
		http.Error(w, "Error saving session", http.StatusInternalServerError)
		return
	}

	// Redirect to the home page
	http.Redirect(w, r, "/", http.StatusFound)
}

func googleAuthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Complete the Google OAuth authentication
	user, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		log.Printf("Error completing user auth: %v", err)
		http.Error(w, "OAuth authentication failed", http.StatusInternalServerError)
		return
	}

	// Split the full name into first and last name
	names := strings.Split(user.Name, " ")
	firstName := names[0]
	lastName := ""
	if len(names) > 1 {
		lastName = strings.Join(names[1:], " ")
	}

	// Fetch or create the user in your database using the Google profile
	var dbUser model.User
	database := db.ConnectDatabase()

	// Check if user exists based on their email address
	if err := database.Where("email = ?", user.Email).First(&dbUser).Error; err != nil {
		// If user does not exist, create a new user record
		dbUser = model.User{
			FirstName:   firstName,
			LastName:    lastName,
			Username:    user.Email, // Use email as a default username if not provided
			Email:       user.Email,
			PhoneNumber: "", // Google OAuth might not provide a phone number
			// PasswordHash remains empty since it's not needed for OAuth users
		}

		if err := database.Create(&dbUser).Error; err != nil {
			log.Printf("Error creating user: %v", err)
			http.Error(w, "Error creating user", http.StatusInternalServerError)
			return
		}
	}

	// Create session and store the user ID
	session, err := store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error getting session: %v", err)
		http.Error(w, "Error getting session", http.StatusInternalServerError)
		return
	}
	// session.Values["user"] is not actually used, but is a required session value for the session to be successful for google consent oauth
	session.Values["user"] = dbUser.Username
	session.Values["userID"] = dbUser.ID
	session.Values["firstName"] = dbUser.FirstName
	session.Values["lastName"] = dbUser.LastName
	session.Values["email"] = dbUser.Email

	// Secure the session with cookie options
	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600, // 1 hour
		HttpOnly: true,
		Secure:   true, // Make sure to set this to true for HTTPS
	}

	// Save the session
	if err := session.Save(r, w); err != nil {
		log.Printf("Error saving session: %v", err)
		http.Error(w, "Error saving session", http.StatusInternalServerError)
		return
	}

	// Redirect to home page or desired page after successful login
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
	session, err := store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error retrieving session: %v", err)
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	// Retrieve user information from the session
	userID, _ := session.Values["userID"].(uint)
	email, _ := session.Values["email"].(string)
	firstName, _ := session.Values["firstName"].(string)
	lastName, _ := session.Values["lastName"].(string)

	// Combine the name
	fullName := firstName + " " + lastName

	// Pass data to the template
	data := map[string]interface{}{
		"UserID": userID,
		"Email":  email,
		"Name":   fullName,
	}

	// Parse and execute the template
	t, err := template.ParseFiles("templates/hello_world.html")
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

func google_auth_consent() {
	loadEnv()

	// Load sensitive information from environment variables
	key := os.Getenv("SESSION_SECRET")
	googleClientID := os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	googleCallbackURL := os.Getenv("GOOGLE_CALLBACK_URL")

	if key == "" || googleClientID == "" || googleClientSecret == "" || googleCallbackURL == "" {
		log.Fatal("Environment variables are not set properly")
	}

	maxAge := 86400 * 30 // 30 days
	isProd := true       // Set to true for https

	store := sessions.NewCookieStore([]byte(key))
	store.MaxAge(maxAge)
	store.Options.Path = "/"
	store.Options.HttpOnly = true // HttpOnly should always be enabled
	store.Options.Secure = isProd

	gothic.Store = store

	// Register Google OAuth provider
	goth.UseProviders(
		google.New(
			googleClientID,
			googleClientSecret,
			googleCallbackURL,
			"email", "profile",
		),
	)

	log.Println("Google OAuth provider registered")
}

func main() {
	// Initialize the Google OAuth provider before starting the server
	google_auth_consent()

	// Initialize the database connection
	database := db.ConnectDatabase()

	// Run auto migration to create the users table based on the User model
	if err := database.AutoMigrate(&model.User{}); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}
	log.Println("Database migrated successfully")

	// Create a new ServeMux to register handlers
	mux := http.NewServeMux()

	// Register existing routes
	mux.Handle("/", logRequest(authMiddleware(http.HandlerFunc(helloWorld))))
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		login(w, r)
	})
	mux.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) {
		signup(w, r)
	})
	mux.HandleFunc("/login/process", loginHandler)
	mux.Handle("/logout", logRequest(authMiddleware(http.HandlerFunc(logoutHandler))))
	mux.HandleFunc("/register/process", registerHandler)

	// Add the Google OAuth routes
	mux.HandleFunc(
		"/auth/google/callback",
		googleAuthCallbackHandler,
	) // Directly handle the callback route
	mux.HandleFunc("/auth/google", func(w http.ResponseWriter, r *http.Request) {
		// Explicitly set the provider
		r = r.WithContext(context.WithValue(r.Context(), "provider", "google"))
		gothic.BeginAuthHandler(w, r) // Initiate the Google OAuth flow
	})

	// Wrap the mux with any middleware if necessary
	loggedHandler := middleware.LoggingMiddleware(mux)

	// Start the server
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
