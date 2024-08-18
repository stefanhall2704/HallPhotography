package auth

import (
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
	"golang.org/x/crypto/bcrypt"

	"github.com/stefanhall2704/GoPhotography/db"
	"github.com/stefanhall2704/GoPhotography/model"
)

var store = sessions.NewCookieStore([]byte("secret"))

func UnauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form data", http.StatusBadRequest)
		return
	}
	username := r.Form.Get("username")
	first_name := r.Form.Get("first_name")
	last_name := r.Form.Get("last_name")
	password := r.Form.Get("password")
	verified_password := r.Form.Get("verify_password")
	phone_number := r.Form.Get("phone_number")
	if password != verified_password {
		UnauthorizedHandler(w, r)
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}
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
	LoginHandler(w, r)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		http.Error(w, "HTTPS is required", http.StatusUpgradeRequired)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form data", http.StatusBadRequest)
		return
	}

	username := r.Form.Get("username")
	password := r.Form.Get("password")

	var user model.User
	database := db.ConnectDatabase()
	if err := database.Where("username = ?", username).First(&user).Error; err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Error getting session", http.StatusInternalServerError)
		return
	}
	session.Values["user"] = username
	session.Values["userID"] = user.ID
	session.Values["firstName"] = user.FirstName
	session.Values["lastName"] = user.LastName
	session.Values["email"] = user.Email
	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true, // Ensure HTTPS
	}

	if err := session.Save(r, w); err != nil {
		http.Error(w, "Error saving session", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func GoogleAuthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	user, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		log.Printf("Error completing user auth: %v", err)
		http.Error(w, "OAuth authentication failed", http.StatusInternalServerError)
		return
	}

	names := strings.Split(user.Name, " ")
	firstName := names[0]
	lastName := ""
	if len(names) > 1 {
		lastName = strings.Join(names[1:], " ")
	}

	var dbUser model.User
	database := db.ConnectDatabase()

	if err := database.Where("email = ?", user.Email).First(&dbUser).Error; err != nil {
		dbUser = model.User{
			FirstName:   firstName,
			LastName:    lastName,
			Username:    user.Email,
			Email:       user.Email,
			PhoneNumber: "",
		}

		if err := database.Create(&dbUser).Error; err != nil {
			log.Printf("Error creating user: %v", err)
			http.Error(w, "Error creating user", http.StatusInternalServerError)
			return
		}
	}

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

	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true, // Make sure to set this to true for HTTPS
	}

	if err := session.Save(r, w); err != nil {
		log.Printf("Error saving session: %v", err)
		http.Error(w, "Error saving session", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")

	session.Values = make(map[interface{}]interface{})

	if err := session.Save(r, w); err != nil {
		http.Error(w, "Error saving session", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "session-name")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if _, ok := session.Values["user"]; !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func LoadEnv() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, proceeding without it")
	}
}

func Google_auth_consent() {
	LoadEnv()

	key := os.Getenv("SESSION_SECRET")
	googleClientID := os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	googleCallbackURL := os.Getenv("GOOGLE_CALLBACK_URL")

	if key == "" || googleClientID == "" || googleClientSecret == "" || googleCallbackURL == "" {
		log.Fatal("Environment variables are not set properly")
	}

	maxAge := 86400 * 30
	isProd := true // Set to true for https

	store := sessions.NewCookieStore([]byte(key))
	store.MaxAge(maxAge)
	store.Options.Path = "/"
	store.Options.HttpOnly = true
	store.Options.Secure = isProd

	gothic.Store = store

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
