package main

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"fmt"
	"encoding/json"
	"strings"
	"strconv"
	// "encoding/json"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth/gothic"
	"github.com/gorilla/mux"

	"github.com/stefanhall2704/GoPhotography/auth"
	"github.com/stefanhall2704/GoPhotography/db"
	"github.com/stefanhall2704/GoPhotography/middleware"
	"github.com/stefanhall2704/GoPhotography/model"
	// "github.com/stefanhall2704/GoPhotography/calendar"
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


type SessionLength int

const (
	Session30Min SessionLength = 30
	Session1Hour SessionLength = 60
	Session2Hours SessionLength = 120
)

func NewSessionLength(minutes int) (SessionLength, error) {
	switch minutes {
	case 30:
		return Session30Min, nil
	case 60:
		return Session1Hour, nil
	case 120:
		return Session2Hours, nil
	default:
		return 0, fmt.Errorf("Unknown session length: (%d)", minutes)
	}
}

func checkForAvailableTimeSlot(timeSlot string, minisSessionId uint) bool {
	return true
}

func bookMinisSession(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error retrieving session: %v", err)
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	firstName, _ := session.Values["firstName"].(string)
	lastName, _ := session.Values["lastName"].(string)

	// convert userId
	userIdStr, _ := session.Values["userID"].(string)
  userId64, err := strconv.ParseUint(userIdStr, 10, 64)
  if err != nil {
      log.Fatal(err)
  }
  userId := uint(userId64)

	fullName := firstName + " " + lastName
	log.Printf("Full Name: %s", fullName)

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form data", http.StatusBadRequest)
		return
	}
	timeSlot := r.Form.Get("time_slot")

	// convert minisSessionId
	minisSessionIdStr := r.Form.Get("minis_session_id")
	minisSessionId64, err := strconv.ParseUint(minisSessionIdStr, 10, 64)
  if err != nil {
      log.Fatal(err)
  }
  minisSessionId := uint(minisSessionId64)

	if checkForAvailableTimeSlot(timeSlot, minisSessionId) == false {
		http.Error(w, "Session time slot already booked", http.StatusBadRequest)
		// Show popup to user that session is booked
		// redirect them back to the page with the sessions on there and show new time slots that are up to date
		return
	}
	bookMinis := model.BookMinis{
		MinisID: minisSessionId,
		UserID: userId,
		TimeSlot: timeSlot,
	}

	database := db.ConnectDatabase()
	if err := database.Create(&bookMinis).Error; err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}
}

func getMinis(w http.ResponseWriter, r *http.Request) {
	database := db.ConnectDatabase()
	var minis []model.BookMinis
	if err := database.Find(&minis).Error; err != nil {
		http.Error(w, "Error fetching sessions", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(minis)
}

func getMinisSessionDays(w http.ResponseWriter, r *http.Request) {
	database := db.ConnectDatabase()
	var minis []model.MinisDay
	if err := database.Find(&minis).Error; err != nil {
		http.Error(w, "Error fetching sessions", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(minis)
}

func getMinisSessions(w http.ResponseWriter, r *http.Request) {
	database := db.ConnectDatabase()
	var minis []model.Minis
	if err := database.Find(&minis).Error; err != nil {
		http.Error(w, "Error fetching sessions", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(minis)
}

func createMinisSession(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form data", http.StatusBadRequest)
		return
	}

	name := r.Form.Get("name")
	description := r.Form.Get("description")
	timeIntervals := r.Form.Get("time_intervals")
	sessionDays := r.Form.Get("session_days") // format needs to be like this: 2006-01-02T15:04,2006-01-02T15:04

	miniDaysSlice := strings.Split(sessionDays, ",")
	var miniDays []model.MinisDay

	for _, dayStr := range miniDaysSlice {
			layout := "2006-01-02T15:04"
			parsedTime, err := time.Parse(layout, dayStr)
			if err != nil {
				http.Error(w, "Invalid time format", http.StatusBadRequest)
				return
			}

    	miniDays = append(miniDays, model.MinisDay{
        	DayForMinis: parsedTime,
    	})
	}

	minisSession := model.Minis{
		Name: name,
		Description: description,
		DurationInterval: timeIntervals,
		Days: miniDays,
	}

	database := db.ConnectDatabase()
	if err := database.Create(&minisSession).Error; err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}
}

func showCalendar(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error retrieving session: %v", err)
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	// If you want to pass session info to the calendar, include these:
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

	t, err := template.ParseFiles("templates/minis/createminissessions.html")
	if err != nil {
		log.Printf("Error parsing template: %v", err)
		http.Error(w, "Error loading calendar page", http.StatusInternalServerError)
		return
	}

	if err := t.Execute(w, data); err != nil {
		log.Printf("Error executing calendar template: %v", err)
		http.Error(w, "Error rendering calendar", http.StatusInternalServerError)
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
	// database := db.ConnectDatabase()
	// if err := database.AutoMigrate(&model.User{}); err != nil {
	// 	log.Fatalf("Failed to migrate database: %v", err)
	// }
	// log.Println("Database migrated successfully")
	request := mux.NewRouter()
	request.HandleFunc("/", home).Methods("GET")
	request.Handle("/profile", auth.AuthMiddleware(http.HandlerFunc(userPofile))).Methods("GET")
	request.HandleFunc("/login", login).Methods("GET")
	request.HandleFunc("/signup", signup).Methods("GET")
	request.HandleFunc("/login/process", auth.LoginHandler).Methods("POST")
	request.HandleFunc("/logout", auth.LogoutHandler).Methods("GET")
	request.HandleFunc("/register/process", auth.RegisterHandler).Methods("POST")
	request.Handle("/create/minis_session", auth.AuthMiddleware(http.HandlerFunc(createMinisSession))).Methods("POST")
	request.HandleFunc("/auth/google/callback", auth.GoogleAuthCallbackHandler).Methods("GET")
	request.HandleFunc("/auth/google", func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), "provider", "google"))
		gothic.BeginAuthHandler(w, r)
	}).Methods("GET")
	request.Handle("/calendar", auth.AuthMiddleware(http.HandlerFunc(showCalendar))).Methods("GET")
	request.Handle("/get/minis_session", auth.AuthMiddleware(http.HandlerFunc(getMinisSessions))).Methods("GET")
	request.Handle("/get/minis_session_days", auth.AuthMiddleware(http.HandlerFunc(getMinisSessionDays))).Methods("GET")
	request.Handle("/get/minis", auth.AuthMiddleware(http.HandlerFunc(getMinis))).Methods("GET")

	loggedHandler := middleware.LoggingMiddleware(request)

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
