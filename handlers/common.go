package handlers

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/stefanhall2704/GoPhotography/db"
	"github.com/stefanhall2704/GoPhotography/model"
)

func Home(w http.ResponseWriter, r *http.Request) {
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
	isAdmin, _ := session.Values["isAdmin"].(bool)

	var fullName string
	if firstName != "" && lastName != "" {
		fullName = firstName + " " + lastName
	}

	// Create data for the template
	data := map[string]interface{}{
		"UserID":        userID,
		"Email":         email,
		"Name":          fullName,
		"IsAdmin":       isAdmin,
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

func UserProfile(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error retrieving session: %v", err)
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	userID, _ := session.Values["userID"].(uint)
	firstName, _ := session.Values["firstName"].(string)
	lastName, _ := session.Values["lastName"].(string)
	email, _ := session.Values["email"].(string)
	isAdmin, _ := session.Values["isAdmin"].(bool)

	fullName := firstName + " " + lastName

	// Get user from database to fetch profile picture
	database := db.ConnectDatabase()
	var user model.User
	if err := database.First(&user, userID).Error; err != nil {
		log.Printf("Error fetching user: %v", err)
		http.Error(w, "Error fetching user data", http.StatusInternalServerError)
		return
	}

	// Generate initials
	initials := ""
	if len(firstName) > 0 {
		initials += string(firstName[0])
	}
	if len(lastName) > 0 {
		initials += string(lastName[0])
	}
	if initials == "" {
		initials = "?"
	}

	data := map[string]interface{}{
		"UserID":         userID,
		"Name":           fullName,
		"Email":          email,
		"IsAdmin":        isAdmin,
		"Authenticated":  true,
		"ProfilePicture": user.ProfilePicture,
		"Initials":       initials,
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

// GetUserBookings retrieves all bookings for the logged-in user
func GetUserBookings(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	userID, ok := session.Values["userID"].(uint)
	if !ok {
		http.Error(w, "User ID not found in session", http.StatusUnauthorized)
		return
	}

	database := db.ConnectDatabase()
	
	// Get minis bookings
	var minisBookings []model.BookMinis
	if err := database.Preload("Minis").Where("user_id = ?", userID).Find(&minisBookings).Error; err != nil {
		http.Error(w, "Error fetching minis bookings", http.StatusInternalServerError)
		return
	}

	// Get regular session bookings
	var sessionBookings []model.BookSession
	if err := database.Preload("Session").Where("user_id = ?", userID).Find(&sessionBookings).Error; err != nil {
		http.Error(w, "Error fetching session bookings", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"minisBookings":   minisBookings,
		"sessionBookings": sessionBookings,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func Login(w http.ResponseWriter, r *http.Request) {
	cwd, _ := os.Getwd()
	templatePath := filepath.Join(cwd, "templates", "login.html")

	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		log.Printf("Error parsing template: %s", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, nil); err != nil {
		log.Printf("Error executing template: %s", err)
	}
}

func Signup(w http.ResponseWriter, r *http.Request) {
	cwd, _ := os.Getwd()
	templatePath := filepath.Join(cwd, "templates", "signup.html")

	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		log.Printf("Error parsing template: %s", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, nil); err != nil {
		log.Printf("Error executing template: %s", err)
	}
}

func GetUsers(w http.ResponseWriter, r *http.Request) {
	database := db.ConnectDatabase()
	var users []model.User
	if err := database.Find(&users).Error; err != nil {
		http.Error(w, "Error fetching users", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(users)
}

func ServerErrorHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}

// GetCurrentUserStatus returns the current user's information including admin status
func GetCurrentUserStatus(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	userID, ok := session.Values["userID"].(uint)
	if !ok {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	database := db.ConnectDatabase()
	var user model.User
	if err := database.First(&user, userID).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"id":        user.ID,
		"firstName": user.FirstName,
		"lastName":  user.LastName,
		"email":     user.Email,
		"username":  user.Username,
		"isAdmin":   user.IsAdmin,
		"sessionIsAdmin": session.Values["isAdmin"],
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
