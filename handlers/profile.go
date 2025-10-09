package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/stefanhall2704/GoPhotography/db"
	"github.com/stefanhall2704/GoPhotography/model"
)

const (
	MaxProfilePictureSize = 10 << 20 // 10 MB
	ProfilePictureDir     = "/app/uploads/profile_pictures"
)

// Ensure profile picture directory exists
func init() {
	if err := os.MkdirAll(ProfilePictureDir, 0755); err != nil {
		log.Printf("Warning: Could not create profile picture directory: %v", err)
	}
}

// UploadProfilePicture handles profile picture uploads
func UploadProfilePicture(w http.ResponseWriter, r *http.Request) {
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

	// Parse multipart form
	if err := r.ParseMultipartForm(MaxProfilePictureSize); err != nil {
		log.Printf("Error parsing multipart form: %v", err)
		http.Error(w, "File too large or form parsing error", http.StatusBadRequest)
		return
	}

	// Get the file from form
	file, fileHeader, err := r.FormFile("profile_picture")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Validate file type
	contentType := fileHeader.Header.Get("Content-Type")
	validTypes := map[string]bool{
		"image/jpeg": true,
		"image/jpg":  true,
		"image/png":  true,
		"image/gif":  true,
		"image/webp": true,
	}
	if !validTypes[strings.ToLower(contentType)] {
		http.Error(w, "Invalid file type. Please upload an image.", http.StatusBadRequest)
		return
	}

	database := db.ConnectDatabase()

	// Get current user
	var user model.User
	if err := database.First(&user, userID).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Delete old profile picture if exists
	if user.ProfilePicture != "" {
		oldPath := filepath.Join(".", user.ProfilePicture)
		if err := os.Remove(oldPath); err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: Could not delete old profile picture: %v", err)
		}
	}

	// Generate unique filename
	timestamp := time.Now().Unix()
	ext := filepath.Ext(fileHeader.Filename)
	safeFilename := fmt.Sprintf("user_%d_%d%s", userID, timestamp, ext)
	destPath := filepath.Join(ProfilePictureDir, safeFilename)

	// Create destination file
	destFile, err := os.Create(destPath)
	if err != nil {
		log.Printf("Error creating destination file: %v", err)
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
	defer destFile.Close()

	// Copy file
	if _, err := io.Copy(destFile, file); err != nil {
		log.Printf("Error saving file: %v", err)
		os.Remove(destPath)
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}

	// Update user record with relative path
	relativePath := strings.TrimPrefix(destPath, "./")
	user.ProfilePicture = relativePath

	if err := database.Save(&user).Error; err != nil {
		log.Printf("Error updating user: %v", err)
		os.Remove(destPath)
		http.Error(w, "Error updating profile", http.StatusInternalServerError)
		return
	}

	// Update session
	session.Values["profilePicture"] = relativePath
	if err := session.Save(r, w); err != nil {
		log.Printf("Warning: Could not update session: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(fmt.Sprintf(`{"success": true, "profile_picture": "/%s"}`, relativePath)))

	log.Printf("✅ Profile picture uploaded for user %d: %s", userID, safeFilename)
}

// DeleteProfilePicture deletes a user's profile picture
func DeleteProfilePicture(w http.ResponseWriter, r *http.Request) {
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

	var user model.User
	if err := database.First(&user, userID).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Delete profile picture file if exists
	if user.ProfilePicture != "" {
		filePath := filepath.Join(".", user.ProfilePicture)
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: Could not delete profile picture: %v", err)
		}
	}

	// Update user record
	user.ProfilePicture = ""
	if err := database.Save(&user).Error; err != nil {
		http.Error(w, "Error updating profile", http.StatusInternalServerError)
		return
	}

	// Update session
	delete(session.Values, "profilePicture")
	if err := session.Save(r, w); err != nil {
		log.Printf("Warning: Could not update session: %v", err)
	}

	// Generate initials
	firstName, _ := session.Values["firstName"].(string)
	lastName, _ := session.Values["lastName"].(string)
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

	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"success":  true,
		"initials": initials,
	}
	json.NewEncoder(w).Encode(response)

	log.Printf("✅ Profile picture deleted for user %d", userID)
}

