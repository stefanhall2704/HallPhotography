package handlers

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"gorm.io/gorm"

	"github.com/stefanhall2704/GoPhotography/db"
	"github.com/stefanhall2704/GoPhotography/model"
)

const (
	MaxUploadSize = 100 << 20 // 100 MB per file
	UploadDir     = "./uploads/session_photos"
)

// Ensure upload directory exists
func init() {
	if err := os.MkdirAll(UploadDir, 0755); err != nil {
		log.Printf("Warning: Could not create upload directory: %v", err)
	}
}

// UploadPhotos handles multiple photo uploads for a booking
func UploadPhotos(w http.ResponseWriter, r *http.Request) {
	// Check if user is admin
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	isAdmin, _ := session.Values["isAdmin"].(bool)
	if !isAdmin {
		http.Error(w, "Unauthorized: Admin access required", http.StatusForbidden)
		return
	}

	// Parse multipart form with 100MB limit per file
	if err := r.ParseMultipartForm(MaxUploadSize); err != nil {
		log.Printf("Error parsing multipart form: %v", err)
		http.Error(w, "File too large or form parsing error", http.StatusBadRequest)
		return
	}

	vars := mux.Vars(r)
	bookingType := vars["type"]
	bookingIDStr := vars["id"]

	bookingID, err := strconv.ParseUint(bookingIDStr, 10, 32)
	if err != nil {
		http.Error(w, "Invalid booking ID", http.StatusBadRequest)
		return
	}

	// Validate booking type
	if bookingType != "session" && bookingType != "minis" {
		http.Error(w, "Invalid booking type", http.StatusBadRequest)
		return
	}

	database := db.ConnectDatabase()

	// Verify booking exists and session date has passed
	if err := validateBookingForPhotoUpload(database, uint(bookingID), bookingType); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Process uploaded files
	files := r.MultipartForm.File["photos"]
	if len(files) == 0 {
		http.Error(w, "No photos uploaded", http.StatusBadRequest)
		return
	}

	var uploadedPhotos []model.SessionPhoto
	uploadedCount := 0

	for _, fileHeader := range files {
		// Validate file type
		if !isValidImageType(fileHeader.Header.Get("Content-Type")) {
			log.Printf("Skipping invalid file type: %s", fileHeader.Filename)
			continue
		}

		// Open uploaded file
		file, err := fileHeader.Open()
		if err != nil {
			log.Printf("Error opening uploaded file %s: %v", fileHeader.Filename, err)
			continue
		}
		defer file.Close()

		// Generate unique filename
		timestamp := time.Now().Unix()
		ext := filepath.Ext(fileHeader.Filename)
		safeFilename := fmt.Sprintf("%s_%d_%d%s", bookingType, bookingID, timestamp+int64(uploadedCount), ext)
		destPath := filepath.Join(UploadDir, safeFilename)

		// Create destination file
		destFile, err := os.Create(destPath)
		if err != nil {
			log.Printf("Error creating destination file: %v", err)
			continue
		}

		// Copy file
		written, err := io.Copy(destFile, file)
		destFile.Close()
		if err != nil {
			log.Printf("Error saving file: %v", err)
			os.Remove(destPath)
			continue
		}

		// Create database entry
		photo := model.SessionPhoto{
			BookingID:   uint(bookingID),
			BookingType: bookingType,
			FileName:    fileHeader.Filename,
			FilePath:    destPath,
			FileSize:    written,
			MimeType:    fileHeader.Header.Get("Content-Type"),
		}

		if err := database.Create(&photo).Error; err != nil {
			log.Printf("Error saving photo record: %v", err)
			os.Remove(destPath)
			continue
		}

		uploadedPhotos = append(uploadedPhotos, photo)
		uploadedCount++
	}

	if uploadedCount == 0 {
		http.Error(w, "No valid photos were uploaded", http.StatusBadRequest)
		return
	}

	// Check if this is the first time uploading photos
	wasAlreadyUploaded := checkIfPhotosAlreadyUploaded(database, uint(bookingID), bookingType)

	// Update booking to mark photos as uploaded
	if err := markPhotosUploaded(database, uint(bookingID), bookingType); err != nil {
		log.Printf("Warning: Could not update booking photos flag: %v", err)
	}

	// Notify user only if this is the first time uploading photos
	if !wasAlreadyUploaded {
		if err := notifyUserPhotosUploaded(database, uint(bookingID), bookingType); err != nil {
			log.Printf("Warning: Could not notify user: %v", err)
		}
		log.Printf("✅ Uploaded %d photos for %s booking %d (first upload)", uploadedCount, bookingType, bookingID)
	} else {
		log.Printf("✅ Added %d more photos for %s booking %d", uploadedCount, bookingType, bookingID)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"uploaded_count": uploadedCount,
		"photos":        uploadedPhotos,
		"is_additional": wasAlreadyUploaded,
	})
}

// GetBookingPhotos returns photos for a booking (checks payment status for users)
func GetBookingPhotos(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	userID, _ := session.Values["userID"].(uint)
	isAdmin, _ := session.Values["isAdmin"].(bool)

	vars := mux.Vars(r)
	bookingType := vars["type"]
	bookingIDStr := vars["id"]

	bookingID, err := strconv.ParseUint(bookingIDStr, 10, 32)
	if err != nil {
		http.Error(w, "Invalid booking ID", http.StatusBadRequest)
		return
	}

	database := db.ConnectDatabase()

	// Verify user owns the booking or is admin
	bookingUserID, hasPaid, err := getBookingInfo(database, uint(bookingID), bookingType)
	if err != nil {
		http.Error(w, "Booking not found", http.StatusNotFound)
		return
	}

	if !isAdmin && bookingUserID != userID {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	// Non-admin users must have paid to view photos
	if !isAdmin && !hasPaid {
		http.Error(w, "Payment required to view photos", http.StatusPaymentRequired)
		return
	}

	// Get photos
	var photos []model.SessionPhoto
	if err := database.Where("booking_id = ? AND booking_type = ?", bookingID, bookingType).Find(&photos).Error; err != nil {
		http.Error(w, "Error fetching photos", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(photos)
}

// ViewPhoto serves a photo for viewing (checks payment status for users)
func ViewPhoto(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	userID, _ := session.Values["userID"].(uint)
	isAdmin, _ := session.Values["isAdmin"].(bool)

	vars := mux.Vars(r)
	photoIDStr := vars["photoId"]

	photoID, err := strconv.ParseUint(photoIDStr, 10, 32)
	if err != nil {
		http.Error(w, "Invalid photo ID", http.StatusBadRequest)
		return
	}

	database := db.ConnectDatabase()

	var photo model.SessionPhoto
	if err := database.First(&photo, photoID).Error; err != nil {
		http.Error(w, "Photo not found", http.StatusNotFound)
		return
	}

	// Verify user owns the booking or is admin
	bookingUserID, hasPaid, err := getBookingInfo(database, photo.BookingID, photo.BookingType)
	if err != nil {
		http.Error(w, "Booking not found", http.StatusNotFound)
		return
	}

	if !isAdmin && bookingUserID != userID {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	if !isAdmin && !hasPaid {
		http.Error(w, "Payment required to view photos", http.StatusPaymentRequired)
		return
	}

	// Check if file exists
	if _, err := os.Stat(photo.FilePath); os.IsNotExist(err) {
		log.Printf("❌ Photo file not found: %s", photo.FilePath)
		http.Error(w, "Photo file not found on server", http.StatusNotFound)
		return
	}

	// Set content type for image display
	w.Header().Set("Content-Type", photo.MimeType)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	
	// Serve the file for viewing
	http.ServeFile(w, r, photo.FilePath)
	log.Printf("📸 Served photo: %s (type: %s)", photo.FileName, photo.MimeType)
}

// DownloadPhoto downloads a single photo
func DownloadPhoto(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	userID, _ := session.Values["userID"].(uint)
	isAdmin, _ := session.Values["isAdmin"].(bool)

	vars := mux.Vars(r)
	photoIDStr := vars["photoId"]

	photoID, err := strconv.ParseUint(photoIDStr, 10, 32)
	if err != nil {
		http.Error(w, "Invalid photo ID", http.StatusBadRequest)
		return
	}

	database := db.ConnectDatabase()

	var photo model.SessionPhoto
	if err := database.First(&photo, photoID).Error; err != nil {
		http.Error(w, "Photo not found", http.StatusNotFound)
		return
	}

	// Verify user owns the booking or is admin
	bookingUserID, hasPaid, err := getBookingInfo(database, photo.BookingID, photo.BookingType)
	if err != nil {
		http.Error(w, "Booking not found", http.StatusNotFound)
		return
	}

	if !isAdmin && bookingUserID != userID {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	if !isAdmin && !hasPaid {
		http.Error(w, "Payment required to download photos", http.StatusPaymentRequired)
		return
	}

	// Set headers to trigger browser download
	w.Header().Set("Content-Type", photo.MimeType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", photo.FileName))
	
	// Serve the file to the client's browser
	http.ServeFile(w, r, photo.FilePath)
	
	log.Printf("✅ Downloaded photo: %s (type: %s)", photo.FileName, photo.MimeType)

	// Mark as downloaded and delete in background
	go func() {
		now := time.Now()
		photo.IsDownloaded = true
		photo.DownloadedAt = &now
		database.Save(&photo)

		// Delete original file for non-admin users
		if !isAdmin {
			deletePhotoFile(photo.FilePath, photo.ID)
		}
	}()
}

// DownloadMultiplePhotos downloads selected photos as a zip file
func DownloadMultiplePhotos(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	userID, _ := session.Values["userID"].(uint)
	isAdmin, _ := session.Values["isAdmin"].(bool)

	var request struct {
		PhotoIDs []uint `json:"photo_ids"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if len(request.PhotoIDs) == 0 {
		http.Error(w, "No photos selected", http.StatusBadRequest)
		return
	}

	database := db.ConnectDatabase()

	var photos []model.SessionPhoto
	if err := database.Where("id IN ?", request.PhotoIDs).Find(&photos).Error; err != nil {
		http.Error(w, "Error fetching photos", http.StatusInternalServerError)
		return
	}

	// Verify all photos belong to same booking and user has access
	if len(photos) == 0 {
		http.Error(w, "No photos found", http.StatusNotFound)
		return
	}

	firstPhoto := photos[0]
	bookingUserID, hasPaid, err := getBookingInfo(database, firstPhoto.BookingID, firstPhoto.BookingType)
	if err != nil {
		http.Error(w, "Booking not found", http.StatusNotFound)
		return
	}

	if !isAdmin && bookingUserID != userID {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	if !isAdmin && !hasPaid {
		http.Error(w, "Payment required to download photos", http.StatusPaymentRequired)
		return
	}

	// Set headers for zip download
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=photos_%s_%d.zip", firstPhoto.BookingType, firstPhoto.BookingID))

	// Create zip writer
	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()

	now := time.Now()
	filesToDelete := []string{}

	for _, photo := range photos {
		// Open photo file
		file, err := os.Open(photo.FilePath)
		if err != nil {
			log.Printf("Error opening file %s: %v", photo.FilePath, err)
			continue
		}

		// Add file to zip
		fileWriter, err := zipWriter.Create(photo.FileName)
		if err != nil {
			file.Close()
			log.Printf("Error creating zip entry: %v", err)
			continue
		}

		if _, err := io.Copy(fileWriter, file); err != nil {
			file.Close()
			log.Printf("Error copying file to zip: %v", err)
			continue
		}

		file.Close()

		// Mark as downloaded in background
		go func(p model.SessionPhoto) {
			p.IsDownloaded = true
			p.DownloadedAt = &now
			database.Save(&p)
		}(photo)

		if !isAdmin {
			filesToDelete = append(filesToDelete, photo.FilePath)
		}
	}

	// Delete original files after download for non-admin users
	if !isAdmin {
		go func() {
			for _, filePath := range filesToDelete {
				deletePhotoFile(filePath, 0)
			}
		}()
	}

	log.Printf("✅ Downloaded %d photos as zip", len(photos))
}

// DownloadAllPhotos downloads all photos for a booking as a zip file
func DownloadAllPhotos(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	userID, _ := session.Values["userID"].(uint)
	isAdmin, _ := session.Values["isAdmin"].(bool)

	vars := mux.Vars(r)
	bookingType := vars["type"]
	bookingIDStr := vars["id"]

	bookingID, err := strconv.ParseUint(bookingIDStr, 10, 32)
	if err != nil {
		http.Error(w, "Invalid booking ID", http.StatusBadRequest)
		return
	}

	database := db.ConnectDatabase()

	// Verify user owns the booking or is admin
	bookingUserID, hasPaid, err := getBookingInfo(database, uint(bookingID), bookingType)
	if err != nil {
		http.Error(w, "Booking not found", http.StatusNotFound)
		return
	}

	if !isAdmin && bookingUserID != userID {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	if !isAdmin && !hasPaid {
		http.Error(w, "Payment required to download photos", http.StatusPaymentRequired)
		return
	}

	// Get all photos
	var photos []model.SessionPhoto
	if err := database.Where("booking_id = ? AND booking_type = ?", bookingID, bookingType).Find(&photos).Error; err != nil {
		http.Error(w, "Error fetching photos", http.StatusInternalServerError)
		return
	}

	if len(photos) == 0 {
		http.Error(w, "No photos found", http.StatusNotFound)
		return
	}

	// Set headers for zip download
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=photos_%s_%d_all.zip", bookingType, bookingID))

	// Create zip writer
	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()

	now := time.Now()
	filesToDelete := []string{}

	for _, photo := range photos {
		// Open photo file
		file, err := os.Open(photo.FilePath)
		if err != nil {
			log.Printf("Error opening file %s: %v", photo.FilePath, err)
			continue
		}

		// Add file to zip
		fileWriter, err := zipWriter.Create(photo.FileName)
		if err != nil {
			file.Close()
			log.Printf("Error creating zip entry: %v", err)
			continue
		}

		if _, err := io.Copy(fileWriter, file); err != nil {
			file.Close()
			log.Printf("Error copying file to zip: %v", err)
			continue
		}

		file.Close()

		// Mark as downloaded in background
		go func(p model.SessionPhoto) {
			p.IsDownloaded = true
			p.DownloadedAt = &now
			database.Save(&p)
		}(photo)

		if !isAdmin {
			filesToDelete = append(filesToDelete, photo.FilePath)
		}
	}

	// Delete original files after download for non-admin users
	if !isAdmin {
		go func() {
			for _, filePath := range filesToDelete {
				deletePhotoFile(filePath, 0)
			}
		}()
	}

	log.Printf("✅ Downloaded all %d photos as zip", len(photos))
}

// GetBookingsWithoutPhotos returns bookings that need photos uploaded (admin todo list)
func GetBookingsWithoutPhotos(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	isAdmin, _ := session.Values["isAdmin"].(bool)
	if !isAdmin {
		http.Error(w, "Unauthorized: Admin access required", http.StatusForbidden)
		return
	}

	database := db.ConnectDatabase()

	// Get confirmed sessions with approved pricing that don't have photos uploaded
	var sessions []struct {
		model.BookSession
		SessionDate time.Time
		UserName    string
	}

	database.Table("book_sessions").
		Select("book_sessions.*, session_days.start as session_date, users.first_name || ' ' || users.last_name as user_name").
		Joins("JOIN session_days ON book_sessions.session_id = session_days.session_id").
		Joins("JOIN users ON book_sessions.user_id = users.id").
		Where("book_sessions.status = ? AND book_sessions.photos_uploaded = ? AND book_sessions.price_approval_status = ?", 
			"confirmed", false, "approved").
		Scan(&sessions)

	// Get confirmed minis with approved pricing that don't have photos uploaded
	var minis []struct {
		model.BookMinis
		MinisDate time.Time
		UserName  string
	}

	database.Table("book_minis").
		Select("book_minis.*, minis_days.start as minis_date, users.first_name || ' ' || users.last_name as user_name").
		Joins("JOIN minis_days ON book_minis.minis_id = minis_days.minis_id").
		Joins("JOIN users ON book_minis.user_id = users.id").
		Where("book_minis.status = ? AND book_minis.photos_uploaded = ? AND book_minis.price_approval_status = ?", 
			"confirmed", false, "approved").
		Scan(&minis)

	response := map[string]interface{}{
		"sessions": sessions,
		"minis":    minis,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// PhotoUploadView serves the photo upload page for admin
func PhotoUploadView(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	isAdmin, _ := session.Values["isAdmin"].(bool)
	if !isAdmin {
		http.Error(w, "Unauthorized: Admin access required", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	bookingType := vars["type"]
	bookingID := vars["id"]

	data := map[string]interface{}{
		"BookingType": bookingType,
		"BookingID":   bookingID,
		"IsAdmin":     isAdmin,
	}

	t, err := template.ParseFiles("templates/admin/upload_photos.html")
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

// PhotoGalleryView serves the photo gallery page for users
func PhotoGalleryView(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	userID, _ := session.Values["userID"].(uint)
	isAdmin, _ := session.Values["isAdmin"].(bool)

	vars := mux.Vars(r)
	bookingType := vars["type"]
	bookingID := vars["id"]

	data := map[string]interface{}{
		"BookingType": bookingType,
		"BookingID":   bookingID,
		"UserID":      userID,
		"IsAdmin":     isAdmin,
	}

	t, err := template.ParseFiles("templates/user/photo_gallery.html")
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

// AdminTodoView serves the admin todo page showing bookings without photos
func AdminTodoView(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	isAdmin, _ := session.Values["isAdmin"].(bool)
	if !isAdmin {
		http.Error(w, "Unauthorized: Admin access required", http.StatusForbidden)
		return
	}

	userID, _ := session.Values["userID"].(uint)
	email, _ := session.Values["email"].(string)
	firstName, _ := session.Values["firstName"].(string)
	lastName, _ := session.Values["lastName"].(string)

	var fullName string
	if firstName != "" && lastName != "" {
		fullName = firstName + " " + lastName
	}

	data := map[string]interface{}{
		"UserID":        userID,
		"Email":         email,
		"Name":          fullName,
		"Authenticated": userID != 0,
		"IsAdmin":       isAdmin,
	}

	t, err := template.ParseFiles("templates/admin/photo_todo.html")
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

// Helper functions

func isValidImageType(mimeType string) bool {
	validTypes := []string{
		"image/jpeg",
		"image/jpg",
		"image/png",
		"image/gif",
		"image/webp",
		"image/tiff",
		"image/bmp",
		"image/heic",
		"image/heif",
	}
	
	mimeType = strings.ToLower(mimeType)
	for _, valid := range validTypes {
		if mimeType == valid {
			return true
		}
	}
	return false
}

func validateBookingForPhotoUpload(db *gorm.DB, bookingID uint, bookingType string) error {
	if bookingType == "session" {
		var booking model.BookSession

		if err := db.First(&booking, bookingID).Error; err != nil {
			return fmt.Errorf("booking not found")
		}

		if booking.Status != "confirmed" {
			return fmt.Errorf("booking must be confirmed before uploading photos")
		}

		if booking.PriceApprovalStatus != "approved" {
			return fmt.Errorf("price must be approved before uploading photos")
		}
	} else {
		var booking model.BookMinis

		if err := db.First(&booking, bookingID).Error; err != nil {
			return fmt.Errorf("booking not found")
		}

		if booking.Status != "confirmed" {
			return fmt.Errorf("booking must be confirmed before uploading photos")
		}

		if booking.PriceApprovalStatus != "approved" {
			return fmt.Errorf("price must be approved before uploading photos")
		}
	}

	return nil
}

func checkIfPhotosAlreadyUploaded(db *gorm.DB, bookingID uint, bookingType string) bool {
	if bookingType == "session" {
		var booking model.BookSession
		if err := db.Select("photos_uploaded").First(&booking, bookingID).Error; err != nil {
			return false
		}
		return booking.PhotosUploaded
	}
	var booking model.BookMinis
	if err := db.Select("photos_uploaded").First(&booking, bookingID).Error; err != nil {
		return false
	}
	return booking.PhotosUploaded
}

func markPhotosUploaded(db *gorm.DB, bookingID uint, bookingType string) error {
	if bookingType == "session" {
		return db.Model(&model.BookSession{}).Where("id = ?", bookingID).Update("photos_uploaded", true).Error
	}
	return db.Model(&model.BookMinis{}).Where("id = ?", bookingID).Update("photos_uploaded", true).Error
}

func getBookingInfo(db *gorm.DB, bookingID uint, bookingType string) (userID uint, hasPaid bool, err error) {
	if bookingType == "session" {
		var booking model.BookSession
		if err := db.First(&booking, bookingID).Error; err != nil {
			return 0, false, err
		}
		return booking.UserID, booking.HasPaid, nil
	}

	var booking model.BookMinis
	if err := db.First(&booking, bookingID).Error; err != nil {
		return 0, false, err
	}
	return booking.UserID, booking.HasPaid, nil
}

func notifyUserPhotosUploaded(db *gorm.DB, bookingID uint, bookingType string) error {
	userID, _, err := getBookingInfo(db, bookingID, bookingType)
	if err != nil {
		return err
	}

	notification := model.Notification{
		UserID:      userID,
		Message:     fmt.Sprintf("Photos have been uploaded for your %s booking! You can view them once payment is confirmed.", bookingType),
		Type:        "photo_upload",
		RelatedID:   bookingID,
		RelatedType: bookingType,
		IsRead:      false,
	}

	return db.Create(&notification).Error
}

func deletePhotoFile(filePath string, photoID uint) {
	time.Sleep(5 * time.Second) // Wait a bit to ensure download completes
	if err := os.Remove(filePath); err != nil {
		log.Printf("Warning: Could not delete photo file %s: %v", filePath, err)
	} else {
		log.Printf("✅ Deleted photo file: %s", filePath)
	}
}

