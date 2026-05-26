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
	UploadDir     = "/app/uploads/session_photos"
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

		// Apply watermark — store watermarked copy alongside original
		mime := fileHeader.Header.Get("Content-Type")
		wmExt := ".jpg"
		wmFilename := fmt.Sprintf("%s_%d_%d%s_wm%s", bookingType, bookingID, timestamp+int64(uploadedCount), ext, wmExt)
		wmPath := filepath.Join(UploadDir, wmFilename)
		if err := applyWatermark(destPath, wmPath, mime); err != nil {
			log.Printf("Warning: could not apply watermark to %s: %v", fileHeader.Filename, err)
			wmPath = "" // fall back to serving original
		}

		// Create database entry
		photo := model.SessionPhoto{
			BookingID:       uint(bookingID),
			BookingType:     bookingType,
			FileName:        fileHeader.Filename,
			FilePath:        destPath,
			WatermarkedPath: wmPath,
			FileSize:        written,
			MimeType:        mime,
		}

		if err := database.Create(&photo).Error; err != nil {
			log.Printf("Error saving photo record: %v", err)
			os.Remove(destPath)
			if wmPath != "" {
				os.Remove(wmPath)
			}
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

	if _, err := os.Stat(photo.FilePath); os.IsNotExist(err) {
		log.Printf("❌ Original photo file not found: %s", photo.FilePath)
		http.Error(w, "Photo file not found on server", http.StatusNotFound)
		return
	}

	if isAdmin {
		// Admins always see the clean original
		w.Header().Set("Content-Type", photo.MimeType)
		w.Header().Set("Cache-Control", "public, max-age=86400")
		http.ServeFile(w, r, photo.FilePath)
		return
	}

	// Regular users always see a watermarked version — generate it on-demand if
	// the cached copy is missing (covers photos uploaded before this feature, or
	// where upload-time generation silently failed).
	wmPath := ensureWatermarked(database, &photo)
	if wmPath == "" {
		// Watermark generation failed — still block the original, return error
		log.Printf("❌ Could not produce watermarked photo %d, refusing to serve original", photo.ID)
		http.Error(w, "Photo temporarily unavailable", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeFile(w, r, wmPath)
	log.Printf("📸 Served watermarked photo %d: %s", photo.ID, photo.FileName)
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

	// Non-admin users may only download photos they marked as favorites
	if !isAdmin && !photo.IsFavorite {
		http.Error(w, "Photo must be marked as a favorite before downloading", http.StatusForbidden)
		return
	}

	// Set headers to trigger browser download
	w.Header().Set("Content-Type", photo.MimeType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", photo.FileName))
	http.ServeFile(w, r, photo.FilePath)
	log.Printf("✅ Downloaded photo: %s", photo.FileName)

	go func() {
		now := time.Now()
		photo.IsDownloaded = true
		photo.DownloadedAt = &now
		database.Save(&photo)
		if !isAdmin {
			deletePhotoFiles(photo.FilePath, photo.WatermarkedPath, photo.ID)
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
	filesToDelete := []struct{ orig, wm string }{}

	for _, photo := range photos {
		file, err := os.Open(photo.FilePath)
		if err != nil {
			log.Printf("Error opening file %s: %v", photo.FilePath, err)
			continue
		}

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

		go func(p model.SessionPhoto) {
			p.IsDownloaded = true
			p.DownloadedAt = &now
			database.Save(&p)
		}(photo)

		if !isAdmin {
			filesToDelete = append(filesToDelete, struct{ orig, wm string }{photo.FilePath, photo.WatermarkedPath})
		}
	}

	if !isAdmin {
		go func() {
			time.Sleep(5 * time.Second)
			for _, p := range filesToDelete {
				os.Remove(p.orig)
				if p.wm != "" {
					os.Remove(p.wm)
				}
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
	filesToDelete := []struct{ orig, wm string }{}

	for _, photo := range photos {
		file, err := os.Open(photo.FilePath)
		if err != nil {
			log.Printf("Error opening file %s: %v", photo.FilePath, err)
			continue
		}

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

		go func(p model.SessionPhoto) {
			p.IsDownloaded = true
			p.DownloadedAt = &now
			database.Save(&p)
		}(photo)

		if !isAdmin {
			filesToDelete = append(filesToDelete, struct{ orig, wm string }{photo.FilePath, photo.WatermarkedPath})
		}
	}

	if !isAdmin {
		go func() {
			time.Sleep(5 * time.Second)
			for _, p := range filesToDelete {
				os.Remove(p.orig)
				if p.wm != "" {
					os.Remove(p.wm)
				}
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
	time.Sleep(5 * time.Second)
	if err := os.Remove(filePath); err != nil {
		log.Printf("Warning: Could not delete photo file %s: %v", filePath, err)
	} else {
		log.Printf("✅ Deleted photo file: %s", filePath)
	}
}

// GalleryInfo returns photos plus limit/favorites metadata for a booking.
func GalleryInfo(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "Payment required to view photos", http.StatusPaymentRequired)
		return
	}

	var photos []model.SessionPhoto
	if err := database.Where("booking_id = ? AND booking_type = ?", bookingID, bookingType).Find(&photos).Error; err != nil {
		http.Error(w, "Error fetching photos", http.StatusInternalServerError)
		return
	}

	downloadLimit := getDownloadLimit(database, uint(bookingID), bookingType)

	favCount := 0
	for _, p := range photos {
		if p.IsFavorite {
			favCount++
		}
	}

	favoritesLocked := !isAdmin && areFavoritesLocked(database, uint(bookingID), bookingType)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"photos":           photos,
		"download_limit":   downloadLimit,
		"total_photos":     len(photos),
		"favorites_count":  favCount,
		"favorites_locked": favoritesLocked,
	})
}

// ToggleFavorite marks or unmarks a photo as a favorite.
func ToggleFavorite(w http.ResponseWriter, r *http.Request) {
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

	bookingUserID, _, err := getBookingInfo(database, photo.BookingID, photo.BookingType)
	if err != nil {
		http.Error(w, "Booking not found", http.StatusNotFound)
		return
	}

	if !isAdmin && bookingUserID != userID {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	// Count current favorites for this booking
	var currentFavCount int64
	database.Model(&model.SessionPhoto{}).
		Where("booking_id = ? AND booking_type = ? AND is_favorite = true", photo.BookingID, photo.BookingType).
		Count(&currentFavCount)

	// Check if favorites are locked (user already downloaded)
	if !isAdmin && areFavoritesLocked(database, photo.BookingID, photo.BookingType) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusLocked)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Your photo selections are locked. You have already downloaded your favorites.",
		})
		return
	}

	downloadLimit := getDownloadLimit(database, photo.BookingID, photo.BookingType)

	// 0 = no limit assigned yet — user cannot select favorites until admin sets one
	if !isAdmin && downloadLimit == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":          "Download limit not yet set",
			"download_limit": 0,
		})
		return
	}

	// Trying to add a new favorite when limit is already reached
	if !photo.IsFavorite && !isAdmin && int(currentFavCount) >= downloadLimit {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":           "Favorite limit reached",
			"download_limit":  downloadLimit,
			"favorites_count": currentFavCount,
		})
		return
	}

	photo.IsFavorite = !photo.IsFavorite
	if err := database.Save(&photo).Error; err != nil {
		http.Error(w, "Error updating photo", http.StatusInternalServerError)
		return
	}

	newFavCount := currentFavCount
	if photo.IsFavorite {
		newFavCount++
	} else {
		newFavCount--
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"is_favorite":     photo.IsFavorite,
		"favorites_count": newFavCount,
		"download_limit":  downloadLimit,
	})
}

// SetDownloadLimit allows admin to set how many photos a booking's user may download.
func SetDownloadLimit(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	isAdmin, _ := session.Values["isAdmin"].(bool)
	if !isAdmin {
		http.Error(w, "Unauthorized", http.StatusForbidden)
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

	var req struct {
		Limit int `json:"limit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Limit < 0 {
		http.Error(w, "Limit must be 0 or greater (0 = all photos)", http.StatusBadRequest)
		return
	}

	database := db.ConnectDatabase()

	var dbErr error
	if bookingType == "session" {
		dbErr = database.Model(&model.BookSession{}).Where("id = ?", bookingID).Update("download_limit", req.Limit).Error
	} else {
		dbErr = database.Model(&model.BookMinis{}).Where("id = ?", bookingID).Update("download_limit", req.Limit).Error
	}

	if dbErr != nil {
		http.Error(w, "Error updating limit", http.StatusInternalServerError)
		return
	}

	log.Printf("✅ Download limit for %s booking %d set to %d", bookingType, bookingID, req.Limit)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"limit":   req.Limit,
	})
}

// DownloadFavorites downloads all of the user's favorited photos as a zip.
func DownloadFavorites(w http.ResponseWriter, r *http.Request) {
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

	downloadLimit := getDownloadLimit(database, uint(bookingID), bookingType)
	if !isAdmin && downloadLimit == 0 {
		http.Error(w, "Downloads not yet available for this booking. Contact Hall's Photography.", http.StatusForbidden)
		return
	}

	// Fetch only favorited photos for the booking
	var photos []model.SessionPhoto
	query := database.Where("booking_id = ? AND booking_type = ?", bookingID, bookingType)
	if !isAdmin {
		query = query.Where("is_favorite = true")
	}
	if err := query.Find(&photos).Error; err != nil {
		http.Error(w, "Error fetching photos", http.StatusInternalServerError)
		return
	}

	if len(photos) == 0 {
		http.Error(w, "No favorited photos to download", http.StatusNotFound)
		return
	}

	// Lock favorites immediately — before streaming so even a partial download
	// prevents re-selection on a retry.
	if !isAdmin {
		lockFavorites(database, uint(bookingID), bookingType)
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=favorites_%s_%d.zip", bookingType, bookingID))

	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()

	now := time.Now()
	var pathsToDelete []struct{ orig, wm string }

	for _, photo := range photos {
		file, err := os.Open(photo.FilePath)
		if err != nil {
			log.Printf("Error opening file %s: %v", photo.FilePath, err)
			continue
		}

		fw, err := zipWriter.Create(photo.FileName)
		if err != nil {
			file.Close()
			continue
		}

		if _, err := io.Copy(fw, file); err != nil {
			file.Close()
			continue
		}
		file.Close()

		go func(p model.SessionPhoto) {
			p.IsDownloaded = true
			p.DownloadedAt = &now
			database.Save(&p)
		}(photo)

		if !isAdmin {
			pathsToDelete = append(pathsToDelete, struct{ orig, wm string }{photo.FilePath, photo.WatermarkedPath})
		}
	}

	if !isAdmin {
		go func() {
			time.Sleep(5 * time.Second)
			for _, p := range pathsToDelete {
				os.Remove(p.orig)
				if p.wm != "" {
					os.Remove(p.wm)
				}
			}
		}()
	}

	log.Printf("✅ Downloaded %d favorite photos as zip for %s booking %d", len(photos), bookingType, bookingID)
}

func areFavoritesLocked(database *gorm.DB, bookingID uint, bookingType string) bool {
	if bookingType == "session" {
		var b model.BookSession
		if err := database.Select("favorites_locked").First(&b, bookingID).Error; err != nil {
			return false
		}
		return b.FavoritesLocked
	}
	var b model.BookMinis
	if err := database.Select("favorites_locked").First(&b, bookingID).Error; err != nil {
		return false
	}
	return b.FavoritesLocked
}

func lockFavorites(database *gorm.DB, bookingID uint, bookingType string) {
	if bookingType == "session" {
		database.Model(&model.BookSession{}).Where("id = ?", bookingID).Update("favorites_locked", true)
	} else {
		database.Model(&model.BookMinis{}).Where("id = ?", bookingID).Update("favorites_locked", true)
	}
}

func getDownloadLimit(database *gorm.DB, bookingID uint, bookingType string) int {
	if bookingType == "session" {
		var b model.BookSession
		if err := database.Select("download_limit").First(&b, bookingID).Error; err != nil {
			return 0
		}
		return b.DownloadLimit
	}
	var b model.BookMinis
	if err := database.Select("download_limit").First(&b, bookingID).Error; err != nil {
		return 0
	}
	return b.DownloadLimit
}

// ensureWatermarked guarantees a watermarked copy exists for a photo.
// It returns the path to the watermarked file, generating it if missing.
// Returns "" only if generation fails — the caller must NOT serve the original.
func ensureWatermarked(database *gorm.DB, photo *model.SessionPhoto) string {
	// Fast path: cached watermarked file already exists on disk
	if photo.WatermarkedPath != "" {
		if _, err := os.Stat(photo.WatermarkedPath); err == nil {
			return photo.WatermarkedPath
		}
	}

	// Slow path: generate now (covers old photos and failed upload-time attempts)
	ext := filepath.Ext(photo.FilePath)
	wmPath := strings.TrimSuffix(photo.FilePath, ext) + "_wm.jpg"

	if err := applyWatermark(photo.FilePath, wmPath, photo.MimeType); err != nil {
		log.Printf("❌ Watermark generation failed for photo %d: %v", photo.ID, err)
		return ""
	}

	// Persist the path so future requests hit the fast path
	if err := database.Model(photo).Update("watermarked_path", wmPath).Error; err != nil {
		log.Printf("⚠️  Could not persist watermarked_path for photo %d: %v", photo.ID, err)
	}

	log.Printf("🖼️  Generated watermark on-demand for photo %d", photo.ID)
	return wmPath
}

func deletePhotoFiles(filePath, watermarkedPath string, photoID uint) {
	time.Sleep(5 * time.Second)
	if err := os.Remove(filePath); err != nil {
		log.Printf("Warning: Could not delete photo file %s: %v", filePath, err)
	}
	if watermarkedPath != "" {
		if err := os.Remove(watermarkedPath); err != nil {
			log.Printf("Warning: Could not delete watermarked file %s: %v", watermarkedPath, err)
		}
	}
}

