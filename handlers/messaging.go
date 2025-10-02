package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	"github.com/stefanhall2704/GoPhotography/db"
	"github.com/stefanhall2704/GoPhotography/model"
)

// GetBookingMessages retrieves all messages for a specific booking
func GetBookingMessages(w http.ResponseWriter, r *http.Request) {
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

	vars := mux.Vars(r)
	bookingType := vars["type"] // "minis" or "session"
	bookingID := vars["id"]

	database := db.ConnectDatabase()

	// Verify user has access to this booking
	if bookingType == "minis" {
		var booking model.BookMinis
		if err := database.First(&booking, bookingID).Error; err != nil {
			http.Error(w, "Booking not found", http.StatusNotFound)
			return
		}

		// Check if user is the booking owner or admin
		isAdmin, _ := session.Values["isAdmin"].(bool)
		if booking.UserID != userID && !isAdmin {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
	} else if bookingType == "session" {
		var booking model.BookSession
		if err := database.First(&booking, bookingID).Error; err != nil {
			http.Error(w, "Booking not found", http.StatusNotFound)
			return
		}

		isAdmin, _ := session.Values["isAdmin"].(bool)
		if booking.UserID != userID && !isAdmin {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
	} else {
		http.Error(w, "Invalid booking type", http.StatusBadRequest)
		return
	}

	// Get messages
	var messages []model.BookingMessage
	bookingIDUint, _ := strconv.ParseUint(bookingID, 10, 64)
	if err := database.Preload("User").
		Where("booking_id = ? AND booking_type = ?", bookingIDUint, bookingType).
		Order("created_at ASC").
		Find(&messages).Error; err != nil {
		http.Error(w, "Error fetching messages", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

// CreateBookingMessage creates a new message in a booking conversation
func CreateBookingMessage(w http.ResponseWriter, r *http.Request) {
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

	vars := mux.Vars(r)
	bookingType := vars["type"]
	bookingID := vars["id"]

	// Parse multipart form data (handles both regular form and FormData from JS)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		// Try regular form parsing as fallback
		if err := r.ParseForm(); err != nil {
			log.Printf("Error parsing form data: %v", err)
			http.Error(w, "Error parsing form data", http.StatusBadRequest)
			return
		}
	}

	message := r.Form.Get("message")
	if message == "" {
		log.Printf("❌ Empty message received")
		http.Error(w, "Message cannot be empty", http.StatusBadRequest)
		return
	}

	log.Printf("💬 Received message for booking %s/%s: %s", bookingType, bookingID, message)

	database := db.ConnectDatabase()

	// Verify user has access to this booking
	var bookingUserID uint
	if bookingType == "minis" {
		var booking model.BookMinis
		if err := database.First(&booking, bookingID).Error; err != nil {
			http.Error(w, "Booking not found", http.StatusNotFound)
			return
		}
		bookingUserID = booking.UserID
	} else if bookingType == "session" {
		var booking model.BookSession
		if err := database.First(&booking, bookingID).Error; err != nil {
			http.Error(w, "Booking not found", http.StatusNotFound)
			return
		}
		bookingUserID = booking.UserID
	} else {
		http.Error(w, "Invalid booking type", http.StatusBadRequest)
		return
	}

	isAdmin, _ := session.Values["isAdmin"].(bool)
	if bookingUserID != userID && !isAdmin {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	// Create message
	bookingIDUint, _ := strconv.ParseUint(bookingID, 10, 64)
	bookingMessage := model.BookingMessage{
		BookingID:   uint(bookingIDUint),
		BookingType: bookingType,
		UserID:      userID,
		Message:     message,
		IsAdmin:     isAdmin,
	}

	if err := database.Create(&bookingMessage).Error; err != nil {
		log.Printf("Error creating message: %v", err)
		http.Error(w, "Error creating message", http.StatusInternalServerError)
		return
	}

	// Create notification for the other party
	firstName, _ := session.Values["firstName"].(string)
	lastName, _ := session.Values["lastName"].(string)
	senderName := fmt.Sprintf("%s %s", firstName, lastName)

	if isAdmin {
		// Admin sent message, notify the booking user
		notifMessage := fmt.Sprintf("%s replied to your %s booking", senderName, bookingType)
		if err := CreateNotification(database, bookingUserID, notifMessage, "message", uint(bookingIDUint), bookingType); err != nil {
			log.Printf("Error creating notification: %v", err)
		}
	} else {
		// User sent message, notify admins
		notifMessage := fmt.Sprintf("%s sent a message about their %s booking", senderName, bookingType)
		if err := CreateAdminNotification(database, notifMessage, "message", uint(bookingIDUint), bookingType); err != nil {
			log.Printf("Error creating admin notification: %v", err)
		}
	}

	log.Printf("✅ Message created for %s booking %s by user %d", bookingType, bookingID, userID)

	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bookingMessage)
}

// GetBookingDetails retrieves full booking details including messages
func GetBookingDetails(w http.ResponseWriter, r *http.Request) {
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

	vars := mux.Vars(r)
	bookingType := vars["type"]
	bookingID := vars["id"]

	database := db.ConnectDatabase()

	var response map[string]interface{}

	if bookingType == "minis" {
		var booking model.BookMinis
		if err := database.Preload("User").Preload("Minis").First(&booking, bookingID).Error; err != nil {
			http.Error(w, "Booking not found", http.StatusNotFound)
			return
		}

		isAdmin, _ := session.Values["isAdmin"].(bool)
		if booking.UserID != userID && !isAdmin {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		// Get messages
		var messages []model.BookingMessage
		bookingIDUint, _ := strconv.ParseUint(bookingID, 10, 64)
		database.Preload("User").
			Where("booking_id = ? AND booking_type = ?", bookingIDUint, bookingType).
			Order("created_at ASC").
			Find(&messages)

		response = map[string]interface{}{
			"booking":  booking,
			"messages": messages,
			"type":     "minis",
		}
	} else if bookingType == "session" {
		var booking model.BookSession
		if err := database.Preload("User").Preload("Session").First(&booking, bookingID).Error; err != nil {
			http.Error(w, "Booking not found", http.StatusNotFound)
			return
		}

		isAdmin, _ := session.Values["isAdmin"].(bool)
		if booking.UserID != userID && !isAdmin {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		// Get messages
		var messages []model.BookingMessage
		bookingIDUint, _ := strconv.ParseUint(bookingID, 10, 64)
		database.Preload("User").
			Where("booking_id = ? AND booking_type = ?", bookingIDUint, bookingType).
			Order("created_at ASC").
			Find(&messages)

		response = map[string]interface{}{
			"booking":  booking,
			"messages": messages,
			"type":     "session",
		}
	} else {
		http.Error(w, "Invalid booking type", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

