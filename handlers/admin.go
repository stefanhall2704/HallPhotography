package handlers

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"

	"github.com/stefanhall2704/GoPhotography/db"
	"github.com/stefanhall2704/GoPhotography/model"
)

// GetAllBookings retrieves all bookings (admin only)
func GetAllBookings(w http.ResponseWriter, r *http.Request) {
	database := db.ConnectDatabase()
	
	// Get all minis bookings
	var minisBookings []model.BookMinis
	if err := database.Preload("User").Preload("Minis").Find(&minisBookings).Error; err != nil {
		http.Error(w, "Error fetching minis bookings", http.StatusInternalServerError)
		return
	}

	// Get all regular session bookings
	var sessionBookings []model.BookSession
	if err := database.Preload("User").Preload("Session").Find(&sessionBookings).Error; err != nil {
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

// UpdateBookingStatus updates the status of a booking (admin or booking owner)
func UpdateBookingStatus(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	currentUserID, ok := session.Values["userID"].(uint)
	if !ok {
		http.Error(w, "User ID not found in session", http.StatusUnauthorized)
		return
	}

	isAdmin, _ := session.Values["isAdmin"].(bool)

	vars := mux.Vars(r)
	bookingType := vars["type"] // "minis" or "session"
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

	status := r.Form.Get("status")
	proposedTimeSlot := r.Form.Get("proposed_time_slot")
	proposedPriceStr := r.Form.Get("proposed_price")
	// message := r.Form.Get("message") // Optional message

	log.Printf("📝 User %d updating booking %s/%s: status=%s, proposed=%s, price=%s", currentUserID, bookingType, bookingID, status, proposedTimeSlot, proposedPriceStr)

	if status == "" {
		log.Printf("❌ Missing status field")
		http.Error(w, "Missing status", http.StatusBadRequest)
		return
	}

	database := db.ConnectDatabase()

	if bookingType == "minis" {
		var booking model.BookMinis
		if err := database.Preload("User").Preload("Minis").First(&booking, bookingID).Error; err != nil {
			http.Error(w, "Booking not found", http.StatusNotFound)
			return
		}

		// Check authorization: must be admin OR the booking owner
		if !isAdmin && booking.UserID != currentUserID {
			log.Printf("❌ Access denied: user %d tried to update booking owned by user %d", currentUserID, booking.UserID)
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		// Special handling for mini session confirmations by admin (photographer)
		if isAdmin && status == "confirmed" {
			// Photographer must set a price when confirming
			if proposedPriceStr == "" {
				log.Printf("❌ Admin tried to confirm mini session without setting a price")
				http.Error(w, "Price is required when confirming a mini session", http.StatusBadRequest)
				return
			}

			proposedPrice, err := strconv.ParseFloat(proposedPriceStr, 64)
			if err != nil || proposedPrice <= 0 {
				log.Printf("❌ Invalid price format: %s", proposedPriceStr)
				http.Error(w, "Invalid price format. Price must be a positive number", http.StatusBadRequest)
				return
			}

			// Set status to awaiting payment approval and store the proposed price
			booking.Status = "awaiting_price_approval"
			booking.ProposedPrice = proposedPrice
			booking.PriceApprovalStatus = "pending"
			
			if proposedTimeSlot != "" {
				booking.ProposedTimeSlot = proposedTimeSlot
			}

			if err := database.Save(&booking).Error; err != nil {
				http.Error(w, "Error updating booking", http.StatusInternalServerError)
				return
			}

			// Notify user about price approval request
			var message string
			if proposedTimeSlot != "" {
				message = fmt.Sprintf("Your mini session has been approved! The photographer has set the price at $%.2f for %s (updated time). Please review and approve the price.", proposedPrice, proposedTimeSlot)
			} else {
				message = fmt.Sprintf("Your mini session has been approved! The photographer has set the price at $%.2f for %s. Please review and approve the price.", proposedPrice, booking.TimeSlot)
			}

			if err := CreateNotification(database, booking.UserID, message, "price_approval", booking.ID, "minis"); err != nil {
				log.Printf("Error creating notification: %v", err)
			}

			log.Printf("✅ Mini session booking %d updated - awaiting user price approval: $%.2f", booking.ID, proposedPrice)

		} else {
			// Regular status updates (non-confirmation or by user)
			booking.Status = status
			if proposedTimeSlot != "" {
				booking.ProposedTimeSlot = proposedTimeSlot
			}

			if err := database.Save(&booking).Error; err != nil {
				http.Error(w, "Error updating booking", http.StatusInternalServerError)
				return
			}

			// Create notification for user (use "minis" for routing)
			var message string
			if status == "cancelled" {
				message = "Your mini session booking has been cancelled"
			} else if proposedTimeSlot != "" {
				message = fmt.Sprintf("The photographer proposed a new time for your mini session: %s", proposedTimeSlot)
			} else {
				message = fmt.Sprintf("Your mini session booking status: %s", status)
			}

			if err := CreateNotification(database, booking.UserID, message, "update", booking.ID, "minis"); err != nil {
				log.Printf("Error creating notification: %v", err)
			}
		}

		// If status update, add it to the conversation
		if status != "" {
			bookingMessage := model.BookingMessage{
				BookingID:   booking.ID,
				BookingType: "minis",
				UserID:      currentUserID,
				Message:     fmt.Sprintf("Status updated to: %s", status),
				IsAdmin:     isAdmin,
			}
			database.Create(&bookingMessage)
		}

	} else if bookingType == "session" {
		var booking model.BookSession
		if err := database.Preload("User").Preload("Session").First(&booking, bookingID).Error; err != nil {
			http.Error(w, "Booking not found", http.StatusNotFound)
			return
		}

		// Check authorization: must be admin OR the booking owner
		if !isAdmin && booking.UserID != currentUserID {
			log.Printf("❌ Access denied: user %d tried to update booking owned by user %d", currentUserID, booking.UserID)
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		// Special handling for session confirmations by admin (photographer)
		if isAdmin && status == "confirmed" {
			// Photographer must set a price when confirming
			if proposedPriceStr == "" {
				log.Printf("❌ Admin tried to confirm session without setting a price")
				http.Error(w, "Price is required when confirming a photography session", http.StatusBadRequest)
				return
			}

			proposedPrice, err := strconv.ParseFloat(proposedPriceStr, 64)
			if err != nil || proposedPrice <= 0 {
				log.Printf("❌ Invalid price format: %s", proposedPriceStr)
				http.Error(w, "Invalid price format. Price must be a positive number", http.StatusBadRequest)
				return
			}

			// Set status to awaiting price approval and store the proposed price
			booking.Status = "awaiting_price_approval"
			booking.ProposedPrice = proposedPrice
			booking.PriceApprovalStatus = "pending"
			
			if proposedTimeSlot != "" {
				booking.ProposedTimeSlot = proposedTimeSlot
			}

			if err := database.Save(&booking).Error; err != nil {
				http.Error(w, "Error updating booking", http.StatusInternalServerError)
				return
			}

			// Notify user about price approval request
			var message string
			if proposedTimeSlot != "" {
				message = fmt.Sprintf("Your photography session has been approved! The photographer has set the price at $%.2f for %s (updated time). Please review and approve the price.", proposedPrice, proposedTimeSlot)
			} else {
				message = fmt.Sprintf("Your photography session has been approved! The photographer has set the price at $%.2f for %s. Please review and approve the price.", proposedPrice, booking.TimeSlot)
			}

			if err := CreateNotification(database, booking.UserID, message, "price_approval", booking.ID, "session"); err != nil {
				log.Printf("Error creating notification: %v", err)
			}

			log.Printf("✅ Session booking %d updated - awaiting user price approval: $%.2f", booking.ID, proposedPrice)

		} else {
			// Regular status updates (non-confirmation or by user)
			booking.Status = status
			if proposedTimeSlot != "" {
				booking.ProposedTimeSlot = proposedTimeSlot
			}

			if err := database.Save(&booking).Error; err != nil {
				http.Error(w, "Error updating booking", http.StatusInternalServerError)
				return
			}

			// Create notification for user (use "session" for routing)
			var message string
			if status == "cancelled" {
				message = "Your photography session booking has been cancelled"
			} else if proposedTimeSlot != "" {
				message = fmt.Sprintf("The photographer proposed a new time for your session: %s", proposedTimeSlot)
			} else {
				message = fmt.Sprintf("Your photography session booking status: %s", status)
			}

			if err := CreateNotification(database, booking.UserID, message, "update", booking.ID, "session"); err != nil {
				log.Printf("Error creating notification: %v", err)
			}
		}

		// If user left a message, add it to the conversation
		if status != "" {
			bookingMessage := model.BookingMessage{
				BookingID:   booking.ID,
				BookingType: "session",
				UserID:      currentUserID,
				Message:     fmt.Sprintf("Status updated to: %s", status),
				IsAdmin:     isAdmin,
			}
			database.Create(&bookingMessage)
		}
	} else {
		log.Printf("❌ Invalid booking type: %s", bookingType)
		http.Error(w, "Invalid booking type", http.StatusBadRequest)
		return
	}

	log.Printf("✅ Successfully updated booking %s/%s", bookingType, bookingID)
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Booking updated successfully"})
}

// UpdateSessionPrice updates the price of a regular session (admin only)
func UpdateSessionPrice(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["id"]

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form data", http.StatusBadRequest)
		return
	}

	priceStr := r.Form.Get("price")
	if priceStr == "" {
		http.Error(w, "Missing price", http.StatusBadRequest)
		return
	}

	price, err := strconv.ParseFloat(priceStr, 64)
	if err != nil {
		http.Error(w, "Invalid price format", http.StatusBadRequest)
		return
	}

	database := db.ConnectDatabase()

	var session model.Session
	if err := database.First(&session, sessionID).Error; err != nil {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	session.Price = price
	if err := database.Save(&session).Error; err != nil {
		http.Error(w, "Error updating session", http.StatusInternalServerError)
		return
	}

	// Notify all users who booked this session
	var bookings []model.BookSession
	if err := database.Where("session_id = ?", sessionID).Find(&bookings).Error; err == nil {
		for _, booking := range bookings {
			message := fmt.Sprintf("The price for your booked session has been set to $%.2f", price)
			if err := CreateNotification(database, booking.UserID, message, "update", booking.ID, "session"); err != nil {
				log.Printf("Error creating notification for user %d: %v", booking.UserID, err)
			}
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Price updated successfully"})
}

// ToggleUserAdmin toggles admin status for a user (super admin only - can be added later)
func ToggleUserAdmin(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	database := db.ConnectDatabase()

	var user model.User
	if err := database.First(&user, userID).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	user.IsAdmin = !user.IsAdmin
	if err := database.Save(&user).Error; err != nil {
		http.Error(w, "Error updating user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"isAdmin": user.IsAdmin,
	})
}

// GetPendingBookings retrieves all pending bookings (admin only)
func GetPendingBookings(w http.ResponseWriter, r *http.Request) {
	database := db.ConnectDatabase()
	
	// Get pending minis bookings
	var minisBookings []model.BookMinis
	if err := database.Preload("User").Preload("Minis").Where("status = ?", "pending").Find(&minisBookings).Error; err != nil {
		http.Error(w, "Error fetching minis bookings", http.StatusInternalServerError)
		return
	}

	// Get pending regular session bookings
	var sessionBookings []model.BookSession
	if err := database.Preload("User").Preload("Session").Where("status = ?", "pending").Find(&sessionBookings).Error; err != nil {
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

// GetAllSessionsForAdmin retrieves all sessions with comprehensive status (admin only)
func GetAllSessionsForAdmin(w http.ResponseWriter, r *http.Request) {
	database := db.ConnectDatabase()
	
	// Get all regular session bookings with details
	var sessions []struct {
		model.BookSession
		SessionDate time.Time
		UserName    string
		SessionName string
	}

	database.Table("book_sessions").
		Select("book_sessions.*, session_days.start as session_date, users.first_name || ' ' || users.last_name as user_name, sessions.name as session_name").
		Joins("JOIN session_days ON book_sessions.session_id = session_days.session_id").
		Joins("JOIN users ON book_sessions.user_id = users.id").
		Joins("JOIN sessions ON book_sessions.session_id = sessions.id").
		Order("session_days.start DESC").
		Scan(&sessions)

	// Get all minis bookings with details
	var minis []struct {
		model.BookMinis
		MinisDate time.Time
		UserName  string
		MinisName string
	}

	database.Table("book_minis").
		Select("book_minis.*, minis_days.start as minis_date, users.first_name || ' ' || users.last_name as user_name, minis.name as minis_name").
		Joins("JOIN minis_days ON book_minis.minis_id = minis_days.minis_id").
		Joins("JOIN users ON book_minis.user_id = users.id").
		Joins("JOIN minis ON book_minis.minis_id = minis.id").
		Order("minis_days.start DESC").
		Scan(&minis)

	response := map[string]interface{}{
		"sessions": sessions,
		"minis":    minis,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// AdminDashboardView serves the admin dashboard page
func AdminDashboardView(w http.ResponseWriter, r *http.Request) {
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

	t, err := template.ParseFiles("templates/admin/dashboard.html")
	if err != nil {
		log.Printf("Error parsing template: %v", err)
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}

	if err := t.Execute(w, nil); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Error rendering page", http.StatusInternalServerError)
	}
}

// ApprovePriceForSession allows users to approve or decline the photographer's proposed price
func ApprovePriceForSession(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	currentUserID, ok := session.Values["userID"].(uint)
	if !ok {
		http.Error(w, "User ID not found in session", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	bookingID := vars["id"]

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		log.Printf("Error parsing multipart form data: %v", err)
		http.Error(w, "Error parsing form data", http.StatusBadRequest)
		return
	}

	approvalStatus := r.Form.Get("approval_status") // "approved" or "declined"
	log.Printf("📝 Received price approval request: booking_id=%s, approval_status=%s, user_id=%d", bookingID, approvalStatus, currentUserID)

	if approvalStatus != "approved" && approvalStatus != "declined" {
		http.Error(w, "Invalid approval status. Must be 'approved' or 'declined'", http.StatusBadRequest)
		return
	}

	database := db.ConnectDatabase()

	var booking model.BookSession
	if err := database.Preload("User").Preload("Session").First(&booking, bookingID).Error; err != nil {
		http.Error(w, "Booking not found", http.StatusNotFound)
		return
	}

	// Verify this booking belongs to the current user
	if booking.UserID != currentUserID {
		log.Printf("❌ Access denied: user %d tried to approve price for booking owned by user %d", currentUserID, booking.UserID)
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	// Verify booking is in the correct state
	if booking.Status != "awaiting_price_approval" {
		log.Printf("❌ Booking %d is not awaiting price approval (current status: %s)", booking.ID, booking.Status)
		http.Error(w, "This booking is not awaiting price approval", http.StatusBadRequest)
		return
	}

	// Update the booking based on approval
	if approvalStatus == "approved" {
		booking.PriceApprovalStatus = "approved"
		booking.Status = "confirmed"
		
		// Update the session price as well
		if err := database.Model(&model.Session{}).Where("id = ?", booking.SessionID).Update("price", booking.ProposedPrice).Error; err != nil {
			log.Printf("Error updating session price: %v", err)
		}

		log.Printf("✅ User %d approved price $%.2f for booking %d", currentUserID, booking.ProposedPrice, booking.ID)

		// Notify admin
		adminMessage := fmt.Sprintf("User %s %s has approved the price of $%.2f for their photography session", 
			booking.User.FirstName, booking.User.LastName, booking.ProposedPrice)
		if err := CreateAdminNotification(database, adminMessage, "price_approved", booking.ID, "session"); err != nil {
			log.Printf("Error creating admin notification: %v", err)
		}

		// Notify user
		userMessage := fmt.Sprintf("Thank you! Your photography session is now confirmed for %s at $%.2f", 
			booking.TimeSlot, booking.ProposedPrice)
		if err := CreateNotification(database, booking.UserID, userMessage, "confirmed", booking.ID, "session"); err != nil {
			log.Printf("Error creating user notification: %v", err)
		}

	} else { // declined
		booking.PriceApprovalStatus = "declined"
		booking.Status = "pending" // Return to pending status
		
		log.Printf("❌ User %d declined price $%.2f for booking %d", currentUserID, booking.ProposedPrice, booking.ID)

		// Notify admin
		adminMessage := fmt.Sprintf("User %s %s has declined the proposed price of $%.2f for their photography session. Please review.", 
			booking.User.FirstName, booking.User.LastName, booking.ProposedPrice)
		if err := CreateAdminNotification(database, adminMessage, "price_declined", booking.ID, "session"); err != nil {
			log.Printf("Error creating admin notification: %v", err)
		}

		// Notify user
		userMessage := "You have declined the proposed price. The photographer will review your booking and may propose a different price."
		if err := CreateNotification(database, booking.UserID, userMessage, "price_declined", booking.ID, "session"); err != nil {
			log.Printf("Error creating user notification: %v", err)
		}
	}

	if err := database.Save(&booking).Error; err != nil {
		http.Error(w, "Error updating booking", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Price %s successfully", approvalStatus),
		"booking": booking,
	})
}

// ApprovePriceForMinis allows users to approve or decline the photographer's proposed price for minis
func ApprovePriceForMinis(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	currentUserID, ok := session.Values["userID"].(uint)
	if !ok {
		http.Error(w, "User ID not found in session", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	bookingID := vars["id"]

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		log.Printf("Error parsing multipart form data: %v", err)
		http.Error(w, "Error parsing form data", http.StatusBadRequest)
		return
	}

	approvalStatus := r.Form.Get("approval_status") // "approved" or "declined"
	log.Printf("📝 Received price approval request for minis: booking_id=%s, approval_status=%s, user_id=%d", bookingID, approvalStatus, currentUserID)

	if approvalStatus != "approved" && approvalStatus != "declined" {
		http.Error(w, "Invalid approval status. Must be 'approved' or 'declined'", http.StatusBadRequest)
		return
	}

	database := db.ConnectDatabase()

	var booking model.BookMinis
	if err := database.Preload("User").Preload("Minis").First(&booking, bookingID).Error; err != nil {
		http.Error(w, "Booking not found", http.StatusNotFound)
		return
	}

	// Verify this booking belongs to the current user
	if booking.UserID != currentUserID {
		log.Printf("❌ Access denied: user %d tried to approve price for booking owned by user %d", currentUserID, booking.UserID)
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	// Verify booking is in the correct state
	if booking.Status != "awaiting_price_approval" {
		http.Error(w, "This booking is not awaiting price approval", http.StatusBadRequest)
		return
	}

	// Update the booking based on approval
	if approvalStatus == "approved" {
		booking.PriceApprovalStatus = "approved"
		booking.Status = "confirmed"

		log.Printf("✅ User %d approved price $%.2f for minis booking %d", currentUserID, booking.ProposedPrice, booking.ID)

		// Notify admin
		adminMessage := fmt.Sprintf("User %s %s has approved the price of $%.2f for their mini session", 
			booking.User.FirstName, booking.User.LastName, booking.ProposedPrice)
		if err := CreateAdminNotification(database, adminMessage, "price_approved", booking.ID, "minis"); err != nil {
			log.Printf("Error creating admin notification: %v", err)
		}

		// Notify user
		userMessage := fmt.Sprintf("Thank you! Your mini session is now confirmed for %s at $%.2f", 
			booking.TimeSlot, booking.ProposedPrice)
		if err := CreateNotification(database, booking.UserID, userMessage, "confirmed", booking.ID, "minis"); err != nil {
			log.Printf("Error creating user notification: %v", err)
		}

	} else { // declined
		booking.PriceApprovalStatus = "declined"
		booking.Status = "pending" // Return to pending status
		
		log.Printf("❌ User %d declined price $%.2f for minis booking %d", currentUserID, booking.ProposedPrice, booking.ID)

		// Notify admin
		adminMessage := fmt.Sprintf("User %s %s has declined the proposed price of $%.2f for their mini session. Please review.", 
			booking.User.FirstName, booking.User.LastName, booking.ProposedPrice)
		if err := CreateAdminNotification(database, adminMessage, "price_declined", booking.ID, "minis"); err != nil {
			log.Printf("Error creating admin notification: %v", err)
		}

		// Notify user
		userMessage := "You have declined the proposed price. The photographer will review your booking and may propose a different price."
		if err := CreateNotification(database, booking.UserID, userMessage, "price_declined", booking.ID, "minis"); err != nil {
			log.Printf("Error creating user notification: %v", err)
		}
	}

	if err := database.Save(&booking).Error; err != nil {
		http.Error(w, "Error updating booking", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Price %s successfully", approvalStatus),
		"booking": booking,
	})
}

// MarkPaymentReceived marks a booking as paid (admin only)
func MarkPaymentReceived(w http.ResponseWriter, r *http.Request) {
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

	// Parse multipart form data
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		// Try regular form parsing as fallback
		if err := r.ParseForm(); err != nil {
			log.Printf("Error parsing form data: %v", err)
			http.Error(w, "Error parsing form data", http.StatusBadRequest)
			return
		}
	}

	amountStr := r.Form.Get("amount")
	if amountStr == "" {
		log.Printf("❌ Missing payment amount in request")
		http.Error(w, "Missing payment amount", http.StatusBadRequest)
		return
	}
	
	log.Printf("📝 Received payment marking request: type=%s, id=%s, amount=%s", bookingType, bookingID, amountStr)

	amount, err := strconv.ParseFloat(amountStr, 64)
	if err != nil || amount <= 0 {
		http.Error(w, "Invalid amount", http.StatusBadRequest)
		return
	}

	database := db.ConnectDatabase()
	now := time.Now()

	if bookingType == "session" {
		var booking model.BookSession
		if err := database.First(&booking, bookingID).Error; err != nil {
			http.Error(w, "Booking not found", http.StatusNotFound)
			return
		}

		booking.HasPaid = true
		booking.PaidAmount = amount
		booking.PaymentDate = &now

		if err := database.Save(&booking).Error; err != nil {
			http.Error(w, "Error updating booking", http.StatusInternalServerError)
			return
		}

		// Notify user
		message := fmt.Sprintf("Payment of $%.2f received! You can now view your photos once they are uploaded.", amount)
		if err := CreateNotification(database, booking.UserID, message, "payment_received", booking.ID, "session"); err != nil {
			log.Printf("Error creating notification: %v", err)
		}

		log.Printf("✅ Marked session booking %d as paid: $%.2f", booking.ID, amount)

	} else if bookingType == "minis" {
		var booking model.BookMinis
		if err := database.First(&booking, bookingID).Error; err != nil {
			http.Error(w, "Booking not found", http.StatusNotFound)
			return
		}

		booking.HasPaid = true
		booking.PaidAmount = amount
		booking.PaymentDate = &now

		if err := database.Save(&booking).Error; err != nil {
			http.Error(w, "Error updating booking", http.StatusInternalServerError)
			return
		}

		// Notify user
		message := fmt.Sprintf("Payment of $%.2f received! You can now view your photos once they are uploaded.", amount)
		if err := CreateNotification(database, booking.UserID, message, "payment_received", booking.ID, "minis"); err != nil {
			log.Printf("Error creating notification: %v", err)
		}

		log.Printf("✅ Marked minis booking %d as paid: $%.2f", booking.ID, amount)

	} else {
		http.Error(w, "Invalid booking type", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "success",
		"message": "Payment marked as received",
	})
}

// Portfolio Management Handlers

// GetPortfolioItems retrieves all portfolio items (public endpoint)
func GetPortfolioItems(w http.ResponseWriter, r *http.Request) {
	database := db.ConnectDatabase()
	
	var items []model.PortfolioItem
	if err := database.Where("is_active = ?", true).Order("sort_order ASC, created_at DESC").Find(&items).Error; err != nil {
		http.Error(w, "Error fetching portfolio items", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(items)
}

// GetAllPortfolioItems retrieves all portfolio items (admin only)
func GetAllPortfolioItems(w http.ResponseWriter, r *http.Request) {
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
	
	var items []model.PortfolioItem
	if err := database.Order("sort_order ASC, created_at DESC").Find(&items).Error; err != nil {
		http.Error(w, "Error fetching portfolio items", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(items)
}

// AddPortfolioItem adds a new portfolio item (admin only)
func AddPortfolioItem(w http.ResponseWriter, r *http.Request) {
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

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "Error parsing form data", http.StatusBadRequest)
		return
	}

	title := r.Form.Get("title")
	description := r.Form.Get("description")
	category := r.Form.Get("category")
	imageURL := r.Form.Get("image_url")
	sortOrderStr := r.Form.Get("sort_order")

	if title == "" || category == "" || imageURL == "" {
		http.Error(w, "Title, category, and image URL are required", http.StatusBadRequest)
		return
	}

	sortOrder := 0
	if sortOrderStr != "" {
		if parsed, err := strconv.Atoi(sortOrderStr); err == nil {
			sortOrder = parsed
		}
	}

	database := db.ConnectDatabase()
	
	item := model.PortfolioItem{
		Title:       title,
		Description: description,
		ImageURL:    imageURL,
		Category:    category,
		IsActive:    true,
		SortOrder:   sortOrder,
	}

	if err := database.Create(&item).Error; err != nil {
		http.Error(w, "Error creating portfolio item", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"message": "Portfolio item created successfully",
		"item": item,
	})
}

// UpdatePortfolioItem updates a portfolio item (admin only)
func UpdatePortfolioItem(w http.ResponseWriter, r *http.Request) {
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
	itemID := vars["id"]

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "Error parsing form data", http.StatusBadRequest)
		return
	}

	database := db.ConnectDatabase()
	
	var item model.PortfolioItem
	if err := database.First(&item, itemID).Error; err != nil {
		http.Error(w, "Portfolio item not found", http.StatusNotFound)
		return
	}

	// Update fields if provided
	if title := r.Form.Get("title"); title != "" {
		item.Title = title
	}
	if description := r.Form.Get("description"); description != "" {
		item.Description = description
	}
	if category := r.Form.Get("category"); category != "" {
		item.Category = category
	}
	if imageURL := r.Form.Get("image_url"); imageURL != "" {
		item.ImageURL = imageURL
	}
	if sortOrderStr := r.Form.Get("sort_order"); sortOrderStr != "" {
		if sortOrder, err := strconv.Atoi(sortOrderStr); err == nil {
			item.SortOrder = sortOrder
		}
	}
	if isActiveStr := r.Form.Get("is_active"); isActiveStr != "" {
		item.IsActive = isActiveStr == "true"
	}

	if err := database.Save(&item).Error; err != nil {
		http.Error(w, "Error updating portfolio item", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"message": "Portfolio item updated successfully",
		"item": item,
	})
}

// DeletePortfolioItem deletes a portfolio item (admin only)
func DeletePortfolioItem(w http.ResponseWriter, r *http.Request) {
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
	itemID := vars["id"]

	database := db.ConnectDatabase()
	
	var item model.PortfolioItem
	if err := database.First(&item, itemID).Error; err != nil {
		http.Error(w, "Portfolio item not found", http.StatusNotFound)
		return
	}

	if err := database.Delete(&item).Error; err != nil {
		http.Error(w, "Error deleting portfolio item", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "success",
		"message": "Portfolio item deleted successfully",
	})
}

