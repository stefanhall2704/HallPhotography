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
		if status == "confirmed" {
			if proposedTimeSlot != "" {
				message = fmt.Sprintf("Your mini session has been confirmed for %s (updated time)", proposedTimeSlot)
			} else {
				message = fmt.Sprintf("Your mini session has been confirmed for %s", booking.TimeSlot)
			}
		} else if status == "cancelled" {
			message = "Your mini session booking has been cancelled"
		} else if proposedTimeSlot != "" {
			message = fmt.Sprintf("The photographer proposed a new time for your mini session: %s", proposedTimeSlot)
		} else {
			message = fmt.Sprintf("Your mini session booking status: %s", status)
		}

		if err := CreateNotification(database, booking.UserID, message, "update", booking.ID, "minis"); err != nil {
			log.Printf("Error creating notification: %v", err)
		}

		// If user left a message, add it to the conversation
		if message != "" {
			bookingMessage := model.BookingMessage{
				BookingID:   booking.ID,
				BookingType: "minis",
				UserID:      currentUserID,
				Message:     message,
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

			// Set status to awaiting payment approval and store the proposed price
			booking.Status = "awaiting_payment_approval"
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
	if booking.Status != "awaiting_payment_approval" {
		http.Error(w, "This booking is not awaiting payment approval", http.StatusBadRequest)
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

