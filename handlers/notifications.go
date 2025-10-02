package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	"gorm.io/gorm"

	"github.com/stefanhall2704/GoPhotography/db"
	"github.com/stefanhall2704/GoPhotography/model"
)

// GetNotifications retrieves all notifications for the logged-in user
func GetNotifications(w http.ResponseWriter, r *http.Request) {
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
	var notifications []model.Notification
	if err := database.Where("user_id = ?", userID).Order("created_at DESC").Find(&notifications).Error; err != nil {
		http.Error(w, "Error fetching notifications", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(notifications)
}

// GetUnreadNotificationCount returns count of unread notifications
func GetUnreadNotificationCount(w http.ResponseWriter, r *http.Request) {
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
	var count int64
	if err := database.Model(&model.Notification{}).Where("user_id = ? AND is_read = ?", userID, false).Count(&count).Error; err != nil {
		http.Error(w, "Error counting notifications", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int64{"count": count})
}

// MarkNotificationAsRead marks a specific notification as read
func MarkNotificationAsRead(w http.ResponseWriter, r *http.Request) {
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
	notificationID, err := strconv.ParseUint(vars["id"], 10, 64)
	if err != nil {
		http.Error(w, "Invalid notification ID", http.StatusBadRequest)
		return
	}

	database := db.ConnectDatabase()
	
	// Verify notification belongs to this user
	var notification model.Notification
	if err := database.First(&notification, notificationID).Error; err != nil {
		http.Error(w, "Notification not found", http.StatusNotFound)
		return
	}

	if notification.UserID != userID {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	notification.IsRead = true
	if err := database.Save(&notification).Error; err != nil {
		http.Error(w, "Error updating notification", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// MarkAllNotificationsAsRead marks all notifications as read for the user
func MarkAllNotificationsAsRead(w http.ResponseWriter, r *http.Request) {
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
	if err := database.Model(&model.Notification{}).Where("user_id = ?", userID).Update("is_read", true).Error; err != nil {
		http.Error(w, "Error updating notifications", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// CreateNotification creates a notification for a specific user
func CreateNotification(database *gorm.DB, userID uint, message string, notifType string, relatedID uint, relatedType string) error {
	notification := model.Notification{
		UserID:      userID,
		Message:     message,
		Type:        notifType,
		RelatedID:   relatedID,
		RelatedType: relatedType,
		IsRead:      false,
	}

	if err := database.Create(&notification).Error; err != nil {
		log.Printf("❌ Error creating notification for user %d: %v", userID, err)
		return err
	}

	log.Printf("✅ Notification created for user %d: %s", userID, message)
	return nil
}

// CreateAdminNotification creates a notification for all admin users
func CreateAdminNotification(database *gorm.DB, message string, notifType string, relatedID uint, relatedType string) error {
	var admins []model.User
	if err := database.Where("is_admin = ?", true).Find(&admins).Error; err != nil {
		log.Printf("❌ Error fetching admin users: %v", err)
		return err
	}

	if len(admins) == 0 {
		log.Printf("⚠️  Warning: No admin users found in database! Cannot send admin notifications.")
		log.Printf("   Run 'go run check_admin.go' to see all users and 'go run set_admin.go <email>' to set an admin.")
		return fmt.Errorf("no admin users found")
	}

	log.Printf("📢 Creating admin notification for %d admin(s): %s", len(admins), message)

	for _, admin := range admins {
		notification := model.Notification{
			UserID:      admin.ID,
			Message:     message,
			Type:        notifType,
			RelatedID:   relatedID,
			RelatedType: relatedType,
			IsRead:      false,
		}

		if err := database.Create(&notification).Error; err != nil {
			log.Printf("❌ Error creating notification for admin %d (%s %s): %v", admin.ID, admin.FirstName, admin.LastName, err)
			// Continue with other admins even if one fails
			continue
		}
		
		log.Printf("✅ Notification created for admin: %s %s (ID: %d)", admin.FirstName, admin.LastName, admin.ID)
	}

	return nil
}

// Helper function to create notification when a booking is made
func CreateBookingNotifications(database *gorm.DB, bookingID uint, userID uint, userName string, bookingType string, timeSlot string) error {
	// bookingType should be "minis" or "session" for routing
	displayType := bookingType
	if bookingType == "minis" {
		displayType = "mini session"
	} else if bookingType == "session" {
		displayType = "photography session"
	}
	
	log.Printf("📬 Creating booking notifications for %s by user %d (%s)", displayType, userID, userName)
	
	// Notification for admin (use display name in message, but bookingType for routing)
	adminMessage := fmt.Sprintf("New %s booking request from %s for %s", displayType, userName, timeSlot)
	if err := CreateAdminNotification(database, adminMessage, "booking", bookingID, bookingType); err != nil {
		log.Printf("⚠️  Failed to create admin notification: %v", err)
		// Don't return error - still try to create user notification
	}

	// Confirmation notification for user
	userMessage := fmt.Sprintf("Your %s booking request for %s has been received. You'll be notified once it's confirmed.", displayType, timeSlot)
	if err := CreateNotification(database, userID, userMessage, "booking", bookingID, bookingType); err != nil {
		log.Printf("⚠️  Failed to create user notification: %v", err)
		return err
	}

	log.Printf("✅ Booking notifications process completed for booking ID %d", bookingID)
	return nil
}

