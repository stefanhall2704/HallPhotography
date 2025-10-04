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
	"github.com/stefanhall2704/GoPhotography/services"
)

// Normal Session Handlers

func BookSessionView(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error retrieving session: %v", err)
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

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
		"Authenticated": userID != 0, // Checks if the user is logged in
		"IsAdmin":       isAdmin,
	}

	t, err := template.ParseFiles("templates/sessions/booksession.html")
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

func BookSession(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error retrieving session: %v", err)
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		log.Printf("Error parsing multipart form: %v", err)
		http.Error(w, "Error parsing form data", http.StatusBadRequest)
		return
	}

	// convert userId
	userIDRaw, ok := session.Values["userID"]
	if !ok {
		http.Error(w, "User ID not found in session", http.StatusUnauthorized)
		return
	}

	var userID uint
	switch v := userIDRaw.(type) {
	case string:
		parsed, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			http.Error(w, "Invalid user ID", http.StatusBadRequest)
			return
		}
		userID = uint(parsed)
	case float64:
		userID = uint(v)
	case int:
		userID = uint(v)
	case int64:
		userID = uint(v)
	case uint:
		userID = v
	case json.Number:
		parsed, err := v.Int64()
		if err != nil {
			http.Error(w, "Invalid user ID", http.StatusBadRequest)
			return
		}
		userID = uint(parsed)
	default:
		log.Printf("Unexpected userID type: %T", userIDRaw)
		http.Error(w, "Invalid user ID type", http.StatusBadRequest)
		return
	}

	timeSlot := r.Form.Get("time_slot")
	sessionDateStr := r.Form.Get("session_date")
	notes := r.Form.Get("notes")

	if timeSlot == "" {
		http.Error(w, "Missing time_slot", http.StatusBadRequest)
		return
	}

	if sessionDateStr == "" {
		http.Error(w, "Missing session_date", http.StatusBadRequest)
		return
	}

	// Parse the session date
	sessionDate, err := time.Parse("2006-01-02", sessionDateStr)
	if err != nil {
		log.Printf("Invalid session_date format: %v", err)
		http.Error(w, "Invalid session_date format, expected YYYY-MM-DD", http.StatusBadRequest)
		return
	}

	database := db.ConnectDatabase()

	// Validate that the booking is at least 2 weeks in the future
	if err := services.ValidateBookingDate(sessionDate); err != nil {
		log.Printf("Booking date validation failed: %v", err)
		http.Error(w, fmt.Sprintf("Invalid booking date: %s", err.Error()), http.StatusBadRequest)
		return
	}

	// Check if this exact time slot is already booked for this date
	// Using database-agnostic date comparison (works with PostgreSQL, MySQL, SQLite)
	var existingBooking model.BookSession
	startOfDay := time.Date(sessionDate.Year(), sessionDate.Month(), sessionDate.Day(), 0, 0, 0, 0, sessionDate.Location())
	endOfDay := startOfDay.Add(24 * time.Hour)
	
	err = database.
		Joins("JOIN sessions ON book_sessions.session_id = sessions.id").
		Joins("JOIN session_days ON sessions.id = session_days.session_id").
		Where("session_days.start >= ? AND session_days.start < ? AND book_sessions.time_slot = ?", startOfDay, endOfDay, timeSlot).
		First(&existingBooking).Error
	
	if err == nil {
		log.Printf("Time slot already booked: date=%s, time_slot=%s", sessionDateStr, timeSlot)
		http.Error(w, "This time slot is already booked", http.StatusConflict)
		return
	}

	// For regular sessions, we create a new Session entry for each booking request
	// This allows flexibility - the photographer can review and confirm bookings
	newSession := model.Session{
		Name:             fmt.Sprintf("Session for %s at %s", sessionDateStr, timeSlot),
		Description:      fmt.Sprintf("User requested session. Notes: %s", notes),
		DurationInterval: "1-2 hours", // Default, can be adjusted
		Price:            0.0,          // To be determined
	}

	// Save the session
	if err := database.Create(&newSession).Error; err != nil {
		log.Printf("Error creating session: %v", err)
		http.Error(w, "Error creating session", http.StatusInternalServerError)
		return
	}

	// Create a session day for this booking
	sessionDay := model.SessionDay{
		SessionID: newSession.ID,
		Start:     sessionDate,
		End:       sessionDate.Add(2 * time.Hour), // Default 2-hour session
	}

	if err := database.Create(&sessionDay).Error; err != nil {
		log.Printf("Error creating session day: %v", err)
		http.Error(w, "Error creating session day", http.StatusInternalServerError)
		return
	}

	// Create the booking
	bookSession := model.BookSession{
		SessionID: newSession.ID,
		UserID:    userID,
		TimeSlot:  timeSlot,
		Status:    "pending",
	}

	if err := database.Create(&bookSession).Error; err != nil {
		log.Printf("Error creating booking: %v", err)
		http.Error(w, "Error creating booking", http.StatusInternalServerError)
		return
	}

	// Get user information for notification
	firstName, _ := session.Values["firstName"].(string)
	lastName, _ := session.Values["lastName"].(string)
	userName := fmt.Sprintf("%s %s", firstName, lastName)

	// Create notifications (use "session" as type for routing)
	bookingInfo := fmt.Sprintf("%s at %s", sessionDateStr, timeSlot)
	if err := CreateBookingNotifications(database, bookSession.ID, userID, userName, "session", bookingInfo); err != nil {
		log.Printf("Error creating notifications: %v", err)
		// Don't fail the booking if notifications fail
	}

	w.WriteHeader(http.StatusCreated)
	log.Printf("Successfully booked session %d for user %d on %s at %s", newSession.ID, userID, sessionDateStr, timeSlot)
}

func GetSessions(w http.ResponseWriter, r *http.Request) {
	database := db.ConnectDatabase()
	var sessions []model.Session
	if err := database.Preload("Days").Preload("Bookings").Find(&sessions).Error; err != nil {
		http.Error(w, "Error fetching sessions", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessions)
}

func GetSessionByID(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	database := db.ConnectDatabase()

	var session model.Session
	if err := database.Preload("Days").First(&session, id).Error; err != nil {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(session)
}

func GetSessionsInRange(w http.ResponseWriter, r *http.Request) {
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")

	if startStr == "" || endStr == "" {
		http.Error(w, "start and end query parameters are required", http.StatusBadRequest)
		return
	}

	startTime, err := time.Parse(time.RFC3339, startStr)
	if err != nil {
		http.Error(w, "invalid start time format", http.StatusBadRequest)
		return
	}

	endTime, err := time.Parse(time.RFC3339, endStr)
	if err != nil {
		http.Error(w, "invalid end time format", http.StatusBadRequest)
		return
	}

	database := db.ConnectDatabase()

	// Calculate minimum bookable date (2 weeks from now)
	minimumDate := time.Now().AddDate(0, 0, services.MinimumBookingNoticeDays)

	// Step 1: Get all SessionDay entries within range that are at least 7 days out
	var sessionDays []model.SessionDay
	if err := database.
		Where("start >= ? AND start <= ? AND start >= ?", startTime, endTime, minimumDate).
		Find(&sessionDays).Error; err != nil {
		http.Error(w, "error fetching session days", http.StatusInternalServerError)
		return
	}

	// Step 2: Extract unique SessionIDs
	sessionIDSet := make(map[uint]bool)
	for _, day := range sessionDays {
		sessionIDSet[day.SessionID] = true
	}

	if len(sessionIDSet) == 0 {
		// No sessions found in range
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]model.Session{})
		return
	}

	// Step 3: Load corresponding Session entries with their Days preloaded
	var sessions []model.Session
	if err := database.
		Preload("Days").
		Where("id IN ?", services.Keys(sessionIDSet)).
		Find(&sessions).Error; err != nil {
		http.Error(w, "error fetching sessions", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessions)
}

func CreateSession(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form data", http.StatusBadRequest)
		return
	}

	name := r.Form.Get("name")
	description := r.Form.Get("description")
	timeIntervals := r.Form.Get("time_intervals")
	priceStr := r.Form.Get("price")
	sessionDays := r.Form.Get("session_days") // format needs to be like this: 2025-06-23T00:00,10:30 - 12:00,2025-06-28T00:00,11:30 - 14:00

	price, err := strconv.ParseFloat(priceStr, 64)
	if err != nil {
		http.Error(w, "Invalid price format", http.StatusBadRequest)
		return
	}

	var sessionDaysParsed []DateTimeRange = parseDateTimes(sessionDays)
	var sessionDaysList []model.SessionDay

	for _, dayStr := range sessionDaysParsed {
		layout := "2006-01-02T15:04"
		parsedStartTime, err := time.Parse(layout, dayStr.Start)
		if err != nil {
			http.Error(w, "Invalid time format", http.StatusBadRequest)
			return
		}
		parsedEndTime, err := time.Parse(layout, dayStr.End)
		if err != nil {
			http.Error(w, "Invalid time format", http.StatusBadRequest)
			return
		}

		sessionDaysList = append(sessionDaysList, model.SessionDay{
			Start: parsedStartTime,
			End:   parsedEndTime,
		})
	}

	session := model.Session{
		Name:             name,
		Description:      description,
		DurationInterval: timeIntervals,
		Price:            price,
		Days:             sessionDaysList,
	}

	database := db.ConnectDatabase()
	if err := database.Create(&session).Error; err != nil {
		http.Error(w, "Error creating session", http.StatusInternalServerError)
		return
	}

	// Notify all users about the new session availability
	if err := NotifyAllUsersOfNewSession(database, name, "session", session.ID); err != nil {
		log.Printf("⚠️  Failed to notify users of new session: %v", err)
		// Don't fail the request if notifications fail
	}

	log.Printf("✅ Photography session created successfully: %s (ID: %d)", name, session.ID)
	w.WriteHeader(http.StatusCreated)
}

func ShowSessionCalendar(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error retrieving session: %v", err)
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

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
		"Authenticated": userID != 0, // Checks if the user is logged in
		"IsAdmin":       isAdmin,
	}

	t, err := template.ParseFiles("templates/sessions/createsessions.html")
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

func GetBookedSessions(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")

	if startStr == "" || endStr == "" {
		http.Error(w, "start and end query parameters are required", http.StatusBadRequest)
		return
	}

	startTime, err := time.Parse(time.RFC3339, startStr)
	if err != nil {
		http.Error(w, "invalid start time format, expected RFC3339", http.StatusBadRequest)
		return
	}

	endTime, err := time.Parse(time.RFC3339, endStr)
	if err != nil {
		http.Error(w, "invalid end time format, expected RFC3339", http.StatusBadRequest)
		return
	}

	database := db.ConnectDatabase()

	// Calculate minimum bookable date (2 weeks from now)
	minimumDate := time.Now().AddDate(0, 0, services.MinimumBookingNoticeDays)

	// Fetch all SessionDay records within the range that are at least 7 days out
	var days []model.SessionDay
	if err := database.
		Where("start >= ? AND start <= ? AND start >= ?", startTime, endTime, minimumDate).
		Find(&days).Error; err != nil {
		http.Error(w, "error fetching days", http.StatusInternalServerError)
		return
	}

	// Fetch all relevant Session entries (by ID)
	sessionIDs := make(map[uint]bool)
	for _, day := range days {
		sessionIDs[day.SessionID] = true
	}

	var sessions []model.Session
	if err := database.
		Where("id IN ?", services.Keys(sessionIDs)).
		Find(&sessions).Error; err != nil {
		http.Error(w, "error fetching sessions", http.StatusInternalServerError)
		return
	}

	// Map sessionID -> duration
	durationMap := make(map[uint]string)
	for _, s := range sessions {
		durationMap[s.ID] = s.DurationInterval
	}

	// Group by date
	allAvailableSlots := make(map[string][]string)

	for _, day := range days {
		duration := durationMap[day.SessionID]
		if duration == "" {
			continue // skip if no duration
		}

		slots, err := services.GetAvailableSessionTimeSlots(database, day.SessionID, day.Start.Format(time.RFC3339), day.End.Format(time.RFC3339), duration)
		if err != nil {
			log.Printf("error generating slots for %s - %s: %v", day.Start, day.End, err)
			continue
		}

		dateOnly := day.Start.Format("2006-01-02")
		allAvailableSlots[dateOnly] = append(allAvailableSlots[dateOnly], slots...)
	}

	// Return as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(allAvailableSlots)
}
