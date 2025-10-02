package handlers

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/stefanhall2704/GoPhotography/db"
	"github.com/stefanhall2704/GoPhotography/model"
	"github.com/stefanhall2704/GoPhotography/services"
)

type DateTimeRange struct {
	Start string
	End   string
}

func parseDateTimes(sessionDays string) []DateTimeRange {
	var ranges []DateTimeRange
	// dateTimes := "2025-06-23T00:00,10:30 - 12:00,2025-06-28T00:00,11:30 - 14:00"
	splitDateTimes := strings.Split(sessionDays, ",")

	for i := 0; i < len(splitDateTimes); i += 2 {
		if i+1 >= len(splitDateTimes) {
			break // avoid out-of-bounds
		}
		date := splitDateTimes[i]
		timeRange := splitDateTimes[i+1]
		times := strings.Split(timeRange, " - ")
		if len(times) != 2 {
			continue // malformed range
		}
		startTime := times[0]
		endTime := times[1]
		startDateTime := strings.TrimSuffix(date, "00:00") + startTime
		endDateTime := strings.TrimSuffix(date, "00:00") + endTime
		ranges = append(ranges, DateTimeRange{
			Start: startDateTime,
			End:   endDateTime,
		})
	}
	return ranges
}

func checkIfMinisTimeslotIsAvailable(timeSlot string, minisSessionId uint, w http.ResponseWriter) bool {
	var exists bool
	database := db.ConnectDatabase()
	err := database.Model(&model.BookMinis{}).
		Select("count(*) > 0").
		Where("time_slot = ? AND minis_id = ?", timeSlot, minisSessionId).
		Find(&exists).Error

	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return false
	}
	return !exists
}

func BookMinisSessionView(w http.ResponseWriter, r *http.Request) {
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

	t, err := template.ParseFiles("templates/minis/bookminis.html")
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

func BookMinisSession(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error retrieving session: %v", err)
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	log.Printf("Session Values: %+v", session.Values)

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

	log.Printf("Raw userID value: %v, type: %T", userIDRaw, userIDRaw)

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

	// convert minisSessionId
	minisSessionIdStr := r.Form.Get("minis_session_id")
	if minisSessionIdStr == "" {
		http.Error(w, "Missing minis_session_id", http.StatusBadRequest)
		return
	}

	minisSessionId64, err := strconv.ParseUint(minisSessionIdStr, 10, 64)
	if err != nil {
		log.Printf("Invalid minis_session_id: %v", err)
		http.Error(w, "Invalid minis_session_id", http.StatusBadRequest)
		return
	}

	minisSessionId := uint(minisSessionId64)

	database := db.ConnectDatabase()

	// Validate that the booking is at least 2 weeks in the future
	sessionDate, err := services.GetMinisSessionDate(database, minisSessionId)
	if err != nil {
		log.Printf("Error retrieving session date: %v", err)
		http.Error(w, "Error validating session date", http.StatusInternalServerError)
		return
	}

	if err := services.ValidateBookingDate(sessionDate); err != nil {
		log.Printf("Booking date validation failed: %v", err)
		http.Error(w, fmt.Sprintf("Invalid booking date: %s", err.Error()), http.StatusBadRequest)
		return
	}

	if checkIfMinisTimeslotIsAvailable(timeSlot, minisSessionId, w) == false {
		http.Error(w, "Session time slot already booked", http.StatusBadRequest)
		// TODO:Show popup to user that session is booked
		// redirect them back to the page with the sessions on there and show new time slots that are up to date
		return
	}

	bookMinis := model.BookMinis{
		MinisID:  minisSessionId,
		UserID:   userID,
		TimeSlot: timeSlot,
		Status:   "pending",
	}

	if err := database.Create(&bookMinis).Error; err != nil {
		http.Error(w, "Error creating booking", http.StatusInternalServerError)
		return
	}

	// Get user information for notification
	firstName, _ := session.Values["firstName"].(string)
	lastName, _ := session.Values["lastName"].(string)
	userName := fmt.Sprintf("%s %s", firstName, lastName)

	// Create notifications (use "minis" as type for routing)
	if err := CreateBookingNotifications(database, bookMinis.ID, userID, userName, "minis", timeSlot); err != nil {
		log.Printf("Error creating notifications: %v", err)
		// Don't fail the booking if notifications fail
	}

	w.WriteHeader(http.StatusCreated)
	log.Printf("Successfully booked minis session %d for user %d at %s", minisSessionId, userID, timeSlot)
}

func GetMinis(w http.ResponseWriter, r *http.Request) {
	database := db.ConnectDatabase()
	var minis []model.BookMinis
	if err := database.Find(&minis).Error; err != nil {
		http.Error(w, "Error fetching sessions", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(minis)
}

func GetMinisSessionDays(w http.ResponseWriter, r *http.Request) {
	database := db.ConnectDatabase()
	var minis []model.MinisDay
	if err := database.Find(&minis).Error; err != nil {
		http.Error(w, "Error fetching sessions", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(minis)
}

func GetMinisSessions(w http.ResponseWriter, r *http.Request) {
	database := db.ConnectDatabase()

	var minis []model.Minis
	if err := database.Preload("Days").Preload("Sessions").Find(&minis).Error; err != nil {
		http.Error(w, "Error fetching sessions", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(minis)
}

func CreateMinisSession(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form data", http.StatusBadRequest)
		return
	}

	name := r.Form.Get("name")
	description := r.Form.Get("description")
	timeIntervals := r.Form.Get("time_intervals")
	sessionDays := r.Form.Get("session_days") // format needs to be like this: 2025-06-23T00:00,10:30 - 12:00,2025-06-28T00:00,11:30 - 14:00

	var minisDays []DateTimeRange = parseDateTimes(sessionDays)
	var miniDays []model.MinisDay

	for _, dayStr := range minisDays {
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

		miniDays = append(miniDays, model.MinisDay{
			Start: parsedStartTime,
			End:   parsedEndTime,
		})
	}

	minisSession := model.Minis{
		Name:             name,
		Description:      description,
		DurationInterval: timeIntervals,
		Days:             miniDays,
	}

	database := db.ConnectDatabase()
	if err := database.Create(&minisSession).Error; err != nil {
		http.Error(w, "Error creating mini session", http.StatusInternalServerError)
		return
	}

	// Notify all users about the new mini session availability
	if err := NotifyAllUsersOfNewSession(database, name, "minis", minisSession.ID); err != nil {
		log.Printf("⚠️  Failed to notify users of new mini session: %v", err)
		// Don't fail the request if notifications fail
	}

	log.Printf("✅ Mini session created successfully: %s (ID: %d)", name, minisSession.ID)
	w.WriteHeader(http.StatusCreated)
}

func ShowMinisCalendar(w http.ResponseWriter, r *http.Request) {
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

func GetMinisSessionsInRange(w http.ResponseWriter, r *http.Request) {
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
	log.Printf("📅 GetMinisSessionsInRange: Querying range %s to %s (minimum date: %s)", 
		startTime.Format("2006-01-02"), endTime.Format("2006-01-02"), minimumDate.Format("2006-01-02"))

	// Debug: Check all MinisDay entries in the database
	var allMinisDays []model.MinisDay
	database.Find(&allMinisDays)
	log.Printf("🔍 Total MinisDay entries in database: %d", len(allMinisDays))
	for i, day := range allMinisDays {
		if i < 5 { // Log first 5 for debugging
			log.Printf("  - MinisDay %d: MinisID=%d, Start=%s, End=%s", 
				day.ID, day.MinisID, day.Start.Format("2006-01-02 15:04"), day.End.Format("2006-01-02 15:04"))
		}
	}

	// Step 1: Get all MinisDay entries within range that are at least 7 days out
	var minisDays []model.MinisDay
	if err := database.
		Where("start >= ? AND start <= ? AND start >= ?", startTime, endTime, minimumDate).
		Find(&minisDays).Error; err != nil {
		http.Error(w, "error fetching minis days", http.StatusInternalServerError)
		return
	}
	log.Printf("📊 Found %d minisDays matching criteria", len(minisDays))

	// Step 2: Extract unique MinisIDs
	minisIDSet := make(map[uint]bool)
	for _, day := range minisDays {
		minisIDSet[day.MinisID] = true
	}

	if len(minisIDSet) == 0 {
		// No sessions found in range
		log.Printf("⚠️  No minis sessions found in range (possibly none meet 2-week minimum)")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]model.Minis{})
		return
	}

	log.Printf("✅ Found %d unique minis sessions", len(minisIDSet))

	// Step 3: Load corresponding Minis entries with their Days preloaded
	var minis []model.Minis
	if err := database.
		Preload("Days").
		Where("id IN ?", services.Keys(minisIDSet)).
		Find(&minis).Error; err != nil {
		http.Error(w, "error fetching minis sessions", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(minis)
}

func GetMinisSessionByID(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	database := db.ConnectDatabase()

	var minis model.Minis
	if err := database.Preload("Days").First(&minis, id).Error; err != nil {
		http.Error(w, "Minis session not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(minis)
}

func GetBookedMinisSessions(w http.ResponseWriter, r *http.Request) {
	//TODO: THIS IS NOT FILTERING OUT THE ALREADY BOOKED SESSIONS
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

	// Calculate minimum bookable date (7 days from now)
	minimumDate := time.Now().AddDate(0, 0, services.MinimumBookingNoticeDays)

	// Fetch all MinisDay records within the range that are at least 7 days out
	var days []model.MinisDay
	if err := database.
		Where("start >= ? AND start <= ? AND start >= ?", startTime, endTime, minimumDate).
		Find(&days).Error; err != nil {
		http.Error(w, "error fetching days", http.StatusInternalServerError)
		return
	}

	// Fetch all relevant Minis entries (by ID)
	minisIDs := make(map[uint]bool)
	for _, day := range days {
		minisIDs[day.MinisID] = true
	}

	var minis []model.Minis
	if err := database.
		Where("id IN ?", services.Keys(minisIDs)).
		Find(&minis).Error; err != nil {
		http.Error(w, "error fetching minis sessions", http.StatusInternalServerError)
		return
	}

	// Map minisID -> duration
	durationMap := make(map[uint]string)
	for _, m := range minis {
		durationMap[m.ID] = m.DurationInterval
	}

	// Group by date
	allAvailableSlots := make(map[string][]string)

	for _, day := range days {
		duration := durationMap[day.MinisID]
		if duration == "" {
			continue // skip if no duration
		}

		slots, err := services.GetAvailableTimeSlots(database, day.MinisID, day.Start.Format(time.RFC3339), day.End.Format(time.RFC3339), duration)
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
