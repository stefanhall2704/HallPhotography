package main

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"fmt"
	"encoding/json"
	"strings"
	"strconv"
	"errors"
	"gorm.io/gorm"
	// "encoding/json"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth/gothic"
	"github.com/gorilla/mux"

	"github.com/stefanhall2704/GoPhotography/auth"
	"github.com/stefanhall2704/GoPhotography/db"
	"github.com/stefanhall2704/GoPhotography/middleware"
	"github.com/stefanhall2704/GoPhotography/model"
	// "github.com/stefanhall2704/GoPhotography/calendar"
)


func serverErrorHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}

// func notFoundHandler(w http.ResponseWriter, r *http.Request) {
// 	http.Error(w, "404 not found", http.StatusNotFound)
// }

var store = sessions.NewCookieStore([]byte("secret"))

func home(w http.ResponseWriter, r *http.Request) {
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


type SessionLength int

const (
	Session30Min SessionLength = 30
	Session1Hour SessionLength = 60
	Session2Hours SessionLength = 120
)

func NewSessionLength(minutes int) (SessionLength, error) {
	switch minutes {
	case 30:
		return Session30Min, nil
	case 60:
		return Session1Hour, nil
	case 120:
		return Session2Hours, nil
	default:
		return 0, fmt.Errorf("Unknown session length: (%d)", minutes)
	}
}

func generateMinisSlots(minisSessionId uint, minisIntervalRaw string, w http.ResponseWriter) {
	minisIntervalString := strings.TrimSuffix(minisIntervalRaw, "min")
	minisInterval, err := strconv.Atoi(minisIntervalString)
	if err != nil {
		log.Printf("Error converting:", err)
		return
	}

	log.Printf("minisInterval: %d", minisInterval)
	var duration string
	database := db.ConnectDatabase()
	if err := database.Model(&model.Minis{}).
		Select("duration_interval").
		Where("id = ?", minisSessionId).
		Scan(&duration).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				http.Error(w, "Session doesn't exist", http.StatusNotFound)
			} else {
				http.Error(w, "Database error", http.StatusInternalServerError)
			}
			return
		}
	
}

func checkIfTimeslotIsAvailable(timeSlot string, minisSessionId uint, w http.ResponseWriter) bool {
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


type TimeSlotRange struct {
	Start time.Time
	End   time.Time
}

func parseSlotDuration(durationStr string) (time.Duration, error) {
	if strings.HasSuffix(durationStr, "min") {
		minStr := strings.TrimSuffix(durationStr, "min")
		minutes, err := time.ParseDuration(minStr + "m")
		if err != nil {
			return 0, fmt.Errorf("invalid duration: %w", err)
		}
		return minutes, nil
	}
	return 0, fmt.Errorf("unsupported duration format: %s", durationStr)
}


func GetAvailableTimeSlots(db *gorm.DB, minisID uint, startStr, endStr, durationStr string) ([]string, error) {
	// Parse times
	start, err := time.Parse(time.RFC3339, startStr)
	if err != nil {
		return nil, fmt.Errorf("invalid start time: %w", err)
	}
	end, err := time.Parse(time.RFC3339, endStr)
	if err != nil {
		return nil, fmt.Errorf("invalid end time: %w", err)
	}

	// Parse duration
	slotDuration, err := parseSlotDuration(durationStr)
	if err != nil {
		return nil, err
	}

	// Get all booked slots for this minis session
	var booked []model.BookMinis
	if err := db.Where("minis_id = ?", minisID).Find(&booked).Error; err != nil {
		return nil, err
	}

	// Build a set of booked strings like "03:00 PM"
	bookedSet := make(map[string]struct{})
	for _, b := range booked {
		bookedSet[b.TimeSlot] = struct{}{}
	}

	// Build available slots
	var available []string
	for t := start; t.Add(slotDuration).Equal(end) || t.Add(slotDuration).Before(end); t = t.Add(slotDuration) {
		display := t.Format("03:04 PM")
		if _, taken := bookedSet[display]; !taken {
			available = append(available, display)
		}
	}

	return available, nil
}


func keys(m map[uint]bool) []uint {
	result := make([]uint, 0, len(m))
	for k := range m {
		result = append(result, k)
	}
	return result
}
func getBookedSessions(w http.ResponseWriter, r *http.Request) {
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

	// Fetch all MinisDay records within the range
	var days []model.MinisDay
	if err := database.
		Where("start >= ? AND end <= ?", startTime, endTime).
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
		Where("id IN ?", keys(minisIDs)).
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

		slots, err := GetAvailableTimeSlots(database, day.MinisID, day.Start.Format(time.RFC3339), day.End.Format(time.RFC3339), duration)
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


func bookMinisSessionView(w http.ResponseWriter, r *http.Request) {
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

func bookMinisSession(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error retrieving session: %v", err)
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	log.Printf("Session Values: %+v", session.Values)
	// firstName, _ := session.Values["firstName"].(string)
	// lastName, _ := session.Values["lastName"].(string)
	// fullName := firstName + " " + lastName

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

	if checkIfTimeslotIsAvailable(timeSlot, minisSessionId, w) == false {
		http.Error(w, "Session time slot already booked", http.StatusBadRequest)

		// TODO:Show popup to user that session is booked
		// redirect them back to the page with the sessions on there and show new time slots that are up to date
		return
	}
	bookMinis := model.BookMinis{
		MinisID: minisSessionId,
		UserID: userID,
		TimeSlot: timeSlot,
	}

	database := db.ConnectDatabase()
	if err := database.Create(&bookMinis).Error; err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}
}

func getUsers(w http.ResponseWriter, r *http.Request) {
	database := db.ConnectDatabase()
	var users []model.User
	if err := database.Find(&users).Error; err != nil {
		http.Error(w, "Error fetching sessions", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(users)
}

func getMinis(w http.ResponseWriter, r *http.Request) {
	database := db.ConnectDatabase()
	var minis []model.BookMinis
	if err := database.Find(&minis).Error; err != nil {
		http.Error(w, "Error fetching sessions", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(minis)
}

func getMinisSessionDays(w http.ResponseWriter, r *http.Request) {
	database := db.ConnectDatabase()
	var minis []model.MinisDay
	if err := database.Find(&minis).Error; err != nil {
		http.Error(w, "Error fetching sessions", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(minis)
}

func getMinisSessions(w http.ResponseWriter, r *http.Request) {
	database := db.ConnectDatabase()

	var minis []model.Minis
	if err := database.Preload("Days").Preload("Sessions").Find(&minis).Error; err != nil {
		http.Error(w, "Error fetching sessions", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(minis)
}

type DateTimeRange struct {
	Start string
	End string
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
			End: endDateTime,
		})
	}
	return ranges
}

func createMinisSession(w http.ResponseWriter, r *http.Request) {
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
    		End: parsedEndTime,
    	})
	}

	minisSession := model.Minis{
		Name: name,
		Description: description,
		DurationInterval: timeIntervals,
		Days: miniDays,
	}

	database := db.ConnectDatabase()
	if err := database.Create(&minisSession).Error; err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}
}

func showCalendar(w http.ResponseWriter, r *http.Request) {
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


func getMinisSessionsInRange(w http.ResponseWriter, r *http.Request) {
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

	// Step 1: Get all MinisDay entries within range
	var minisDays []model.MinisDay
	if err := database.
		Where("start >= ? AND end <= ?", startTime, endTime).
		Find(&minisDays).Error; err != nil {
		http.Error(w, "error fetching minis days", http.StatusInternalServerError)
		return
	}

	// Step 2: Extract unique MinisIDs
	minisIDSet := make(map[uint]bool)
	for _, day := range minisDays {
		minisIDSet[day.MinisID] = true
	}

	if len(minisIDSet) == 0 {
		// No sessions found in range
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]model.Minis{})
		return
	}

	// Step 3: Load corresponding Minis entries with their Days preloaded
	var minis []model.Minis
	if err := database.
		Preload("Days").
		Where("id IN ?", keys(minisIDSet)).
		Find(&minis).Error; err != nil {
		http.Error(w, "error fetching minis sessions", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(minis)
}
func getMinisSessionByID(w http.ResponseWriter, r *http.Request) {
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

func userPofile(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error retrieving session: %v", err)
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	firstName, _ := session.Values["firstName"].(string)
	lastName, _ := session.Values["lastName"].(string)
	email, _ := session.Values["email"].(string)

	fullName := firstName + " " + lastName

	data := map[string]interface{}{
		"Name":  fullName,
		"Email": email,
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

func login(w http.ResponseWriter, r *http.Request) {
	cwd, _ := os.Getwd()
	templatePath := filepath.Join(cwd, "templates", "login.html")

	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		log.Printf("Error parsing template: %s", err)
		serverErrorHandler(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, nil); err != nil {
		log.Printf("Error executing template: %s", err)
	}
}

func signup(w http.ResponseWriter, r *http.Request) {
	cwd, _ := os.Getwd()
	templatePath := filepath.Join(cwd, "templates", "signup.html")

	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		log.Printf("Error parsing template: %s", err)
		serverErrorHandler(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, nil); err != nil {
		log.Printf("Error executing template: %s", err)
	}
}

func main() {
	auth.Google_auth_consent()
	database := db.ConnectDatabase()
	if err := database.AutoMigrate(&model.Minis{}, &model.MinisDay{}, &model.Package{}, &model.Photo{},&model.BookMinis{}); err != nil {
		log.Fatalf("Failed to auto-migrate User table: %v", err)
	}
	log.Println("Database migrated successfully")
	request := mux.NewRouter()
	request.HandleFunc("/", home).Methods("GET")
	request.Handle("/profile", auth.AuthMiddleware(http.HandlerFunc(userPofile))).Methods("GET")
	request.HandleFunc("/login", login).Methods("GET")
	request.HandleFunc("/signup", signup).Methods("GET")
	request.HandleFunc("/login/process", auth.LoginHandler).Methods("POST")
	request.HandleFunc("/logout", auth.LogoutHandler).Methods("GET")
	request.HandleFunc("/register/process", auth.RegisterHandler).Methods("POST")
	request.Handle("/create/minis_session", auth.AuthMiddleware(http.HandlerFunc(createMinisSession))).Methods("POST")
	request.HandleFunc("/auth/google/callback", auth.GoogleAuthCallbackHandler).Methods("GET")
	request.HandleFunc("/auth/google", func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), "provider", "google"))
		gothic.BeginAuthHandler(w, r)
	}).Methods("GET")
	request.Handle("/calendar", auth.AdminAuthMiddleware(http.HandlerFunc(showCalendar))).Methods("GET")
	request.Handle("/get/minis_session", auth.AuthMiddleware(http.HandlerFunc(getMinisSessions))).Methods("GET")
	request.Handle("/get/minis_session_by_id/{id}", auth.AuthMiddleware(http.HandlerFunc(getMinisSessionByID))).Methods("GET")
	request.Handle("/get/minis_sessions", auth.AuthMiddleware(http.HandlerFunc(getMinisSessionsInRange))).Methods("GET")
	request.Handle("/get/minis_session_days", auth.AuthMiddleware(http.HandlerFunc(getMinisSessionDays))).Methods("GET")
	request.Handle("/get/minis", auth.AuthMiddleware(http.HandlerFunc(getMinis))).Methods("GET")
	request.Handle("/get/users", auth.AuthMiddleware(http.HandlerFunc(getUsers))).Methods("GET")
	request.Handle("/get/days", auth.AuthMiddleware(http.HandlerFunc(getBookedSessions))).Methods("GET")
	request.Handle("/book_minis", auth.AuthMiddleware(http.HandlerFunc(bookMinisSessionView))).Methods("GET")
	request.Handle("/create/book_minis", auth.AuthMiddleware(http.HandlerFunc(bookMinisSession))).Methods("POST")


	loggedHandler := middleware.LoggingMiddleware(request)

	log.Println("Starting server on :8080")
	if err := http.ListenAndServeTLS(":8080", "server.crt", "server.key", loggedHandler); err != nil {
		log.Fatalf("could not start server: %s", err)
	}
}

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		next.ServeHTTP(w, r)
	})
}
