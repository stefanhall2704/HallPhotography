package main

import (
	"context"
	"log"
	"net/http"

	"github.com/markbates/goth/gothic"
	"github.com/gorilla/mux"

	"github.com/stefanhall2704/GoPhotography/auth"
	"github.com/stefanhall2704/GoPhotography/db"
	"github.com/stefanhall2704/GoPhotography/handlers"
	"github.com/stefanhall2704/GoPhotography/middleware"
	"github.com/stefanhall2704/GoPhotography/model"
)


func serverErrorHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}



func main() {
	auth.Google_auth_consent()
	database := db.ConnectDatabase()
	if err := database.AutoMigrate(&model.User{}, &model.Notification{}, &model.Minis{}, &model.MinisDay{}, &model.Package{}, &model.Photo{}, &model.BookMinis{}, &model.Session{}, &model.SessionDay{}, &model.BookSession{}, &model.BookingMessage{}); err != nil {
		log.Fatalf("Failed to auto-migrate database: %v", err)
	}
	log.Println("Database migrated successfully")
	
	request := mux.NewRouter()
	
	// Common routes
	request.HandleFunc("/", handlers.Home).Methods("GET")
	request.Handle("/profile", auth.AuthMiddleware(http.HandlerFunc(handlers.UserProfile))).Methods("GET")
	request.HandleFunc("/login", handlers.Login).Methods("GET")
	request.HandleFunc("/signup", handlers.Signup).Methods("GET")
	request.HandleFunc("/login/process", auth.LoginHandler).Methods("POST")
	request.HandleFunc("/logout", auth.LogoutHandler).Methods("GET")
	request.HandleFunc("/register/process", auth.RegisterHandler).Methods("POST")
	request.HandleFunc("/auth/google/callback", auth.GoogleAuthCallbackHandler).Methods("GET")
	request.HandleFunc("/auth/google", func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), "provider", "google"))
		gothic.BeginAuthHandler(w, r)
	}).Methods("GET")
	
	// Minis session routes
	request.Handle("/create/minis_session", auth.AuthMiddleware(http.HandlerFunc(handlers.CreateMinisSession))).Methods("POST")
	request.Handle("/calendar", auth.AdminAuthMiddleware(http.HandlerFunc(handlers.ShowMinisCalendar))).Methods("GET")
	request.Handle("/get/minis_session", auth.AuthMiddleware(http.HandlerFunc(handlers.GetMinisSessions))).Methods("GET")
	request.Handle("/get/minis_session_by_id/{id}", auth.AuthMiddleware(http.HandlerFunc(handlers.GetMinisSessionByID))).Methods("GET")
	request.Handle("/get/minis_sessions", auth.AuthMiddleware(http.HandlerFunc(handlers.GetMinisSessionsInRange))).Methods("GET")
	request.Handle("/get/minis_session_days", auth.AuthMiddleware(http.HandlerFunc(handlers.GetMinisSessionDays))).Methods("GET")
	request.Handle("/get/minis", auth.AuthMiddleware(http.HandlerFunc(handlers.GetMinis))).Methods("GET")
	request.Handle("/get/minis_days", auth.AuthMiddleware(http.HandlerFunc(handlers.GetBookedMinisSessions))).Methods("GET")
	request.Handle("/book_minis", auth.AuthMiddleware(http.HandlerFunc(handlers.BookMinisSessionView))).Methods("GET")
	request.Handle("/create/book_minis", auth.AuthMiddleware(http.HandlerFunc(handlers.BookMinisSession))).Methods("POST")
	
	// Normal session routes
	request.Handle("/create/session", auth.AuthMiddleware(http.HandlerFunc(handlers.CreateSession))).Methods("POST")
	request.Handle("/session_calendar", auth.AdminAuthMiddleware(http.HandlerFunc(handlers.ShowSessionCalendar))).Methods("GET")
	request.Handle("/get/sessions", auth.AuthMiddleware(http.HandlerFunc(handlers.GetSessions))).Methods("GET")
	request.Handle("/get/session_by_id/{id}", auth.AuthMiddleware(http.HandlerFunc(handlers.GetSessionByID))).Methods("GET")
	request.Handle("/get/sessions_in_range", auth.AuthMiddleware(http.HandlerFunc(handlers.GetSessionsInRange))).Methods("GET")
	request.Handle("/get/session_days", auth.AuthMiddleware(http.HandlerFunc(handlers.GetBookedSessions))).Methods("GET")
	
	// Original route for backward compatibility (must be after more specific routes)
	request.Handle("/get/days", auth.AuthMiddleware(http.HandlerFunc(handlers.GetBookedMinisSessions))).Methods("GET")
	request.Handle("/book_session", auth.AuthMiddleware(http.HandlerFunc(handlers.BookSessionView))).Methods("GET")
	request.Handle("/create/book_session", auth.AuthMiddleware(http.HandlerFunc(handlers.BookSession))).Methods("POST")
	
	// Common API routes
	request.Handle("/get/users", auth.AuthMiddleware(http.HandlerFunc(handlers.GetUsers))).Methods("GET")
	request.Handle("/get/user_bookings", auth.AuthMiddleware(http.HandlerFunc(handlers.GetUserBookings))).Methods("GET")
	request.Handle("/get/current_user", auth.AuthMiddleware(http.HandlerFunc(handlers.GetCurrentUserStatus))).Methods("GET")
	
	// Notification routes
	request.Handle("/get/notifications", auth.AuthMiddleware(http.HandlerFunc(handlers.GetNotifications))).Methods("GET")
	request.Handle("/get/notifications/unread_count", auth.AuthMiddleware(http.HandlerFunc(handlers.GetUnreadNotificationCount))).Methods("GET")
	request.Handle("/notifications/{id}/mark_read", auth.AuthMiddleware(http.HandlerFunc(handlers.MarkNotificationAsRead))).Methods("POST")
	request.Handle("/notifications/mark_all_read", auth.AuthMiddleware(http.HandlerFunc(handlers.MarkAllNotificationsAsRead))).Methods("POST")
	
	// Admin routes
	request.Handle("/admin/bookings", auth.AdminAuthMiddleware(http.HandlerFunc(handlers.GetAllBookings))).Methods("GET")
	request.Handle("/admin/bookings/pending", auth.AdminAuthMiddleware(http.HandlerFunc(handlers.GetPendingBookings))).Methods("GET")
	request.Handle("/admin/booking/{type}/{id}/status", auth.AuthMiddleware(http.HandlerFunc(handlers.UpdateBookingStatus))).Methods("POST") // Auth only - checks ownership inside
	request.Handle("/admin/session/{id}/price", auth.AdminAuthMiddleware(http.HandlerFunc(handlers.UpdateSessionPrice))).Methods("POST")
	request.Handle("/admin/user/{id}/toggle_admin", auth.AdminAuthMiddleware(http.HandlerFunc(handlers.ToggleUserAdmin))).Methods("POST")
	
	// User approval routes
	request.Handle("/booking/session/{id}/approve_price", auth.AuthMiddleware(http.HandlerFunc(handlers.ApprovePriceForSession))).Methods("POST")
	
	// Messaging routes
	request.Handle("/booking/{type}/{id}", auth.AuthMiddleware(http.HandlerFunc(handlers.GetBookingDetails))).Methods("GET")
	request.Handle("/booking/{type}/{id}/messages", auth.AuthMiddleware(http.HandlerFunc(handlers.GetBookingMessages))).Methods("GET")
	request.Handle("/booking/{type}/{id}/message", auth.AuthMiddleware(http.HandlerFunc(handlers.CreateBookingMessage))).Methods("POST")

	// Serve static files (CSS, JS, images)
	request.PathPrefix("/css/").Handler(http.StripPrefix("/css/", http.FileServer(http.Dir("templates/css/"))))
	request.PathPrefix("/js/").Handler(http.StripPrefix("/js/", http.FileServer(http.Dir("templates/js/"))))

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
