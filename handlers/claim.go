package handlers

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/stefanhall2704/GoPhotography/db"
	"github.com/stefanhall2704/GoPhotography/model"
)

type claimPageData struct {
	Error string
}

// ClaimPhotosView renders the claim-your-photos page
func ClaimPhotosView(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	email, _ := session.Values["email"].(string)
	if email == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	database := db.ConnectDatabase()
	var pending model.PendingCustomer
	if err := database.Where("email = ? AND is_claimed = ?", email, false).First(&pending).Error; err != nil {
		// No unclaimed booking for this user — send them home
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	t, err := template.ParseFiles("templates/claim_photos.html")
	if err != nil {
		log.Printf("Error parsing claim template: %v", err)
		http.Error(w, "Error loading page", http.StatusInternalServerError)
		return
	}
	t.Execute(w, claimPageData{})
}

// ClaimPhotos processes the session date verification and links the booking to the user
func ClaimPhotos(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Error retrieving session", http.StatusInternalServerError)
		return
	}

	email, _ := session.Values["email"].(string)
	userID, _ := session.Values["userID"].(uint)
	if email == "" || userID == 0 {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	submittedDateStr := r.FormValue("session_date")
	submittedDate, err := time.Parse("2006-01-02", submittedDateStr)
	if err != nil {
		renderClaimError(w, "Please enter a valid date.")
		return
	}

	database := db.ConnectDatabase()
	var pending model.PendingCustomer
	if err := database.Where("email = ? AND is_claimed = ?", email, false).First(&pending).Error; err != nil {
		// No pending booking — redirect home
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	stored := pending.SessionDate
	if submittedDate.Year() != stored.Year() || submittedDate.Month() != stored.Month() || submittedDate.Day() != stored.Day() {
		renderClaimError(w, "That date doesn't match our records. Please double-check the date of your session, or contact Caitlin for help.")
		return
	}

	// Link the booking to this user
	now := time.Now()
	if pending.BookingType == "session" {
		if err := database.Model(&model.BookSession{}).Where("id = ?", pending.BookingID).Update("user_id", userID).Error; err != nil {
			log.Printf("Error claiming session booking: %v", err)
			http.Error(w, "Error claiming booking", http.StatusInternalServerError)
			return
		}
	} else {
		if err := database.Model(&model.BookMinis{}).Where("id = ?", pending.BookingID).Update("user_id", userID).Error; err != nil {
			log.Printf("Error claiming minis booking: %v", err)
			http.Error(w, "Error claiming booking", http.StatusInternalServerError)
			return
		}
	}

	database.Model(&pending).Updates(model.PendingCustomer{
		IsClaimed:       true,
		ClaimedByUserID: userID,
		ClaimedAt:       &now,
	})

	http.Redirect(w, r, fmt.Sprintf("/booking/%s/%d/photos-view", pending.BookingType, pending.BookingID), http.StatusFound)
}

func renderClaimError(w http.ResponseWriter, msg string) {
	t, err := template.ParseFiles("templates/claim_photos.html")
	if err != nil {
		log.Printf("Error parsing claim template: %v", err)
		http.Error(w, "Error loading page", http.StatusInternalServerError)
		return
	}
	t.Execute(w, claimPageData{Error: msg})
}
