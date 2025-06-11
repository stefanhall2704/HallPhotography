package calendarreader

import (
	// "context"
	"fmt"
	"net/http"
	"os"
	"time"
	"log"
	// "strconv"

	"github.com/gorilla/sessions"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/calendar/v3"
	"google.golang.org/api/option"
)

// EventInfo represents a simplified version of a calendar event
// type EventInfo struct {
// 	Summary string
// 	Start   string
// 	End     string
// }

// CreateCalendarClient creates a Google Calendar client using the session tokens
func CreateCalendarClient(r *http.Request) (*calendar.Service, error) {
	var store = sessions.NewCookieStore([]byte("secret"))
	session, err := store.Get(r, "session-name")
	if err != nil {
		return nil, fmt.Errorf("session error: %v", err)
	}

	accessToken, ok := session.Values["access_token"].(string)
	if !ok {
		return nil, fmt.Errorf("missing access_token in session")
	}

	token := &oauth2.Token{
		AccessToken: accessToken,
	}

	refreshToken, ok := session.Values["refresh_token"].(string)
	if ok {
		token.RefreshToken = refreshToken
	}

	expiry, ok := session.Values["token_expiry"].(time.Time)
	if ok {
		token.Expiry = expiry
	}

	config := &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		Endpoint:     google.Endpoint,
		RedirectURL:  os.Getenv("GOOGLE_CALLBACK_URL"),
		Scopes:       []string{"https://www.googleapis.com/auth/calendar.readonly"},
	}

	client := config.Client(r.Context(), token)
	return calendar.NewService(r.Context(), option.WithHTTPClient(client))
}

type EventInfo struct {
	ID          string
	Summary     string
	Description string
	Location    string
	Start       string
	End         string
	Link        string
	Creator     string
}

func GetUpcomingEvents(r *http.Request) ([]EventInfo, error) {
	srv, err := CreateCalendarClient(r)
	if err != nil {
		return nil, err
	}

	startStr := r.URL.Query().Get("start")
	
	log.Printf("Start Time: %s", startStr)
	endStr := r.URL.Query().Get("end")

	var timeMin, timeMax time.Time

	if startStr != "" {
		// t, err := time.Parse("2006-01-02", startStr)
		t, err := time.Parse(time.RFC3339, startStr)
		if err == nil {
			timeMin = t.AddDate(0, 0, 14) // Skip 2 weeks from start of visible range
		}
	}
	if endStr != "" {
		// t, err := time.Parse("2006-01-02", endStr)
		t, err := time.Parse(time.RFC3339, endStr)
		if err == nil {
			timeMax = t
		}
	}

	if timeMin.IsZero() {
		timeMin = time.Now().AddDate(0, 0, 14).UTC().Truncate(24 * time.Hour)
	}
	if timeMax.IsZero() {
		timeMax = timeMin.AddDate(0, 1, 0)
	}

	call := srv.Events.List("primary").
		ShowDeleted(false).
		SingleEvents(true).
		TimeMin(timeMin.Format(time.RFC3339)).
		TimeMax(timeMax.Format(time.RFC3339)).
		OrderBy("startTime")

	events, err := call.Do()
	if err != nil {
		return nil, err
	}

	var results []EventInfo
	for _, item := range events.Items {
		startRaw := item.Start.DateTime
		if startRaw == "" {
			startRaw = item.Start.Date
		} else if parsed, err := time.Parse(time.RFC3339, startRaw); err == nil {
			startRaw = parsed.Format("2006-01-02")
		}

		endRaw := item.End.DateTime
		if endRaw == "" {
			endRaw = item.End.Date
		} else if parsed, err := time.Parse(time.RFC3339, endRaw); err == nil {
			endRaw = parsed.Format("2006-01-02")
		}

		creator := ""
		if item.Creator != nil {
			creator = item.Creator.Email
		}

		results = append(results, EventInfo{
			ID:          item.Id,
			Summary:     item.Summary,
			Description: item.Description,
			Location:    item.Location,
			Start:       startRaw,
			End:         endRaw,
			Link:        item.HtmlLink,
			Creator:     creator,
		})
	}

	return results, nil
}
