package handlers

import (
	"github.com/gorilla/sessions"
)

// Shared store variable for all handlers
var store = sessions.NewCookieStore([]byte("secret"))
