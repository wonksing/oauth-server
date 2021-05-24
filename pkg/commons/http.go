package commons

import (
	"net/http"
	"time"
)

func SetCookie(w http.ResponseWriter, name, value string, validHours time.Duration) {

	ck := http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: true,
		SameSite: http.SameSiteDefaultMode,
		Path:     "/",
		Expires:  time.Now().Add(validHours * time.Hour),
	}
	http.SetCookie(w, &ck)
}
