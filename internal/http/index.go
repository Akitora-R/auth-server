package http

import (
	"auth-server/internal"
	"net/http"
	"os"
)

func indexHandler(w http.ResponseWriter, r *http.Request) {
	_, err := os.Stat(internal.PlaceholderFile)
	if os.IsNotExist(err) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("UwU"))
	} else {
		w.Header().Set("Content-Type", "image/jpeg")
		http.ServeFile(w, r, internal.PlaceholderFile)
	}
}
