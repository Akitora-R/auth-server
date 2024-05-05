package http

import (
	"auth-server/internal"
	"net/http"

	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-session/session"
)

func getRegistrationHandler(_ *server.Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := session.Start(r.Context(), w, r)
		if err != nil {
			http.Error(w, "internal_server_error", http.StatusInternalServerError)
			return
		}
		_, ok := s.Get(internal.SessionKeyTelegramData)
		if !ok {
			http.Error(w, "internal_server_error", http.StatusInternalServerError)
			return
		}
		renderHtml(w, "registration.gohtml", 200, map[string]any{})
	}
}
