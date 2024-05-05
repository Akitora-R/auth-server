package http

import (
	"auth-server/internal"
	"auth-server/internal/model"
	storeImpl "auth-server/internal/store"
	"net/http"

	"github.com/go-session/session"
)

func getAuthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := session.Start(r.Context(), w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if _, ok := s.Get(internal.SessionKeyUserID); !ok {
			w.Header().Set("Location", internal.PathLogin)
			w.WriteHeader(http.StatusFound)
			return
		}
		if _, ok := s.Get(internal.SessionKeyScopeConsented); ok {
			w.Header().Set("Location", internal.PathAuthorize)
			w.WriteHeader(http.StatusFound)
			return
		}

		cID, ok := s.Get(internal.SessionKeyClientID)
		if !ok {
			http.Error(w, "failed to get client id", http.StatusInternalServerError)
			return
		}

		clientInfo, err := storeImpl.ClientRepo.GetByID(r.Context(), cID.(string))
		if err != nil {
			http.Error(w, "failed to get client info", http.StatusInternalServerError)
			return
		}
		data := map[string]any{}

		if rt, ok := s.Get(internal.SessionKeyResponseType); !ok {
			http.Error(w, "failed to get response type", http.StatusInternalServerError)
			return
		} else {
			data["responseType"] = rt
		}
		if sci, ok := clientInfo.(model.ScopedClientInfo); ok {
			data["clientInfo"] = sci
		}
		scopes, ok := s.Get(internal.SessionKeyScopeRequested)
		if !ok {
			http.Error(w, "failed to get requested scope", http.StatusInternalServerError)
			return
		}
		data["scopeRequested"] = scopes

		_ = renderHtml(w, "auth.gohtml", 200, data)
	}
}
