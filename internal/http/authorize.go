package http

import (
	"auth-server/internal"
	"auth-server/internal/model"
	storeImpl "auth-server/internal/store"
	"log/slog"
	"net/http"

	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-session/session"
)

func getAuthorizeHandler(srv *server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Authorize Request", "remote", r.RemoteAddr)
		s, err := session.Start(r.Context(), w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = r.ParseForm()
		uid, ok := s.Get(internal.SessionKeyUserID)
		if !ok {
			_ = s.Flush()
			clientID := r.Form.Get("client_id")
			slog.Info("logging for not logged user", "client_id", clientID)
			ci, err := storeImpl.ClientRepo.GetByID(r.Context(), clientID)
			if err != nil {
				slog.Warn("err when fetch client", "id", clientID, "err", err.Error())
				http.Error(w, "invalid_client_id", http.StatusBadRequest)
				return
			}
			if ci == nil {
				slog.Warn("fetched nil client", "id", clientID)
				http.Error(w, "invalid_client_id", http.StatusBadRequest)
				return
			}
			s.Set(internal.SessionKeyResponseType, r.Form.Get("response_type"))
			s.Set(internal.SessionKeyScopeRequested, model.ParseScopes(r.FormValue("scope")))
			s.Set(internal.SessionKeyClientID, clientID)
			if err = s.Save(); err != nil {
				slog.Error("error when saving session", "err", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Location", internal.PathLogin)
			w.WriteHeader(http.StatusFound)
			return
		}
		slog.Info("logging for logged user", "user_id", uid)

		if consented := r.Form["consented"]; len(consented) > 0 {
			var consents []model.ScopeInfo
			for _, consentStr := range consented {
				if scope, err := model.ParseScope(consentStr); err == nil {
					consents = append(consents, scope)
				}
			}
			if len(consents) > 0 {
				s.Set(internal.SessionKeyScopeConsented, consents)
			} else {
				slog.Debug("logged but consents is invalid", "user_id", uid, "redirect", internal.PathAuth)
				w.Header().Set("Location", internal.PathAuth)
				w.WriteHeader(http.StatusFound)
				return
			}
		} else if _, ok = s.Get(internal.SessionKeyScopeConsented); !ok {
			slog.Debug("logged but not consented", "user_id", uid, "redirect", internal.PathAuth)
			w.Header().Set("Location", internal.PathAuth)
			w.WriteHeader(http.StatusFound)
			return
		}
		if err = s.Save(); err != nil {
			slog.Error("error when saving session", "err", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		err = srv.HandleAuthorizeRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	}
}
