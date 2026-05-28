package http

import (
	"auth-server/internal"
	"auth-server/internal/model"
	storeImpl "auth-server/internal/store"
	"auth-server/internal/util"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-session/session/v3"
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
			handleUnauthenticated(w, r, s)
			return
		}

		if handleAuthenticated(w, r, s, uid) {
			err = srv.HandleAuthorizeRequest(w, r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
			}
		}
	}
}

func handleUnauthenticated(w http.ResponseWriter, r *http.Request, s session.Store) {
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
	s.Set(internal.SessionKeyState, r.FormValue("state"))
	s.Set(internal.SessionKeyCodeChallenge, r.FormValue("code_challenge"))
	if err = s.Save(); err != nil {
		slog.Error("error when saving session", "err", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Location", internal.PathLogin)
	w.WriteHeader(http.StatusFound)
}

func handleAuthenticated(w http.ResponseWriter, r *http.Request, s session.Store, uid any) bool {
	var sessionUser *model.SessionUserInfo
	if v, ok := uid.(map[string]any); ok {
		var err error
		sessionUser, err = util.MapToStruct[*model.SessionUserInfo](v)
		if err != nil {
			slog.Error("failed to parse session user info", "err", err)
			http.Error(w, "failed to parse session user info", http.StatusInternalServerError)
			return false
		}
	} else {
		slog.Error("invalid session user info type", "type", fmt.Sprintf("%T", uid))
		http.Error(w, "invalid session user info type", http.StatusInternalServerError)
		return false
	}
	slog.Info("logging for logged user", "user_id", sessionUser.User.ID)

	if consented := r.Form["consented"]; len(consented) > 0 {
		var consents []*model.ScopeInfo
		for _, consentStr := range consented {
			if scope, err := model.ParseScope(consentStr); err == nil {
				consents = append(consents, &scope)
			}
		}
		if len(consents) > 0 {
			s.Set(internal.SessionKeyScopeConsented, consents)
		} else {
			slog.Debug("logged but consents is invalid", "user_id", uid, "redirect", internal.PathAuth)
			w.Header().Set("Location", internal.PathAuth)
			w.WriteHeader(http.StatusFound)
			return false
		}
	} else if _, ok := s.Get(internal.SessionKeyScopeConsented); !ok {
		slog.Debug("logged but not consented", "user_id", sessionUser.User.ID, "redirect", internal.PathAuth)
		w.Header().Set("Location", internal.PathAuth)
		w.WriteHeader(http.StatusFound)
		return false
	}
	if err := s.Save(); err != nil {
		slog.Error("error when saving session", "err", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}
