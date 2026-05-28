package http

import (
	"auth-server/internal"
	"auth-server/internal/model"
	"auth-server/internal/render"
	storeImpl "auth-server/internal/store"
	"auth-server/internal/util"
	"net/http"

	"github.com/go-session/session/v3"
)

func getAuthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := session.Start(r.Context(), w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		uVal, ok := s.Get(internal.SessionKeyUserID)
		if !ok {
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
		scopeList, err := util.Decode[[]*model.Scope](scopes)
		if err != nil {
			http.Error(w, "failed to parse scopes", http.StatusInternalServerError)
			return
		}
		var scopeInfos []model.ScopeInfo
		for _, s := range scopeList {
			scopeInfos = append(scopeInfos, s)
		}
		data["scopeRequested"] = scopeInfos
		// inject user info into template
		var sessionUser *model.SessionUserInfo
		if v, ok := uVal.(map[string]any); ok {
			var err error
			sessionUser, err = util.MapToStruct[*model.SessionUserInfo](v)
			if err != nil {
				http.Error(w, "failed to parse session user info", http.StatusInternalServerError)
				return
			}
		} else {
			http.Error(w, "invalid session user info type", http.StatusInternalServerError)
			return
		}
		data["user"] = sessionUser.User
		data["sessionUser"] = sessionUser
		data["codeChallengeMethod"] = "S256"

		if state, ok := s.Get(internal.SessionKeyState); ok {
			data["state"] = state
		}
		if cc, ok := s.Get(internal.SessionKeyCodeChallenge); ok {
			data["codeChallenge"] = cc
		}

		_ = render.Html(w, "auth.gohtml", 200, data)
	}
}
