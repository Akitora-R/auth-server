package oauth2

import (
	"auth-server/internal"
	"auth-server/internal/model"
	storeImpl "auth-server/internal/store"
	"encoding/json"
	"fmt"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-resty/resty/v2"
	"github.com/go-session/session"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"time"
)

const (
	sessionKeyUserID         = "LoggedInUserID"
	sessionKeyClientID       = "ClientID"
	sessionKeyScopeRequested = "scopeRequested"
	sessionKeyScopeConsented = "scopeConsented"
	sessionKeyResponseType   = "responseType"
	pathLogin                = "/login"
	pathAuth                 = "/auth"
	pathAuthorize            = "/oauth2/authorize"
	pathJwkSet               = "/.well-known/jwks.json"
	placeholderFile          = "placeholder.jpg"
)

var tpl = template.Must(template.New("").ParseGlob("template/*"))

func InitRoute(srv *server.Server) {
	session.SetExpired(15 * 60)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := os.Stat(placeholderFile)
		if os.IsNotExist(err) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("UwU"))
		} else {
			w.Header().Set("Content-Type", "image/jpeg")
			http.ServeFile(w, r, placeholderFile)
		}
	})
	http.HandleFunc(pathLogin, loginHandler)
	http.HandleFunc(pathAuth, authHandler)
	http.HandleFunc(pathAuthorize, func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Authorize Request", "remote", r.RemoteAddr)
		s, err := session.Start(r.Context(), w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = r.ParseForm()
		uid, ok := s.Get(sessionKeyUserID)
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
			s.Set(sessionKeyResponseType, r.Form.Get("response_type"))
			s.Set(sessionKeyScopeRequested, model.ParseScopes(r.FormValue("scope")))
			s.Set(sessionKeyClientID, clientID)
			if err = s.Save(); err != nil {
				slog.Error("error when saving session", "err", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Location", pathLogin)
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
				s.Set(sessionKeyScopeConsented, consents)
			} else {
				slog.Debug("logged but consents is invalid", "user_id", uid, "redirect", pathAuth)
				w.Header().Set("Location", pathAuth)
				w.WriteHeader(http.StatusFound)
				return
			}
		} else if _, ok = s.Get(sessionKeyScopeConsented); !ok {
			slog.Debug("logged but not consented", "user_id", uid, "redirect", pathAuth)
			w.Header().Set("Location", pathAuth)
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
	})

	http.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		err := srv.HandleTokenRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		username, password, ok := r.BasicAuth()
		if !ok {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request", "error_description": "Missing client authentication"})
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		cli, err := srv.Manager.GetClient(r.Context(), username)
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client", "error_description": "AuthClient authentication failed"})
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if cli.GetSecret() != password {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client", "error_description": "AuthClient authentication failed"})
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		_ = r.ParseMultipartForm(1 << 20)
		token := r.PostForm.Get("token")
		if token == "" {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request", "error_description": "Token parameter is missing"})
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		ti, err := srv.Manager.LoadAccessToken(r.Context(), token)
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_token", "error_description": "Token is invalid or expired"})
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		m := map[string]any{
			"active": true,
			"sub":    ti.GetUserID(),
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(m)
	})

	http.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		token, err := srv.ValidationBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		data := map[string]any{
			"expires_in": int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds()),
			"client_id":  token.GetClientID(),
			"sub":        token.GetUserID(),
		}
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		_ = e.Encode(data)
	})
	http.HandleFunc(pathJwkSet, func(w http.ResponseWriter, r *http.Request) {
		var keys []map[string]string
		for _, key := range JWTKeys {
			keys = append(keys, key.ToJWK())
		}

		jwks := map[string]interface{}{
			"keys": keys,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	sessionStore, err := session.Start(r.Context(), w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodPost {
		handleFormLogin(w, r, sessionStore)
	} else if r.Method == http.MethodGet {
		handleLoginPage(w, sessionStore)
	}
}

func handleFormLogin(w http.ResponseWriter, r *http.Request, s session.Store) {
	if _, ok := s.Get(sessionKeyClientID); !ok {
		_ = s.Flush()
		http.Error(w, "invalid_client_id", http.StatusBadRequest)
		return
	}
	if r.Form == nil {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	email := r.Form.Get("email")
	password := r.Form.Get("password")
	if err := verifyRequest(r.Form.Get("cf-turnstile-response"), r.Header.Get("CF-Connecting-IP")); err != nil {
		get, _ := s.Get(sessionKeyClientID)
		_ = renderLoginPage(w, get.(string), http.StatusUnauthorized, err)
		return
	}
	d, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})
	userInfo, _, err := storeImpl.UserRepo.GetUserByCredentials(email, model.ProviderEmailPassword, d)
	if err != nil {
		get, _ := s.Get(sessionKeyClientID)
		_ = renderLoginPage(w, get.(string), http.StatusUnauthorized, err)
		return
	}
	s.Set(sessionKeyUserID, userInfo.GetID())
	_ = s.Save()

	w.Header().Set("Location", "/auth")
	w.WriteHeader(http.StatusFound)
}

type TurnstileResp struct {
	Success     bool      `json:"success"`
	ErrorCodes  []string  `json:"error-codes"`
	ChallengeTs time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
}

func verifyRequest(token, ip string) error {
	response, err := resty.New().R().SetFormData(map[string]string{
		"secret":   internal.AuthServerConfig.Cloudflare.Turnstile.Secret,
		"response": token,
		"remoteip": ip,
	}).Post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
	if err != nil {
		return err
	}
	re := TurnstileResp{}
	if err = json.Unmarshal(response.Body(), &re); err != nil {
		return err
	}
	if !re.Success {
		return fmt.Errorf("%v", re.ErrorCodes)
	}
	return nil
}

func handleLoginPage(w http.ResponseWriter, s session.Store) {
	_, ok := s.Get(sessionKeyUserID)
	if ok {
		w.Header().Set("Location", pathAuth)
		w.WriteHeader(http.StatusFound)
		return
	}
	cid, ok := s.Get(sessionKeyClientID)
	if !ok {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	_ = renderLoginPage(w, cid.(string), http.StatusUnauthorized, nil)
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	s, err := session.Start(r.Context(), w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, ok := s.Get(sessionKeyUserID); !ok {
		w.Header().Set("Location", pathLogin)
		w.WriteHeader(http.StatusFound)
		return
	}
	if _, ok := s.Get(sessionKeyScopeConsented); ok {
		w.Header().Set("Location", pathAuthorize)
		w.WriteHeader(http.StatusFound)
		return
	}

	cID, ok := s.Get(sessionKeyClientID)
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

	if rt, ok := s.Get(sessionKeyResponseType); !ok {
		http.Error(w, "failed to get response type", http.StatusInternalServerError)
		return
	} else {
		data["responseType"] = rt
	}
	if sci, ok := clientInfo.(model.ScopedClientInfo); ok {
		data["clientInfo"] = sci
	}
	scopes, ok := s.Get(sessionKeyScopeRequested)
	if !ok {
		http.Error(w, "failed to get requested scope", http.StatusInternalServerError)
		return
	}
	data["scopeRequested"] = scopes

	_ = renderHtml(w, "auth.gohtml", 200, data)
}

func renderLoginPage(w http.ResponseWriter, clientName string, code int, err error) error {
	data := map[string]any{
		"client_name": clientName,
		"site_key":    internal.AuthServerConfig.Cloudflare.Turnstile.Key,
		"bot_name":    internal.AuthServerConfig.Telegram.BotName,
	}
	if err != nil {
		data["err"] = err
	}
	return renderHtml(w, "login.gohtml", code, data)
}

func renderHtml(w http.ResponseWriter, tplName string, code int, data any) error {
	w.WriteHeader(code)
	return tpl.ExecuteTemplate(w, tplName, data)
}
