package http

import (
	"auth-server/internal"
	"auth-server/internal/model"
	storeImpl "auth-server/internal/store"
	"auth-server/internal/util"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"

	"github.com/go-session/session"
)

type loginReq struct {
	ProviderType *model.ProviderType `json:"provider_type,omitempty"`
	LoginKey     string              `json:"login_key,omitempty"`
	Data         json.RawMessage     `json:"data,omitempty"`
	CfToken      string              `json:"cf_token,omitempty"`
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	sessionStore, err := session.Start(r.Context(), w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodPost {
		handleJsonLogin(w, r, sessionStore)
	} else if r.Method == http.MethodGet {
		handleLoginPage(w, sessionStore)
	}
}

func handleLoginPage(w http.ResponseWriter, s session.Store) {
	_, ok := s.Get(internal.SessionKeyUserID)
	if ok {
		w.Header().Set("Location", internal.PathAuth)
		w.WriteHeader(http.StatusFound)
		return
	}
	cid, ok := s.Get(internal.SessionKeyClientID)
	if !ok {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	_ = renderLoginPage(w, cid.(string), http.StatusUnauthorized, nil)
}

func handleJsonLogin(w http.ResponseWriter, r *http.Request, s session.Store) {
	w.Header().Set("Content-Type", "application/json")
	b, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 1})
		return
	}
	req := loginReq{}
	_ = json.Unmarshal(b, &req)
	remoteIp := getIp(r)
	if err := verifyRequest(req.CfToken, remoteIp); err != nil {
		slog.Warn("failed to verify request", "user_addr", remoteIp)
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 1})
		return
	}
	userInfo, err := storeImpl.UserRepo.GetUserByCredentials(req.LoginKey, req.ProviderType, req.Data, s)
	if err != nil {
		slog.Warn("failed to verify credentials", "loginKey", req.LoginKey, "provider", req.ProviderType)
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 1})
		return
	}
	if userInfo == nil {
		slog.Warn("unregistered credential", "loginKey", req.LoginKey, "provider", req.ProviderType)
		if *req.ProviderType == model.ProviderTelegram {
			botTokenDigest := util.DigestSHA256(internal.AuthServerConfig.Telegram.BotToken)
			if !util.ValidateTelegramCredential(req.Data, botTokenDigest) {
				slog.Warn("Invalid Telegram Credentials")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"code": 1,
					"err":  "Invalid Telegram Credentials",
				})
				return
			}
			tgUser := model.TelegramUser{}
			_ = json.Unmarshal(req.Data, &tgUser)
			s.Set(internal.SessionKeyTelegramData, tgUser)
			if err = s.Save(); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"code": 1,
					"err":  err,
				})
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		err = json.NewEncoder(w).Encode(map[string]any{
			"code": 0,
			"data": map[string]any{"user": nil},
		})
		return
	}
	s.Set(internal.SessionKeyUserID, userInfo.GetID())
	_ = s.Save()

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"code": 0,
		"data": map[string]any{
			"user": userInfo,
		},
	})
}

func getIp(r *http.Request) string {
	remoteIp := r.Header.Get("CF-Connecting-IP")
	if remoteIp == "" {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		remoteIp = host
	}
	return remoteIp
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
