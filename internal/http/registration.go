package http

import (
	"auth-server/internal"
	"auth-server/internal/model"
	"auth-server/internal/store"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-session/session"
)

type regReq struct {
	ProviderType model.ProviderType `json:"provider_type,omitempty"`
	Data         json.RawMessage    `json:"data,omitempty"`
	CfToken      string             `json:"cf_token,omitempty"`
}

type emailRegData struct {
	Email string `json:"email"`
}

func getRegistrationHandler(_ *server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionStore, err := session.Start(r.Context(), w, r)
		if err != nil {
			responseJson(w, 1, err)
			return
		}
		if r.Method == http.MethodPost {
			handleJsonReg(w, r, sessionStore)
		} else if r.Method == http.MethodGet {
			handleRegPage(w, sessionStore)
		}
	}
}

func handleJsonReg(w http.ResponseWriter, r *http.Request, s session.Store) {
	ip := getIp(r)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		responseJson(w, 1, err)
		return
	}
	req := regReq{}
	_ = json.Unmarshal(body, &req)
	if err = verifyRequest(req.CfToken, ip); err != nil {
		responseJson(w, 1, err)
		return
	}
	tgData, ok := s.Get(internal.SessionKeyTelegramData)
	if !ok {
		responseJson(w, 1, "failed to read user data")
		return
	}
	tgUser := tgData.(model.TelegramUser)
	bytes, _ := json.Marshal(tgUser)

	erd := emailRegData{}
	_ = json.Unmarshal(req.Data, &erd)
	if erd.Email == "" {
		slog.Warn("failed to get user email")
		responseJson(w, 1, "email is required")
		return
	}

	p := model.ProviderTelegram
	now := time.Now()
	baseModel := model.BaseModel{
		CreatedAt: &now,
		UpdatedAt: &now,
	}
	userProvider := model.AuthUserProvider{
		LoginKey:     strconv.FormatInt(tgUser.Id, 10),
		ProviderType: &p,
		ProviderData: bytes,
		BaseModel:    baseModel,
	}

	user := model.AuthUser{
		Email:       erd.Email,
		DisplayName: tgUser.Username,
		BaseModel:   baseModel,
	}

	err = store.UserRepo.AddUser(&user, userProvider)
	if err != nil {
		responseJson(w, 1, err)
		return
	}

	s.Delete(internal.SessionKeyTelegramData)

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"code": 0})
}

func handleRegPage(w http.ResponseWriter, s session.Store) {
	tgData, ok := s.Get(internal.SessionKeyTelegramData)
	if !ok {
		http.Error(w, "failed to read user data", http.StatusInternalServerError)
		return
	}
	_ = renderHtml(w, "registration.gohtml", 200, map[string]any{
		"tgData":   tgData,
		"site_key": internal.AuthServerConfig.Cloudflare.Turnstile.Key,
	})
}
