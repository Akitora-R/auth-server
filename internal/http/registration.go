package http

import (
	"auth-server/internal"
	"auth-server/internal/model"
	"auth-server/internal/render"
	"auth-server/internal/store"
	"auth-server/internal/util"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-session/session/v3"
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
			slog.Error("failed to start session", "error", err)
			responseJson(w, 1, err)
			return
		}
		if r.Method == http.MethodPost {
			handleJsonReg(w, r, sessionStore)
		} else if r.Method == http.MethodGet {
			handleRegPage(w, r, sessionStore)
		}
	}
}

func handleJsonReg(w http.ResponseWriter, r *http.Request, s session.Store) {
	ip := getIp(r)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		slog.Error("failed to read registration request body", "error", err, "ip", ip)
		responseJson(w, 1, err)
		return
	}
	req := regReq{}
	if err = json.Unmarshal(body, &req); err != nil {
		slog.Error("failed to unmarshal registration request", "error", err, "ip", ip)
		responseJson(w, 1, err)
		return
	}
	if err = verifyRequest(req.CfToken, ip); err != nil {
		slog.Warn("failed to verify turnstile request", "error", err, "ip", ip)
		responseJson(w, 1, "failed to verify turnstile request")
		return
	}
	tgData, ok := s.Get(internal.SessionKeyTelegramData)
	if !ok {
		slog.Warn("failed to read telegram user data from session", "ip", ip)
		responseJson(w, 1, "failed to read user data")
		return
	}
	tgUserMap, ok := tgData.(map[string]any)
	if !ok {
		slog.Error("failed to cast telegram user data", "ip", ip)
		responseJson(w, 1, "failed to read user data")
		return
	}
	tgUser, err := util.MapToStruct[*model.TelegramUser](tgUserMap)
	if err != nil {
		slog.Error("failed to cast telegram user data", "error", err, "ip", ip)
		responseJson(w, 1, "failed to read user data")
		return
	}
	bytes, _ := json.Marshal(tgUser)

	erd := emailRegData{}
	if err = json.Unmarshal(req.Data, &erd); err != nil {
		slog.Error("failed to unmarshal email registration data", "error", err, "ip", ip)
	}
	if erd.Email == "" {
		slog.Warn("email is missing in registration data", "ip", ip, "loginKey", tgUser.Id)
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

	user := model.User{
		Email:       erd.Email,
		DisplayName: tgUser.FirstName + " " + tgUser.Username,
	}

	err = store.UserRepo.AddUser(&user, userProvider)
	if err != nil {
		slog.Error("failed to add user to database", "error", err, "ip", ip, "loginKey", tgUser.Id, "email", user.Email)
		responseJson(w, 1, err)
		return
	}
	slog.Info("user registered successfully", "ip", ip, "loginKey", tgUser.Id, "email", user.Email)

	s.Delete(internal.SessionKeyTelegramData)

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"code": 0})
}

func handleRegPage(w http.ResponseWriter, r *http.Request, s session.Store) {
	tgData, ok := s.Get(internal.SessionKeyTelegramData)
	if !ok {
		slog.Warn("failed to read telegram user data from session on registration page", "ip", getIp(r))
		http.Error(w, "failed to read user data", http.StatusInternalServerError)
		return
	}
	_ = render.Html(w, "registration.gohtml", 200, map[string]any{
		"tgData":   tgData,
		"site_key": internal.AuthServerConfig.Cloudflare.Turnstile.Key,
	})
}
