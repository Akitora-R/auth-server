package http

import (
	"auth-server/internal"
	"auth-server/internal/model"
	"auth-server/internal/store"
	"encoding/json"
	"fmt"
	"html/template"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
)

var tpl = template.Must(template.New("").ParseGlob("template/*"))

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

func renderHtml(w http.ResponseWriter, tplName string, code int, data any) error {
	w.WriteHeader(code)
	return tpl.ExecuteTemplate(w, tplName, data)
}

func responseJson(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	if code == 0 {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"code": code, "data": data})
}

// ================= Admin: Clients =================

type adminClientPageData struct {
	Clients      []model.AuthClient
	ErrorMsg     string
	ShowAdminNav bool
}

func getAdminClientsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clients, err := store.ClientRepo.(*store.DbClientStore).List(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("failed to load clients"))
			return
		}
		_ = renderHtml(w, "admin_clients.gohtml", http.StatusOK, adminClientPageData{Clients: clients, ShowAdminNav: true})
	}
}

func postAdminClientNewHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("invalid form"))
			return
		}
		name := r.FormValue("display_name")
		domain := r.FormValue("domain")
		scopesStr := r.FormValue("scopes")
		secret := r.FormValue("secret")
		tokenTypeStr := r.FormValue("token_type")
		if secret == "" {
			secret = generateRandomSecret(32)
		}
		ttInt, _ := strconv.Atoi(tokenTypeStr)
		tt := model.TokenType(ttInt)
		scopes := []string{}
		for _, s := range strings.Split(scopesStr, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				scopes = append(scopes, s)
			}
		}
		c := &model.AuthClient{DisplayName: name, Domain: domain, Secret: secret, Scopes: scopes, TokenType: &tt}
		if err := store.ClientRepo.(*store.DbClientStore).Create(r.Context(), c); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("create failed: " + err.Error()))
			return
		}
		http.Redirect(w, r, internal.PathAdminClients, http.StatusFound)
	}
}

func postAdminClientDelHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		id := r.FormValue("id")
		if id != "" {
			_ = store.ClientRepo.(*store.DbClientStore).Delete(r.Context(), id)
		}
		http.Redirect(w, r, internal.PathAdminClients, http.StatusFound)
	}
}

// simple random secret generator (non-crypto for admin convenience)
func generateRandomSecret(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := range b {
		b[i] = letters[r.Intn(len(letters))]
	}
	return string(b)
}
