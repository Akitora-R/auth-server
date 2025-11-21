package http

import (
	"auth-server/internal"
	"auth-server/internal/model"
	"auth-server/internal/store"
	"auth-server/internal/util"
	"encoding/json"
	"log/slog"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-session/session/v3"
)

// ================= Admin: Middleware =================

func adminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		store, err := session.Start(c.Request.Context(), c.Writer, c.Request)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to start session"})
			return
		}

		uVal, ok := store.Get(internal.SessionKeyUserID)
		if !ok {
			c.Redirect(http.StatusFound, internal.PathLogin+"?next="+internal.NextAdmin)
			c.Abort()
			return
		}

		var su *model.SessionUserInfo = nil
		if su, err = util.MapToStruct[*model.SessionUserInfo](uVal.(map[string]any)); err != nil {
			slog.Error("failed to parse session user info", "err", err)
			c.Redirect(http.StatusFound, internal.PathLogin+"?next="+internal.NextAdmin)
			c.Abort()
			return
		}

		if !su.User.HasRole("admin") {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "you don't have permission to access this page"})
			return
		}

		c.Next()
	}
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

// ================= Admin: Accounts =================

type adminAccountPageData struct {
	Accounts     []model.User
	ErrorMsg     string
	ShowAdminNav bool
}

func getAdminAccountsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, err := store.UserRepo.(*store.DbUserStore).List()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("failed to load users: " + err.Error()))
			return
		}
		_ = renderHtml(w, "admin_accounts.gohtml", http.StatusOK, adminAccountPageData{Accounts: users, ShowAdminNav: true})
	}
}

func postAdminAccountNewHandler() http.HandlerFunc {
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
		email := r.FormValue("email")
		displayName := r.FormValue("display_name")
		password := r.FormValue("password")

		if email == "" || password == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("email and password required"))
			return
		}

		u := &model.User{
			Email:       email,
			DisplayName: displayName,
		}

		pData := map[string]string{"password": util.DigestSHA256Hex(password)}
		pDataBytes, _ := json.Marshal(pData)

		pt := model.ProviderEmailPassword
		provider := model.AuthUserProvider{
			LoginKey:     email,
			ProviderType: &pt,
			ProviderData: pDataBytes,
		}

		if err := store.UserRepo.AddUser(u, provider); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("create failed: " + err.Error()))
			return
		}
		http.Redirect(w, r, "/admin/accounts", http.StatusFound)
	}
}

func postAdminAccountDelHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		idStr := r.FormValue("id")
		id, _ := strconv.ParseInt(idStr, 10, 64)
		if id != 0 {
			_ = store.UserRepo.(*store.DbUserStore).Delete(id)
		}
		http.Redirect(w, r, "/admin/accounts", http.StatusFound)
	}
}
