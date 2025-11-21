package admin

import (
	"auth-server/internal"
	"auth-server/internal/model"
	"auth-server/internal/render"
	"auth-server/internal/store"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type adminClientPageData struct {
	Clients      []model.AuthClient
	ErrorMsg     string
	ShowAdminNav bool
}

func GetClients() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clients, err := store.ClientRepo.(*store.DbClientStore).List(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("failed to load clients"))
			return
		}
		_ = render.Html(w, "admin_clients.gohtml", http.StatusOK, adminClientPageData{Clients: clients, ShowAdminNav: true})
	}
}

func PostClientNew() http.HandlerFunc {
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

func PostClientDel() http.HandlerFunc {
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
