package admin

import (
	"auth-server/internal/model"
	"auth-server/internal/render"
	"auth-server/internal/store"
	"auth-server/internal/util"
	"encoding/json"
	"net/http"
	"strconv"
)

type adminAccountPageData struct {
	Accounts     []model.User
	ErrorMsg     string
	ShowAdminNav bool
}

func GetAccounts() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, err := store.UserRepo.(*store.DbUserStore).List()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("failed to load users: " + err.Error()))
			return
		}
		_ = render.Html(w, "admin_accounts.gohtml", http.StatusOK, adminAccountPageData{Accounts: users, ShowAdminNav: true})
	}
}

func PostAccountNew() http.HandlerFunc {
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

func PostAccountDel() http.HandlerFunc {
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
