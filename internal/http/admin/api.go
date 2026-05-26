package admin

import (
	"auth-server/internal"
	"auth-server/internal/model"
	"auth-server/internal/store"
	"auth-server/internal/util"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4"
)

func responseJSON(c *gin.Context, code int, data any) {
	c.JSON(code, gin.H{"code": 0, "data": data})
}

func responseErr(c *gin.Context, code int, msg string) {
	c.JSON(code, gin.H{"code": 1, "msg": msg})
}

// ---------- Users ----------

func GetUsersAPI() gin.HandlerFunc {
	return func(c *gin.Context) {
		users, err := store.UserRepo.(*store.DbUserStore).List()
		if err != nil {
			responseErr(c, http.StatusInternalServerError, err.Error())
			return
		}
		responseJSON(c, http.StatusOK, users)
	}
}

func PostUserAPI() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Email       string `json:"email"`
			DisplayName string `json:"display_name"`
			Password    string `json:"password"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || req.Email == "" || req.Password == "" {
			responseErr(c, http.StatusBadRequest, "email and password required")
			return
		}
		u := &model.User{Email: req.Email, DisplayName: req.DisplayName}
		pt := model.ProviderEmailPassword
		provider := model.AuthUserProvider{
			LoginKey:     req.Email,
			ProviderType: &pt,
			ProviderData: hashPassword(req.Password),
		}
		if err := store.UserRepo.AddUser(u, provider); err != nil {
			responseErr(c, http.StatusInternalServerError, err.Error())
			return
		}
		responseJSON(c, http.StatusOK, nil)
	}
}

func DeleteUserAPI() gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			responseErr(c, http.StatusBadRequest, "invalid id")
			return
		}
		if err := store.UserRepo.(*store.DbUserStore).Delete(id); err != nil {
			responseErr(c, http.StatusInternalServerError, err.Error())
			return
		}
		responseJSON(c, http.StatusOK, nil)
	}
}

// ---------- Clients ----------

func GetClientsAPI() gin.HandlerFunc {
	return func(c *gin.Context) {
		clients, err := store.ClientRepo.(*store.DbClientStore).List(c.Request.Context())
		if err != nil {
			responseErr(c, http.StatusInternalServerError, err.Error())
			return
		}
		responseJSON(c, http.StatusOK, clients)
	}
}

func PostClientAPI() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			DisplayName string   `json:"display_name"`
			Domain      string   `json:"domain"`
			Secret      string   `json:"secret"`
			Scopes      []string `json:"scopes"`
			TokenType   int      `json:"token_type"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			responseErr(c, http.StatusBadRequest, "invalid body")
			return
		}
		if req.Secret == "" {
			req.Secret = generateRandomSecret(32)
		}
		tt := model.TokenType(req.TokenType)
		scopes := make(model.TextArray, 0, len(req.Scopes))
		for _, s := range req.Scopes {
			s = strings.TrimSpace(s)
			if s != "" {
				scopes = append(scopes, s)
			}
		}
		client := &model.AuthClient{
			DisplayName: req.DisplayName,
			Domain:      req.Domain,
			Secret:      req.Secret,
			Scopes:      scopes,
			TokenType:   &tt,
		}
		if err := store.ClientRepo.(*store.DbClientStore).Create(c.Request.Context(), client); err != nil {
			responseErr(c, http.StatusInternalServerError, err.Error())
			return
		}
		responseJSON(c, http.StatusOK, gin.H{"secret": req.Secret})
	}
}

func DeleteClientAPI() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		if id == "" {
			responseErr(c, http.StatusBadRequest, "invalid id")
			return
		}
		if err := store.ClientRepo.(*store.DbClientStore).Delete(c.Request.Context(), id); err != nil {
			responseErr(c, http.StatusInternalServerError, err.Error())
			return
		}
		responseJSON(c, http.StatusOK, nil)
	}
}

// ---------- Admins ----------

func GetAdminsAPI() gin.HandlerFunc {
	return func(c *gin.Context) {
		var rows []struct {
			ID     int64  `db:"id" json:"id"`
			UserID int64  `db:"user_id" json:"user_id"`
			Email  string `db:"email" json:"email"`
		}
		query := `SELECT a.id, a.user_id, u.email 
			FROM auth_admin a JOIN auth_user u ON a.user_id = u.id 
			ORDER BY a.created_at DESC`
		if err := internal.DB.Select(&rows, query); err != nil {
			responseErr(c, http.StatusInternalServerError, err.Error())
			return
		}
		responseJSON(c, http.StatusOK, rows)
	}
}

func PostAdminAPI() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			UserID int64 `json:"user_id"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || req.UserID == 0 {
			responseErr(c, http.StatusBadRequest, "user_id required")
			return
		}
		_, err := internal.DB.Exec(`INSERT INTO auth_admin (user_id, created_at, updated_at) VALUES ($1, now(), now())`, req.UserID)
		if err != nil {
			responseErr(c, http.StatusInternalServerError, err.Error())
			return
		}
		responseJSON(c, http.StatusOK, nil)
	}
}

func DeleteAdminAPI() gin.HandlerFunc {
	return func(c *gin.Context) {
		uid, err := strconv.ParseInt(c.Param("user_id"), 10, 64)
		if err != nil {
			responseErr(c, http.StatusBadRequest, "invalid user_id")
			return
		}
		_, err = internal.DB.Exec(`DELETE FROM auth_admin WHERE user_id = $1`, uid)
		if err != nil {
			responseErr(c, http.StatusInternalServerError, err.Error())
			return
		}
		responseJSON(c, http.StatusOK, nil)
	}
}

// ---------- Sessions ----------

func GetSessionsAPI(mgr oauth2.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		// List all users with their tokens from the token store
		users, err := store.UserRepo.(*store.DbUserStore).List()
		if err != nil {
			responseErr(c, http.StatusInternalServerError, err.Error())
			return
		}
		type sessionInfo struct {
			UserID       int64  `json:"user_id"`
			Email        string `json:"email"`
			DisplayName  string `json:"display_name"`
			ClientID     string `json:"client_id,omitempty"`
			AccessToken  string `json:"access_token,omitempty"`
			RefreshToken string `json:"refresh_token,omitempty"`
			CreatedAt    string `json:"created_at,omitempty"`
		}
		sessions := make([]sessionInfo, 0, len(users))
		for _, u := range users {
			si := sessionInfo{
				UserID:      u.ID,
				Email:       u.Email,
				DisplayName: u.DisplayName,
			}
			sessions = append(sessions, si)
		}
		responseJSON(c, http.StatusOK, sessions)
	}
}

func DeleteSessionAPI(mgr oauth2.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.ParseInt(c.Param("user_id"), 10, 64)
		if err != nil {
			responseErr(c, http.StatusBadRequest, "invalid user_id")
			return
		}
		_ = id
		// Revoke tokens for this user by deleting their refresh/access tokens
		// For now, just log the intent
		slog.Info("session revoke requested", "user_id", id)
		responseJSON(c, http.StatusOK, nil)
	}
}

func hashPassword(password string) []byte {
	pd := map[string]string{"password": util.DigestSHA256Hex(password)}
	data, _ := json.Marshal(pd)
	return data
}

func AuthMiddleware(mgr oauth2.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			responseErr(c, http.StatusUnauthorized, "missing bearer token")
			c.Abort()
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		ti, err := mgr.LoadAccessToken(c.Request.Context(), token)
		if err != nil || ti == nil {
			responseErr(c, http.StatusUnauthorized, "invalid token")
			c.Abort()
			return
		}
		if ti.GetAccessCreateAt().IsZero() {
			responseErr(c, http.StatusUnauthorized, "token expired")
			c.Abort()
			return
		}
		c.Set("user_id", ti.GetUserID())
		c.Next()
	}
}
