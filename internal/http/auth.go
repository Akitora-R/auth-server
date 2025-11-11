package http

import (
	"auth-server/internal"
	"auth-server/internal/model"
	storeImpl "auth-server/internal/store"
	"net/http"

	"github.com/gin-gonic/gin"
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
		data["scopeRequested"] = scopes
		// 将用户信息注入模板，便于展示昵称/邮箱等
		sessionUser := uVal.(*model.SessionUserInfo)
		data["user"] = sessionUser.User
		data["sessionUser"] = sessionUser

		_ = renderHtml(w, "auth.gohtml", 200, data)
	}
}

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

		sessionUser, ok := uVal.(*model.SessionUserInfo)
		if !ok || sessionUser.User == nil {
			c.Redirect(http.StatusFound, internal.PathLogin+"?next="+internal.NextAdmin)
			c.Abort()
			return
		}

		if !sessionUser.User.HasRole("admin") {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "you don't have permission to access this page"})
			return
		}

		c.Next()
	}
}
