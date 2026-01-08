package admin

import (
	"auth-server/internal"
	"auth-server/internal/model"
	"auth-server/internal/util"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-session/session/v3"
)

// AuthMiddleware checks if the user is an admin.
func AuthMiddleware() gin.HandlerFunc {
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
