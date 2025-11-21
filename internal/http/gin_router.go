package http

import (
	"auth-server/internal"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-session/session/v3"
)

// CreateGinEngine builds a gin.Engine replacing the previous net/http mux.
// Gradually wraps existing handler funcs to reduce refactor impact.
func CreateGinEngine(srv *server.Server) *gin.Engine {
	r := gin.New()
	// discard default gin text logger, we use slog
	gin.DefaultWriter = io.Discard
	gin.DefaultErrorWriter = io.Discard
	r.Use(gin.Recovery())
	r.Use(ginSlogLogger())

	// keep previous session expiration behavior (15 minutes)
	session.SetExpired(15 * 60)
	r.Use(func(c *gin.Context) {
		// touch session to ensure middleware order doesn't break later usage
		// (lazy start in handlers still works; this is a placeholder for future auth middleware)
		c.Next()
	})

	// Root & static placeholder
	r.GET("/", gin.WrapF(indexHandler))

	// Auth related
	loginHandler := getLoginHandler()
	r.GET(internal.PathLogin, loginHandler)
	r.POST(internal.PathLogin, loginHandler)
	r.GET(internal.PathAuthorize, gin.WrapF(getAuthorizeHandler(srv)))
	r.POST(internal.PathAuthorize, gin.WrapF(getAuthorizeHandler(srv)))
	r.GET(internal.PathAuth, gin.WrapF(getAuthHandler()))
	r.POST(internal.PathToken, gin.WrapF(getTokenHandler(srv)))
	r.POST(internal.PathIntrospect, gin.WrapF(getIntrospectHandler(srv)))
	r.POST(internal.PathUserinfo, gin.WrapF(getUserinfoHandler(srv)))
	r.GET(internal.PathJwkSet, gin.WrapF(jwkSetHandler))
	r.GET(internal.PathRegistration, gin.WrapF(getRegistrationHandler(srv)))
	r.POST(internal.PathRegistration, gin.WrapF(getRegistrationHandler(srv)))

	// Admin routes
	adminGroup := r.Group("/admin")
	adminGroup.Use(adminAuthMiddleware())
	{
		adminGroup.GET("/client", gin.WrapF(getAdminClientsHandler()))
		adminGroup.POST("/client/new", gin.WrapF(postAdminClientNewHandler()))
		adminGroup.POST("/client/del", gin.WrapF(postAdminClientDelHandler()))

		adminGroup.GET("/accounts", gin.WrapF(getAdminAccountsHandler()))
		adminGroup.POST("/accounts/new", gin.WrapF(postAdminAccountNewHandler()))
		adminGroup.POST("/accounts/del", gin.WrapF(postAdminAccountDelHandler()))
	}

	// 404 fallback
	r.NoRoute(func(c *gin.Context) {
		c.String(http.StatusNotFound, "Not Found")
	})

	return r
}

// ginSlogLogger provides structured logging via slog.
func ginSlogLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		rawQuery := c.Request.URL.RawQuery
		method := c.Request.Method
		clientIP := c.ClientIP()
		uaShort, uaHash, uaLen := compactUA(c.Request.UserAgent())
		c.Next()
		latency := time.Since(start)
		status := c.Writer.Status()
		size := c.Writer.Size()
		var errMsg string
		if len(c.Errors) > 0 {
			errMsg = c.Errors.String()
		}
		if rawQuery != "" {
			path = path + "?" + rawQuery
		}
		level := slog.LevelInfo
		if status >= 500 {
			level = slog.LevelError
		} else if status >= 400 {
			level = slog.LevelWarn
		}
		slog.Log(c, level, "http_request",
			"status", status,
			"method", method,
			"path", path,
			"ip", clientIP,
			// Compact UA to avoid excessively long log lines while keeping correlation
			"ua", uaShort,
			"ua_len", uaLen,
			"ua_hash", uaHash,
			"latency_ms", latency.Milliseconds(),
			"resp_bytes", size,
			"err", errMsg,
		)
	}
}

// maxUALength caps the length of the UA string recorded in logs.
const maxUALength = 128

// compactUA returns a truncated UA (at most maxUALength runes),
// a short stable hash for correlation, and the original length.
func compactUA(ua string) (short string, hash string, length int) {
	length = len(ua)
	// Stable short hash (first 8 bytes of sha256 => 16 hex chars)
	sum := sha256.Sum256([]byte(ua))
	hash = hex.EncodeToString(sum[:8])

	// Truncate by runes to avoid breaking multibyte characters
	r := []rune(ua)
	if len(r) > maxUALength {
		short = string(r[:maxUALength]) + "…"
	} else {
		short = ua
	}
	return
}
