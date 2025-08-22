package http

import (
	"auth-server/internal"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-session/session"
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
	r.GET(internal.PathLogin, gin.WrapF(loginHandler))
	r.POST(internal.PathLogin, gin.WrapF(loginHandler))
	r.GET(internal.PathAuthorize, gin.WrapF(getAuthorizeHandler(srv)))
	r.POST(internal.PathAuthorize, gin.WrapF(getAuthorizeHandler(srv)))
	r.GET(internal.PathAuth, gin.WrapF(getAuthHandler()))
	r.POST(internal.PathToken, gin.WrapF(getTokenHandler(srv)))
	r.POST(internal.PathIntrospect, gin.WrapF(getIntrospectHandler(srv)))
	r.POST(internal.PathUserinfo, gin.WrapF(getUserinfoHandler(srv)))
	r.GET(internal.PathJwkSet, gin.WrapF(jwkSetHandler))
	r.GET(internal.PathRegistration, gin.WrapF(getRegistrationHandler(srv)))
	r.POST(internal.PathRegistration, gin.WrapF(getRegistrationHandler(srv)))

	// Admin clients
	r.GET(internal.PathAdminClients, gin.WrapF(getAdminClientsHandler()))
	r.POST(internal.PathAdminClientNew, gin.WrapF(postAdminClientNewHandler()))
	r.POST(internal.PathAdminClientDel, gin.WrapF(postAdminClientDelHandler()))

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
		ua := c.Request.UserAgent()
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
			"ua", ua,
			"latency_ms", latency.Milliseconds(),
			"resp_bytes", size,
			"err", errMsg,
		)
	}
}
