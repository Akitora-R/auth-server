package oauth2

import (
	storeImpl "auth-server/internal/store"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/go-session/session"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func InitServer() *server.Server {
	manager := manage.NewDefaultManager()

	// manage.DefaultAuthorizeCodeTokenCfg
	manager.SetAuthorizeCodeTokenCfg(&manage.Config{
		AccessTokenExp:    time.Hour * 2,
		RefreshTokenExp:   time.Hour * 24 * 3,
		IsGenerateRefresh: true,
	})

	// token store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// generate jwt access token
	// manager.MapAccessGenerate(generates.NewJWTAccessGenerate("", []byte("00000000"), jwt.SigningMethodHS512))
	manager.MapAccessGenerate(generates.NewAccessGenerate())

	manager.MapClientStorage(storeImpl.ClientStore)

	oauth2ServerConfig := server.Config{
		TokenType: "Bearer",
		AllowedResponseTypes: []oauth2.ResponseType{
			oauth2.Code,
			oauth2.Token,
		},
		AllowedGrantTypes: []oauth2.GrantType{
			oauth2.AuthorizationCode,
			oauth2.ClientCredentials,
			oauth2.Refreshing,
		},
		AllowedCodeChallengeMethods: []oauth2.CodeChallengeMethod{
			oauth2.CodeChallengePlain,
			oauth2.CodeChallengeS256,
		},
	}
	srv := server.NewServer(&oauth2ServerConfig, manager)
	srv.SetUserAuthorizationHandler(userAuthorizeHandler)
	srv.SetAuthorizeScopeHandler(scopeHandler)
	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		slog.Error("Internal Error", "err", err)
		return
	})
	srv.SetResponseErrorHandler(func(re *errors.Response) {
		slog.Error("Response Error", "err", re.Error.Error())
	})
	return srv
}

func userAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	s, err := session.Start(r.Context(), w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	uid, ok := s.Get(sessionKeyUserID)
	if !ok {
		http.Error(w, "failed to read session data", http.StatusInternalServerError)
		return
	}
	userID = strconv.FormatInt(uid.(int64), 10)
	return
}

func scopeHandler(w http.ResponseWriter, r *http.Request) (string, error) {
	s, err := session.Start(r.Context(), w, r)
	if err != nil {
		return "", err
	}
	consented, ok := s.Get(sessionKeyScopeConsented)
	if !ok {
		return "", errors.New("failed to get scope")
	}
	var scopeName []string
	for _, scopeInfo := range consented.([]ScopeInfo) {
		scopeName = append(scopeName, scopeInfo.GetName())
	}
	return strings.Join(scopeName, " "), nil
}
