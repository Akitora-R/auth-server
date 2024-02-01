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
		TokenType:            "Bearer",
		AllowedResponseTypes: []oauth2.ResponseType{oauth2.Code, oauth2.Token},
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
		return
	}
	uid, ok := s.Get(sessionKeyUserID)
	if !ok {
		if r.Form == nil {
			_ = r.ParseForm()
		}
		clientID := r.Form.Get("client_id")
		ci, clientErr := storeImpl.ClientStore.GetByID(r.Context(), clientID)
		if clientErr != nil {
			err = clientErr
			return
		}
		if ci == nil {
			err = errors.New("invalid client id")
			return
		}
		s.Set(sessionKeyResponseType, r.Form.Get("response_type"))
		s.Set(sessionKeyScopeRequested, parseScopes(r.FormValue("scope")))
		s.Set(sessionKeyClientID, clientID)
		if err = s.Save(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Location", pathLogin)
		w.WriteHeader(http.StatusFound)
		return
	}
	if consented := r.Form["consented"]; len(consented) > 0 {
		var consents []ScopeInfo
		for _, consentStr := range consented {
			if scope, err := parseScope(consentStr); err == nil {
				consents = append(consents, scope)
			}
		}
		if len(consents) > 0 {
			s.Set(sessionKeyScopeConsented, consents)
		}
	} else {
		w.Header().Set("Location", pathAuth)
		w.WriteHeader(http.StatusFound)
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
