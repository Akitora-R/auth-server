package http

import (
	"auth-server/internal"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-resty/resty/v2"
	"github.com/go-session/session"
)

var tpl = template.Must(template.New("").ParseGlob("template/*"))

type AuthHandler func(srv *server.Server) http.HandlerFunc

// var authHandlers = map[string]AuthHandler{}

func CreateMux(srv *server.Server) *http.ServeMux {
	session.SetExpired(15 * 60)
	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc(internal.PathLogin, loginHandler)
	mux.HandleFunc(internal.PathAuth, getAuthHandler())
	mux.HandleFunc(internal.PathAuthorize, getAuthorizeHandler(srv))
	mux.HandleFunc(internal.PathToken, getTokenHandler(srv))
	mux.HandleFunc(internal.PathIntrospect, getIntrospectHandler(srv))
	mux.HandleFunc(internal.PathUserinfo, getUserinfoHandler(srv))
	mux.HandleFunc(internal.PathJwkSet, jwkSetHandler)
	mux.HandleFunc(internal.PathRegistration, getRegistrationHandler(srv))
	return mux
}

type TurnstileResp struct {
	Success     bool      `json:"success"`
	ErrorCodes  []string  `json:"error-codes"`
	ChallengeTs time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
}

func verifyRequest(token, ip string) error {
	response, err := resty.New().R().SetFormData(map[string]string{
		"secret":   internal.AuthServerConfig.Cloudflare.Turnstile.Secret,
		"response": token,
		"remoteip": ip,
	}).Post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
	if err != nil {
		return err
	}
	re := TurnstileResp{}
	if err = json.Unmarshal(response.Body(), &re); err != nil {
		return err
	}
	if !re.Success {
		return fmt.Errorf("%v", re.ErrorCodes)
	}
	return nil
}

func renderHtml(w http.ResponseWriter, tplName string, code int, data any) error {
	w.WriteHeader(code)
	return tpl.ExecuteTemplate(w, tplName, data)
}
