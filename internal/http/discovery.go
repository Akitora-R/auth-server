package http

import (
	"auth-server/internal"
	"encoding/json"
	"fmt"
	"net/http"
)

func discoveryHandler(w http.ResponseWriter, r *http.Request) {
	host := internal.AuthServerConfig.Host
	port := internal.AuthServerConfig.Port
	issuer := fmt.Sprintf("http://%s:%d", host, port)
	// If port is 80 or 443, we might want to omit it in the issuer URL depending on deployment
	if port == 80 {
		issuer = fmt.Sprintf("http://%s", host)
	}

	metadata := map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + internal.PathAuthorize,
		"token_endpoint":                        issuer + internal.PathToken,
		"jwks_uri":                              issuer + internal.PathJwkSet,
		"userinfo_endpoint":                     issuer + internal.PathUserinfo,
		"introspection_endpoint":                issuer + internal.PathIntrospect,
		"response_types_supported":              []string{"code", "token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"claims_supported":                      []string{"sub", "iss", "auth_time", "name", "email"},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(metadata)
}
