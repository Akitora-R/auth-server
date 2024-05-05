package http

import (
	"auth-server/internal/oauth2"
	"encoding/json"
	"net/http"
)

func jwkSetHandler(w http.ResponseWriter, r *http.Request) {
	var keys []map[string]string
	for _, key := range oauth2.JWTKeys {
		keys = append(keys, key.ToJWK())
	}

	jwks := map[string]any{
		"keys": keys,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jwks)
}
