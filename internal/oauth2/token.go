package oauth2

import (
	"auth-server/internal"
	"auth-server/internal/model"
	"context"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/golang-jwt/jwt"
)

var tokenGenerator = map[model.TokenType]oauth2.AccessGenerate{
	model.OpaqueToken: &generates.AccessGenerate{},
	model.JWT:         generates.NewJWTAccessGenerate(internal.AuthServerConfig.JWT[0].Kid, []byte(internal.AuthServerConfig.JWT[0].PEM), jwt.SigningMethodRS256),
}

type ClientConfigTokenGenerate struct {
}

func (c *ClientConfigTokenGenerate) Token(ctx context.Context, data *oauth2.GenerateBasic, isGenRefresh bool) (access, refresh string, err error) {
	var tokenType model.TokenType
	if ci, ok := data.Client.(model.ScopedClientInfo); ok {
		tokenType = ci.GetTokenType()
	} else {
		tokenType = model.OpaqueToken
	}
	return tokenGenerator[tokenType].Token(ctx, data, isGenRefresh)
}
