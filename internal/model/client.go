package model

import (
	"slices"

	"fmt"

	"github.com/go-oauth2/oauth2/v4"
)

type ScopedClientInfo interface {
	oauth2.ClientInfo
	GetDisplayName() string
	GetScopes() []string
	GetTokenType() TokenType
}

type AuthClient struct {
	ID          int64      `db:"id"`
	Secret      string     `db:"secret"`
	Domain      string     `db:"domain"`
	DisplayName string     `db:"display_name"`
	Scopes      TextArray  `db:"scopes"`
	TokenType   *TokenType `db:"token_type"`
	BaseModel
}

func (c *AuthClient) GetID() string {
	return fmt.Sprint(c.ID)
}

func (c *AuthClient) GetSecret() string {
	return c.Secret
}

func (c *AuthClient) GetDomain() string {
	return c.Domain
}

func (c *AuthClient) IsPublic() bool {
	return false
}

func (c *AuthClient) GetUserID() string {
	return ""
}

func (c *AuthClient) GetDisplayName() string {
	return c.DisplayName
}

func (c *AuthClient) GetScopes() []string {
	return c.Scopes
}

func (c *AuthClient) HasScope(scope string) bool {
	return slices.Contains(c.Scopes, scope)
}

func (c *AuthClient) GetTokenType() TokenType {
	return *c.TokenType
}
