package model

import "github.com/go-oauth2/oauth2/v4"

type ScopedClientInfo interface {
	oauth2.ClientInfo
	GetDisplayName() string
	GetScopes() []string
	GetTokenType() TokenType
}

type AuthClient struct {
	ID          string     `db:"id"`
	Secret      string     `db:"secret"`
	Domain      string     `db:"domain"`
	DisplayName string     `db:"display_name"`
	Scopes      TextArray  `db:"scopes"`
	TokenType   *TokenType `db:"token_type"`
	BaseModel
}

func (c *AuthClient) GetID() string {
	return c.ID
}

func (c *AuthClient) GetSecret() string {
	return c.Secret
}

func (c *AuthClient) GetDomain() string {
	return c.Domain
}

func (c *AuthClient) IsPublic() bool {
	return true
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
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

func (c *AuthClient) GetTokenType() TokenType {
	return *c.TokenType
}
