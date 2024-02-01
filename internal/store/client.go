package store

import (
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/store"
)

var ClientStore oauth2.ClientStore

type ScopedClientInfo interface {
	oauth2.ClientInfo
	GetName() string
	GetScopes() []string
}

type ScopedClient struct {
	ID     string   `yaml:"id"`
	Secret string   `yaml:"secret"`
	Domain string   `yaml:"domain"`
	Public bool     `yaml:"public"`
	UserID string   `yaml:"user-id"`
	Name   string   `yaml:"name"`
	Scopes []string `yaml:"scopes"`
}

func (c *ScopedClient) GetID() string {
	return c.ID
}

func (c *ScopedClient) GetSecret() string {
	return c.Secret
}

func (c *ScopedClient) GetDomain() string {
	return c.Domain
}

func (c *ScopedClient) IsPublic() bool {
	return c.Public
}

func (c *ScopedClient) GetUserID() string {
	return c.UserID
}

func (c *ScopedClient) GetName() string {
	return c.Name
}

func (c *ScopedClient) GetScopes() []string {
	return c.Scopes
}

func (c *ScopedClient) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

func init() {
	cs := store.NewClientStore()
	_ = cs.Set("oidc-client", &ScopedClient{
		ID:     "oidc-client",
		Secret: "secret",
		Domain: "https://example.com/oauth2/callback",
	})
	ClientStore = cs
}
