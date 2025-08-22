package store

import (
	"auth-server/internal"
	"auth-server/internal/model"
	"context"
	"errors"
	"time"

	"github.com/go-oauth2/oauth2/v4"
)

var ClientRepo oauth2.ClientStore = &MySQLClientStore{}

type MySQLClientStore struct {
}

func (m *MySQLClientStore) GetByID(_ context.Context, id string) (oauth2.ClientInfo, error) {
	var client []model.AuthClient
	if err := internal.DB.Select(&client, "select * from auth_client where id = $1", id); err != nil {
		return nil, err
	}
	if len(client) < 1 {
		return nil, nil
	}
	return &client[0], nil
}

// List returns all clients (admin usage)
func (m *MySQLClientStore) List(ctx context.Context) ([]model.AuthClient, error) {
	var clients []model.AuthClient
	if err := internal.DB.Select(&clients, "select * from auth_client order by created_at desc"); err != nil {
		return nil, err
	}
	return clients, nil
}

// Create inserts a new client
func (m *MySQLClientStore) Create(ctx context.Context, c *model.AuthClient) error {
	now := time.Now()
	c.CreatedAt = &now
	c.UpdatedAt = &now
	if c.TokenType == nil {
		return errors.New("token type required")
	}
	_, err := internal.DB.NamedExecContext(ctx, `insert into auth_client (id, display_name, secret, domain, scopes, token_type, created_at, updated_at) 
			values (:id, :display_name, :secret, :domain, :scopes, :token_type, :created_at, :updated_at)`, c)
	return err
}

// Delete removes a client by id
func (m *MySQLClientStore) Delete(ctx context.Context, id string) error {
	_, err := internal.DB.ExecContext(ctx, "delete from auth_client where id = $1", id)
	return err
}
