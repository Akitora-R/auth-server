package store

import (
	"auth-server/internal"
	"auth-server/internal/model"
	"context"
	"github.com/go-oauth2/oauth2/v4"
)

var ClientRepo oauth2.ClientStore = &MySQLClientStore{}

type MySQLClientStore struct {
}

func (m *MySQLClientStore) GetByID(_ context.Context, id string) (oauth2.ClientInfo, error) {
	var client []model.AuthClient
	if err := internal.DB.Select(&client, "select * from auth_client where id = ?", id); err != nil {
		return nil, err
	}
	if len(client) < 1 {
		return nil, nil
	}
	return &client[0], nil
}
