package store

import (
	"auth-server/internal"
	"auth-server/internal/model"
	"encoding/json"
	"errors"
	"fmt"
)

var UserRepo UserStore = &MySQLUserStore{}

type UserStore interface {
	GetUserByID(id int64) (model.UserInfo, error)
	GetUserByCredentials(providerID string, providerType model.ProviderType, data json.RawMessage) (user model.UserInfo, registrable bool, err error)
}

type MySQLUserStore struct {
}

func (m *MySQLUserStore) GetUserByID(id int64) (model.UserInfo, error) {
	user := model.AuthUser{}
	if err := internal.DB.Get(&user, "select * from auth_user where id = ?", id); err != nil {
		return nil, err
	}
	return &user, nil
}

func (m *MySQLUserStore) GetUserByCredentials(
	userKey string,
	providerType model.ProviderType,
	data json.RawMessage,
) (model.UserInfo, bool, error) {
	provider := model.AuthUserProvider{}
	if err := internal.DB.Get(&provider, `select * from auth_user_provider where login_key = ? and provider_type = ?`, userKey, providerType); err != nil {
		return nil, false, err
	}
	switch provider.ProviderType {
	case model.ProviderEmailPassword:
		req := model.EmailPasswordProviderData{}
		if err := json.Unmarshal(data, &req); err != nil {
			return nil, false, err
		}
		repo := model.EmailPasswordProviderData{}
		if err := json.Unmarshal(provider.ProviderData, &repo); err != nil {
			return nil, false, err
		}
		if repo.Validate(req.Password) {
			u, err := m.GetUserByID(provider.UserID)
			return u, false, err
		} else {
			return nil, false, errors.New("invalid_credentials")
		}
	case model.ProviderTelegram:
		// TODO
		panic("telegram provider not implemented yet")
	default:
		return nil, false, fmt.Errorf("unknown ProviderType: %v", providerType)
	}
}
