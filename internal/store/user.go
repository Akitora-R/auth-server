package store

import (
	"auth-server/internal"
	"auth-server/internal/model"
	"auth-server/internal/util"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-session/session"
	"log/slog"
	"time"
)

var UserRepo UserStore = &MySQLUserStore{}

type UserStore interface {
	GetUserByID(id int64) (model.UserInfo, error)
	GetUserByCredentials(providerID string, providerType *model.ProviderType, data json.RawMessage, sessionStore session.Store) (user model.UserInfo, err error)
	AddUser(user model.UserInfo, provider model.AuthUserProvider) error
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
	loginKey string,
	providerType *model.ProviderType,
	data json.RawMessage,
	sessionStore session.Store,
) (model.UserInfo, error) {
	var providers []model.AuthUserProvider
	if err := internal.DB.Select(&providers, `select * from auth_user_provider where login_key = ? and provider_type = ?`, loginKey, providerType); err != nil {
		return nil, err
	}
	if len(providers) <= 0 {
		return nil, nil
	}
	provider := providers[0]
	switch *provider.ProviderType {
	case model.ProviderEmailPassword:
		req := model.EmailPasswordProviderData{}
		if err := json.Unmarshal(data, &req); err != nil {
			return nil, err
		}
		repo := model.EmailPasswordProviderData{}
		if err := json.Unmarshal(provider.ProviderData, &repo); err != nil {
			return nil, err
		}
		if repo.Validate(req.Password) {
			u, err := m.GetUserByID(provider.UserID)
			return u, err
		} else {
			return nil, errors.New("invalid_credentials")
		}
	case model.ProviderTelegram:
		botTokenDigest := util.DigestSHA256(internal.AuthServerConfig.Telegram.BotToken)
		if !util.ValidateTelegramCredential(data, botTokenDigest) {
			slog.Warn("Invalid Telegram Credentials")
			return nil, errors.New("invalid_credentials")
		}
		tgUser := model.TelegramUser{}
		_ = json.Unmarshal(data, &tgUser)
		sessionStore.Set(internal.SessionKeyTelegramData, tgUser)
		if err := sessionStore.Save(); err != nil {
			return nil, err
		}
		return m.GetUserByID(provider.UserID)
	default:
		return nil, fmt.Errorf("unknown ProviderType: %v", providerType)
	}
}

func (m *MySQLUserStore) AddUser(user model.UserInfo, provider model.AuthUserProvider) error {
	now := time.Now()
	e := model.AuthUser{
		Email:       user.GetEmail(),
		DisplayName: user.GetDisplayName(),
		BaseModel: model.BaseModel{
			CreatedAt: &now,
			UpdatedAt: &now,
		},
	}

	// Start a transaction
	tx, err := internal.DB.Beginx()
	if err != nil {
		return err
	}

	// Defer a rollback in case anything fails
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p) // re-throw panic after Rollback
		} else if err != nil {
			_ = tx.Rollback() // err is non-nil; don't change it
		} else {
			_ = tx.Commit() // err is nil; if Commit returns error update err
		}
	}()

	var uCount = 0
	if err = tx.Get(&uCount, "SELECT COUNT(*) FROM auth_user WHERE email = ?", user.GetEmail()); err != nil {
		return err
	}

	if uCount > 0 {
		return errors.New("user_exists")
	}

	insertUserSql := `INSERT INTO auth.auth_user (email, display_name, created_at, updated_at) 
              VALUES (:email, :display_name, :created_at, :updated_at)`

	result, err := tx.NamedExec(insertUserSql, e)
	if err != nil {
		return err
	}

	userID, err := result.LastInsertId()
	if err != nil {
		return err
	}

	// Insert provider data
	provider.UserID = userID
	provider.BaseModel = model.BaseModel{
		CreatedAt: &now,
		UpdatedAt: &now,
	}

	insertProviderSql := `INSERT INTO auth.auth_user_provider (user_id, login_key, provider_type, provider_data, created_at, updated_at)
              VALUES (:user_id, :login_key, :provider_type, :provider_data, :created_at, :updated_at)`

	_, err = tx.NamedExec(insertProviderSql, provider)
	if err != nil {
		return err
	}

	return nil
}
