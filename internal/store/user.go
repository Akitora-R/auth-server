package store

import (
	"auth-server/internal"
	"auth-server/internal/model"
	"auth-server/internal/util"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-session/session/v3"
)

var UserRepo UserStore = &DbUserStore{}

type UserStore interface {
	GetUserByID(id int64) (model.UserInfo, error)
	GetUserByCredentials(providerID string, providerType *model.ProviderType, data json.RawMessage, sessionStore session.Store) (user model.UserInfo, err error)
	AddUser(user model.UserInfo, provider model.AuthUserProvider) error
}

type DbUserStore struct {
}

func (m *DbUserStore) GetUserByID(id int64) (model.UserInfo, error) {
	authUser := model.AuthUser{}
	if err := internal.DB.Get(&authUser, "select * from auth_user where id = $1", id); err != nil {
		return nil, err
	}
	var roles []model.AuthRole
	query := `SELECT r.id, r.name, r.description
			  FROM auth_role r
			  JOIN auth_user_role ur ON r.id = ur.role_id
			  WHERE ur.user_id = $1`
	if err := internal.DB.Select(&roles, query, authUser.ID); err != nil {
		return nil, err
	}
	roleInfos := make([]model.RoleInfo, 0, len(roles))
	for _, r := range roles {
		var des string
		if r.Description != nil {
			des = *r.Description
		} else {
			des = ""
		}
		roleInfos = append(roleInfos, &model.Role{
			ID:          r.ID,
			Name:        r.Name,
			Description: des,
		})
	}
	user := model.NewUserFromAuth(authUser, roleInfos, nil)
	return &user, nil
}

func (m *DbUserStore) GetUserByCredentials(
	loginKey string,
	providerType *model.ProviderType,
	data json.RawMessage,
	sessionStore session.Store,
) (model.UserInfo, error) {
	var providers []model.AuthUserProvider
	if err := internal.DB.Select(&providers, `select * from auth_user_provider where login_key = $1 and provider_type = $2`, loginKey, providerType); err != nil {
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

func (m *DbUserStore) AddUser(user model.UserInfo, provider model.AuthUserProvider) error {
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
	if err = tx.Get(&uCount, "SELECT COUNT(*) FROM auth_user WHERE email = $1", user.GetEmail()); err != nil {
		return err
	}

	if uCount > 0 {
		return errors.New("user_exists")
	}

	insertUserSql := `INSERT INTO auth_user (email, display_name, created_at, updated_at) 
	              VALUES (:email, :display_name, :created_at, :updated_at) RETURNING id`
	rows, err := tx.NamedQuery(insertUserSql, e)
	if err != nil {
		return err
	}
	var userID int64
	if rows.Next() {
		if err = rows.Scan(&userID); err != nil {
			return err
		}
	}
	_ = rows.Close()

	// Insert provider data
	provider.UserID = userID
	provider.BaseModel = model.BaseModel{
		CreatedAt: &now,
		UpdatedAt: &now,
	}

	insertProviderSql := `INSERT INTO auth_user_provider (user_id, login_key, provider_type, provider_data, created_at, updated_at)
	              VALUES (:user_id, :login_key, :provider_type, :provider_data, :created_at, :updated_at)`

	_, err = tx.NamedExec(insertProviderSql, provider)
	if err != nil {
		return err
	}

	return nil
}
