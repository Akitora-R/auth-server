package model

import "time"

type UserInfo interface {
	GetID() int64
	GetEmail() string
	GetDisplayName() string
}

type AuthUser struct {
	ID          int64  `db:"id"`
	Email       string `db:"email"`
	DisplayName string `db:"display_name"`
	BaseModel
}

func (u *AuthUser) GetID() int64 {
	return u.ID
}

func (u *AuthUser) GetEmail() string {
	return u.Email
}

func (u *AuthUser) GetDisplayName() string {
	return u.DisplayName
}

// User 表示领域层的用户信息，比数据库实体包含更多上下文数据
type User struct {
	ID          int64      `json:"id"`
	Email       string     `json:"email"`
	DisplayName string     `json:"display_name"`
	Roles       []AuthRole `json:"roles,omitempty"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

// SessionUserInfo 用于在会话中存储当前登录用户的上下文数据
type SessionUserInfo struct {
	User          User           `json:"user"`
	ProviderType  *ProviderType  `json:"provider_type,omitempty"`
	LoginIP       string         `json:"login_ip,omitempty"`
	LoginClientID string         `json:"login_client_id,omitempty"`
	LoginAt       time.Time      `json:"login_at"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

// NewUserFromAuth 通过数据库实体构造领域层用户
func NewUserFromAuth(authUser UserInfo, roles []AuthRole, lastLoginAt *time.Time) User {
	return User{
		ID:          authUser.GetID(),
		Email:       authUser.GetEmail(),
		DisplayName: authUser.GetDisplayName(),
		Roles:       roles,
		LastLoginAt: lastLoginAt,
	}
}

// NewSessionUserInfo 构建一个 SessionUserInfo 以便存入会话
func NewSessionUserInfo(user User, providerType *ProviderType, loginIP, loginClientID string, loginAt time.Time, metadata map[string]any) *SessionUserInfo {
	return &SessionUserInfo{
		User:          user,
		ProviderType:  providerType,
		LoginIP:       loginIP,
		LoginClientID: loginClientID,
		LoginAt:       loginAt,
		Metadata:      metadata,
	}
}
