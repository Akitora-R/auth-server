package model

import "time"

type UserInfo interface {
	GetID() int64
	GetEmail() string
	GetDisplayName() string
	GetRoles() []RoleInfo
	HasRole(roleName string) bool
}

type AuthUser struct {
	ID          int64  `db:"id"`
	Email       string `db:"email"`
	DisplayName string `db:"display_name"`
	BaseModel
}

// User represents a user in the system
type User struct {
	ID          int64      `json:"id"`
	Email       string     `json:"email"`
	DisplayName string     `json:"display_name"`
	Roles       []RoleInfo `json:"roles,omitempty"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

func (u *User) GetID() (_ int64) {
	return u.ID
}

func (u *User) GetEmail() (_ string) {
	return u.Email
}

func (u *User) GetDisplayName() (_ string) {
	return u.DisplayName
}

func (u *User) GetRoles() (_ []RoleInfo) {
	return u.Roles
}

func (u *User) HasRole(roleName string) bool {
	for _, role := range u.Roles {
		if role.GetName() == roleName {
			return true
		}
	}
	return false
}

// SessionUserInfo 用于在会话中存储当前登录用户的上下文数据
type SessionUserInfo struct {
	User          UserInfo       `json:"user"`
	ProviderType  *ProviderType  `json:"provider_type,omitempty"`
	LoginIP       string         `json:"login_ip,omitempty"`
	LoginClientID string         `json:"login_client_id,omitempty"`
	LoginAt       time.Time      `json:"login_at"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

// NewUserFromAuth constructs a user from the auth user entity
func NewUserFromAuth(authUser AuthUser, roles []RoleInfo, lastLoginAt *time.Time) User {
	return User{
		ID:          authUser.ID,
		Email:       authUser.Email,
		DisplayName: authUser.DisplayName,
		Roles:       roles,
		LastLoginAt: lastLoginAt,
	}
}

// NewSessionUserInfo constructs a SessionUserInfo to be stored in the session
func NewSessionUserInfo(user UserInfo, providerType *ProviderType, loginIP, loginClientID string, loginAt time.Time, metadata map[string]any) *SessionUserInfo {
	return &SessionUserInfo{
		User:          user,
		ProviderType:  providerType,
		LoginIP:       loginIP,
		LoginClientID: loginClientID,
		LoginAt:       loginAt,
		Metadata:      metadata,
	}
}
