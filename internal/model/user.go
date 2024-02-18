package model

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
