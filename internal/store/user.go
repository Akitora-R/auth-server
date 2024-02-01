package store

import "auth-server/internal"

var UserRepo UserStore = &MySqlUserStore{}

type UserInfo interface {
	GetID() int64
	GetEmail() string
	GetName() string
}

type UserStore interface {
	GetUserByID(id int64) (UserInfo, error)
	GetUser(email, pwd string) (UserInfo, error)
}

type SysUser struct {
	ID       int64  `db:"id"`
	Email    string `db:"email"`
	Nickname string `db:"nickname"`
}

func (u *SysUser) GetID() int64 {
	return u.ID
}

func (u *SysUser) GetEmail() string {
	return u.Email
}

func (u *SysUser) GetName() string {
	return u.Nickname
}

type MySqlUserStore struct {
}

func (m *MySqlUserStore) GetUserByID(id int64) (UserInfo, error) {
	user := SysUser{}
	if err := internal.DB.Get(&user, "select id, email, nickname from sys_user where id = ?", id); err != nil {
		return nil, err
	}
	return &user, nil
}

func (m *MySqlUserStore) GetUser(email, pwd string) (UserInfo, error) {
	user := SysUser{}
	if err := internal.DB.Get(&user, "select id, email, nickname from sys_user where email = ? and password = ?", email, pwd); err != nil {
		return nil, err
	}
	return &user, nil
}
