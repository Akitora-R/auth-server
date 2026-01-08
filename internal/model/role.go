package model

type AuthRole struct {
	ID          int64   `db:"id"`
	Name        string  `db:"name"`
	Description *string `db:"description"`
	BaseModel
}

type Role struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// NewRoleFromAuth 通过数据库实体构造领域层角色
func NewRoleFromAuth(authRole AuthRole) *Role {
	var desc string
	if authRole.Description != nil {
		desc = *authRole.Description
	}
	return &Role{
		ID:          authRole.ID,
		Name:        authRole.Name,
		Description: desc,
	}
}
