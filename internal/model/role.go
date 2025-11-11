package model

type AuthRole struct {
	ID          int64   `db:"id"`
	Name        string  `db:"name"`
	Description *string `db:"description"`
	BaseModel
}

type RoleInfo interface {
	GetID() int64
	GetName() string
	GetDescription() string
}

type Role struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (r *Role) GetID() (_ int64) {
	return r.ID
}

func (r *Role) GetName() (_ string) {
	return r.Name
}

func (r *Role) GetDescription() (_ string) {
	return r.Description
}

// NewRoleFromAuth 通过数据库实体构造领域层角色
func NewRoleFromAuth(authRole RoleInfo) Role {
	return Role{
		ID:          authRole.GetID(),
		Name:        authRole.GetName(),
		Description: authRole.GetDescription(),
	}
}
