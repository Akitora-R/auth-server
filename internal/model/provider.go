package model

import (
	"auth-server/internal/util"
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

type ProviderData[D any] interface {
	Validate(data D) bool
}

type AuthUserProvider struct {
	ID           int64           `db:"id"`
	UserID       int64           `db:"user_id"`
	LoginKey     string          `db:"login_key"`
	ProviderType ProviderType    `db:"provider_type"`
	ProviderData json.RawMessage `db:"provider_data"`
	BaseModel
}

type ProviderType int

const (
	ProviderEmailPassword ProviderType = iota
	ProviderTelegram
)

func (t *ProviderType) Value() (driver.Value, error) {
	v := *t
	switch v {
	case ProviderEmailPassword:
		return "EmailPassword", nil
	case ProviderTelegram:
		return "Telegram", nil
	default:
		return nil, fmt.Errorf("unknown ProviderType: %v", t)
	}
}

func (t *ProviderType) Scan(value interface{}) error {
	var strVal string
	switch value.(type) {
	case []uint8:
		strVal = string(value.([]uint8))
	case string:
		strVal = value.(string)
	default:
		return fmt.Errorf("TokenType must be a string, got %T", value)
	}

	switch strVal {
	case "EmailPassword":
		*t = ProviderEmailPassword
	case "Telegram":
		*t = ProviderTelegram
	default:
		return fmt.Errorf("unknown TokenType: %s", strVal)
	}
	return nil
}

type EmailPasswordProviderData struct {
	Password string `json:"password"`
}

func (p *EmailPasswordProviderData) Validate(data string) bool {
	return util.DigestSHA256Hex(data) == p.Password
}
