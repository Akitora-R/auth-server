package model

import (
	"database/sql/driver"
	"fmt"
)

type TokenType int

const (
	OpaqueToken TokenType = iota
	JWT                   = iota
)

func (t *TokenType) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var tokenStr string
	if err := unmarshal(&tokenStr); err != nil {
		return err
	}

	switch tokenStr {
	case "OpaqueToken":
		*t = OpaqueToken
	case "JWT":
		*t = JWT
	default:
		return fmt.Errorf("unknown token type: %s", tokenStr)
	}

	return nil
}

func (t *TokenType) Value() (driver.Value, error) {
	v := *t
	switch v {
	case OpaqueToken:
		return "OpaqueToken", nil
	case JWT:
		return "JWT", nil
	default:
		return nil, fmt.Errorf("unknown TokenType: %v", t)
	}
}

func (t *TokenType) Scan(value interface{}) error {
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
	case "OpaqueToken":
		*t = OpaqueToken
	case "JWT":
		*t = JWT
	default:
		return fmt.Errorf("unknown TokenType: %s", strVal)
	}

	return nil
}
