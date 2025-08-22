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

func (t *TokenType) Scan(value any) error {
	var strVal string
	switch v := value.(type) {
	case []uint8:
		strVal = string(v)
	case string:
		strVal = v
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

// String returns the textual name of the token type
func (t TokenType) String() string {
	switch t {
	case OpaqueToken:
		return "OpaqueToken"
	case JWT:
		return "JWT"
	default:
		return fmt.Sprintf("Unknown(%d)", int(t))
	}
}
