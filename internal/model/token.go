package model

import "fmt"

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
