package oauth2

import (
	"auth-server/internal"
	"auth-server/internal/model"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func init() {
	err := LoadJWTConfig()
	if err != nil {
		panic(err)
	}
}

func LoadJWTConfig() error {
	for _, keyConfig := range internal.AuthServerConfig.Jwt {
		switch keyConfig.Type {
		case "RSA":
			publicKey, err := parseRSAPublicKeyFromPEM(keyConfig.PEM)
			if err != nil {
				return err
			}
			JWTConfig = append(JWTConfig, &model.RSAKey{KeyID: keyConfig.Kid, PublicKey: publicKey})
		case "HMAC":
			JWTConfig = append(JWTConfig, &model.HMACKey{KeyID: keyConfig.Kid, Secret: []byte(keyConfig.Secret)})
		}
	}
	return nil
}

// Helper function to parse RSA public key
func parseRSAPublicKeyFromPEM(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &priv.PublicKey, nil
}

var JWTConfig []model.JWTKey
