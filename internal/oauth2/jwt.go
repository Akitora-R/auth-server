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
	for _, keyConfig := range internal.AuthServerConfig.JWT {
		switch keyConfig.Alg {
		case "RS256":
			publicKey, privateKey, err := parseRSAPublicKeyFromPEM(keyConfig.Sec)
			if err != nil {
				return err
			}
			JWTKeys = append(JWTKeys, &model.RSAKey{KeyID: keyConfig.Kid, PublicKey: publicKey, PrivateKey: privateKey})
		case "HS512":
			JWTKeys = append(JWTKeys, &model.HMACKey{KeyID: keyConfig.Kid, Secret: []byte(keyConfig.Sec)})
		default:
			return fmt.Errorf("unknown alg: %s", keyConfig.Alg)
		}
	}
	return nil
}

// Helper function to parse RSA public key
func parseRSAPublicKeyFromPEM(pemStr string) (*rsa.PublicKey, *rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, nil, fmt.Errorf("failed to parse PEM block")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return &priv.PublicKey, priv, nil
}

var JWTKeys []model.JWTKey
