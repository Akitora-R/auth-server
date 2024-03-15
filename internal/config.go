package internal

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"

	"gopkg.in/yaml.v3"
)

var AuthServerConfig Config

type JWTConfig struct {
	Kid string `yaml:"kid"`
	Alg string `yaml:"alg"`
	Sec string `yaml:"sec"`
}

type Config struct {
	Host  string `yaml:"host"`
	Port  int    `yaml:"port"`
	Redis struct {
		Address string `yaml:"address"`
	} `yaml:"redis"`
	DB  string      `yaml:"db"`
	JWT []JWTConfig `yaml:"jwt"`
}

func init() {
	data, err := os.ReadFile("config.yaml")
	if err != nil {
		slog.Warn("failed to read config file or file not found, using default values", "err", err)
	} else {
		if err = yaml.Unmarshal(data, &AuthServerConfig); err != nil {
			slog.Error("failed to unmarshal config", "err", err)
		}
	}
	setDefaultValues()
}

func setDefaultValues() {
	if AuthServerConfig.Host == "" {
		AuthServerConfig.Host = "localhost"
		slog.Debug("set default listening host", "address", AuthServerConfig.Host)
	}
	if AuthServerConfig.Port == 0 {
		AuthServerConfig.Port = 8080
		slog.Debug("set default listening port", "port", AuthServerConfig.Port)
	}
	if AuthServerConfig.Redis.Address == "" {
		AuthServerConfig.Redis.Address = "localhost:6379"
		slog.Debug("set default redis address", "port", AuthServerConfig.Redis.Address)
	}
	if AuthServerConfig.DB == "" {
		AuthServerConfig.DB = "root:root@(localhost:3306)/auth?parseTime=true"
		slog.Debug("set default db address", "port", AuthServerConfig.DB)
	}
	if len(AuthServerConfig.JWT) == 0 {
		keySize := 2048
		alg := "RS256"
		privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
		if err != nil {
			panic("failed to generate RSA keys")
		}
		privateKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		})

		slog.Info("Generated RSA key pair", "algorithm", alg, "keySize", keySize)
		AuthServerConfig.JWT = []JWTConfig{
			{
				Kid: "default",
				Alg: alg,
				Sec: string(privateKeyPEM),
			},
		}
	}
}
