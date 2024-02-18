package internal

import (
	"log/slog"
	"os"

	"gopkg.in/yaml.v3"
)

var AuthServerConfig Config

type JWTConfig struct {
	Kid    string `yaml:"kid"`
	Type   string `yaml:"type"`
	PEM    string `yaml:"pem,omitempty"`
	Secret string `yaml:"secret,omitempty"`
}

type Config struct {
	Host  string `yaml:"host"`
	Port  int    `yaml:"port"`
	Redis struct {
		Address string `yaml:"address"`
	} `yaml:"redis"`
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
	}
	if AuthServerConfig.Port == 0 {
		AuthServerConfig.Port = 8080
	}
	if AuthServerConfig.Redis.Address == "" {
		AuthServerConfig.Redis.Address = "localhost:6379"
	}
}
