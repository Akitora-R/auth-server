package internal

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"regexp"

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
		Host string `yaml:"host"`
		Port string `yaml:"port"`
	} `yaml:"redis"`
	DB         string      `yaml:"db"`
	JWT        []JWTConfig `yaml:"jwt"`
	Cloudflare struct {
		Turnstile struct {
			Key    string `yaml:"key"`
			Secret string `yaml:"secret"`
		} `yaml:"turnstile"`
	} `yaml:"cloudflare"`
	Telegram struct {
		BotName  string `yaml:"bot-name"`
		BotToken string `yaml:"bot-token"`
	} `yaml:"telegram"`
}

func init() {
	configPath, err := filepath.Abs("config.yaml")
	if err != nil {
		slog.Warn("failed to get absolute path of config file", "err", err)
		return
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		slog.Warn("failed to read config file or file not found", "path", configPath, "err", err)
		return
	}

	if err = yaml.Unmarshal(data, &AuthServerConfig); err != nil {
		slog.Error("failed to unmarshal config", "path", configPath, "err", err)
		return
	}

	slog.Info("successfully loaded config file", "path", configPath)

	resolveEnv(&AuthServerConfig)
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
	if AuthServerConfig.Redis.Host == "" {
		AuthServerConfig.Redis.Host = "localhost"
		slog.Debug("set default redis address", "port", AuthServerConfig.Redis.Host)
	}
	if AuthServerConfig.Redis.Port == "" {
		AuthServerConfig.Redis.Port = "6379"
		slog.Debug("set default redis port", "port", AuthServerConfig.Redis.Port)
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
	if AuthServerConfig.Cloudflare.Turnstile.Key == "" || AuthServerConfig.Cloudflare.Turnstile.Secret == "" {
		panic("Cloudflare Turnstile un-config")
	}
}

func resolveEnv(cfg *Config) {
	cfgV := reflect.ValueOf(cfg).Elem()
	resolveStruct(cfgV)
}

func resolveStruct(v reflect.Value) {
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		switch field.Kind() {
		case reflect.String:
			resolveString(field, fieldType.Name)
		case reflect.Slice:
			for j := 0; j < field.Len(); j++ {
				resolveStruct(field.Index(j))
			}
		case reflect.Struct:
			resolveStruct(field)
		default:
		}
	}
}

func resolveString(v reflect.Value, fieldName string) {
	val := v.String()
	re := regexp.MustCompile(`\$\{(.+?)(?::(.+?))?}`)
	matches := re.FindStringSubmatch(val)

	if len(matches) > 1 {
		envKey := matches[1]
		defaultValue := ""
		if len(matches) == 3 {
			defaultValue = matches[2]
		}

		envVal, found := os.LookupEnv(envKey)
		if !found {
			if defaultValue == "" {
				panic(fmt.Sprintf("Environment variable for %s (%s) is not set and no default value is provided", fieldName, envKey))
			}
			envVal = defaultValue
		}
		v.SetString(envVal)
	}
}
