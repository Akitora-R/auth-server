package store

import (
	"auth-server/internal"
	"auth-server/internal/model"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

var UserRepo UserStore = &MySQLUserStore{}

type UserStore interface {
	GetUserByID(id int64) (model.UserInfo, error)
	GetUserByCredentials(providerID string, providerType model.ProviderType, data json.RawMessage) (user model.UserInfo, registrable bool, err error)
}

type MySQLUserStore struct {
}

func (m *MySQLUserStore) GetUserByID(id int64) (model.UserInfo, error) {
	user := model.AuthUser{}
	if err := internal.DB.Get(&user, "select * from auth_user where id = ?", id); err != nil {
		return nil, err
	}
	return &user, nil
}

func (m *MySQLUserStore) GetUserByCredentials(
	loginKey string,
	providerType model.ProviderType,
	data json.RawMessage,
) (model.UserInfo, bool, error) {
	provider := model.AuthUserProvider{}
	if err := internal.DB.Get(&provider, `select * from auth_user_provider where login_key = ? and provider_type = ?`, loginKey, providerType); err != nil {
		return nil, false, err
	}
	switch provider.ProviderType {
	case model.ProviderEmailPassword:
		req := model.EmailPasswordProviderData{}
		if err := json.Unmarshal(data, &req); err != nil {
			return nil, false, err
		}
		repo := model.EmailPasswordProviderData{}
		if err := json.Unmarshal(provider.ProviderData, &repo); err != nil {
			return nil, false, err
		}
		if repo.Validate(req.Password) {
			u, err := m.GetUserByID(provider.UserID)
			return u, false, err
		} else {
			return nil, false, errors.New("invalid_credentials")
		}
	case model.ProviderTelegram:
		// TODO
		panic("telegram provider not implemented yet")
	default:
		return nil, false, fmt.Errorf("unknown ProviderType: %v", providerType)
	}
}

// validateTelegramCredential validates the credentials received from Telegram
// by comparing the computed hash with the provided hash.
func ValidateTelegramCredential(jsonData []byte, hash string, botTokenDigest []byte) bool {
	// Unmarshal the JSON data into a map
	var dataMap map[string]interface{}
	if err := json.Unmarshal(jsonData, &dataMap); err != nil {
		return false
	}

	// Create a slice to hold key-value pairs, excluding the "hash" key
	var fs []string
	for k, v := range dataMap {
		if k == "hash" {
			continue // Skip the "hash" field
		}
		fs = append(fs, k+"="+v.(string)) // Assume all values are strings for simplicity
	}

	// Sort the key-value pairs by key
	sort.Strings(fs)

	// Join the sorted key-value pairs with a newline character
	digestStr := strings.Join(fs, "\n")

	// Calculate the HMAC hash of the digest string using the bot token digest
	requestHash := calRequestHashHex(digestStr, botTokenDigest)

	// Return true if the computed hash matches the provided hash
	return requestHash == hash
}

// calRequestHashHex calculates the HMAC-SHA256 hash of a string with the given key,
// and returns the result as a hexadecimal string.
func calRequestHashHex(s string, key []byte) string {
	// Create a new HMAC-SHA256 hasher with the provided key
	h := hmac.New(sha256.New, key)

	// Write the string to be hashed
	h.Write([]byte(s))

	// Compute the HMAC-SHA256 hash
	hashed := h.Sum(nil)

	// Return the hexadecimal encoding of the hash
	return hex.EncodeToString(hashed)
}
