package util

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ValidateTelegramCredential validates the credentials received from Telegram
// by comparing the computed hash with the provided hash.
func ValidateTelegramCredential(jsonData json.RawMessage, botTokenDigest []byte) bool {
	// Unmarshal the JSON data into a map
	var dataMap map[string]any
	var hash string
	if err := json.Unmarshal(jsonData, &dataMap); err != nil {
		return false
	}

	// Create a slice to hold key-value pairs, excluding the "hash" key
	var fs []string
	for k, v := range dataMap {
		if k == "hash" {
			hash = v.(string)
			continue // Skip the "hash" field
		}
		var valueStr string
		switch v := v.(type) {
		case string:
			valueStr = v
		case float64:
			valueStr = fmt.Sprintf("%d", int64(v))
		case int64:
			valueStr = fmt.Sprintf("%d", v)
		default:
			valueStr = fmt.Sprintf("%v", v) // Fallback for other types
		}
		fs = append(fs, k+"="+valueStr)
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
