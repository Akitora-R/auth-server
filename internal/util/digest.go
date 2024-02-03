package util

import (
	"crypto/sha256"
	"encoding/hex"
)

func DigestSHA256Hex(input string) string {
	hash := sha256.Sum256([]byte(input))
	hexString := hex.EncodeToString(hash[:])
	return hexString
}
