package util

import (
	"crypto/sha256"
	"encoding/hex"
)

func DigestSHA256Hex(input string) string {
	hexString := hex.EncodeToString(DigestSHA256(input))
	return hexString
}

func DigestSHA256(input string) []byte {
	hash := sha256.Sum256([]byte(input))
	return hash[:]
}
