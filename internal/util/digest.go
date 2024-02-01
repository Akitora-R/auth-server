package util

import (
	"crypto/sha256"
	"encoding/hex"
)

// DigestSHA256Hex 接受一个字符串并返回其SHA-256哈希的十六进制字符串表示形式
func DigestSHA256Hex(input string) string {
	// 使用SHA-256哈希函数计算输入字符串的哈希值
	hash := sha256.Sum256([]byte(input))

	// 将哈希值的字节切片转换为十六进制字符串
	hexString := hex.EncodeToString(hash[:])

	return hexString
}
