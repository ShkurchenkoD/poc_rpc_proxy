package tron

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
)

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var base58Indexes = func() [128]int {
	var idx [128]int
	for i := range idx {
		idx[i] = -1
	}
	for i := 0; i < len(base58Alphabet); i++ {
		idx[base58Alphabet[i]] = i
	}
	return idx
}()

func normalizeAddress(address string) (string, error) {
	addr := strings.TrimSpace(address)
	if addr == "" {
		return "", ErrInvalidAddress
	}
	if strings.HasPrefix(addr, "0x") || strings.HasPrefix(addr, "0X") {
		addr = addr[2:]
	}
	if isHexAddress(addr) {
		return strings.ToLower(addr), nil
	}
	payload, err := base58CheckDecode(addr)
	if err != nil {
		return "", ErrInvalidAddress
	}
	if len(payload) != 21 || payload[0] != 0x41 {
		return "", ErrInvalidAddress
	}
	return hex.EncodeToString(payload), nil
}

func isHexAddress(addr string) bool {
	if len(addr) != 42 || !strings.HasPrefix(addr, "41") {
		return false
	}
	for i := 0; i < len(addr); i++ {
		c := addr[i]
		if !isHexChar(c) {
			return false
		}
	}
	return true
}

func isHexChar(c byte) bool {
	switch {
	case c >= '0' && c <= '9':
		return true
	case c >= 'a' && c <= 'f':
		return true
	case c >= 'A' && c <= 'F':
		return true
	default:
		return false
	}
}

func base58CheckDecode(input string) ([]byte, error) {
	decoded, err := decodeBase58(input)
	if err != nil {
		return nil, err
	}
	if len(decoded) < 4 {
		return nil, errors.New("invalid base58check length")
	}
	payload := decoded[:len(decoded)-4]
	checksum := decoded[len(decoded)-4:]
	hash := sha256.Sum256(payload)
	hash = sha256.Sum256(hash[:])
	if !bytes.Equal(checksum, hash[:4]) {
		return nil, errors.New("invalid base58check checksum")
	}
	return payload, nil
}

func decodeBase58(input string) ([]byte, error) {
	if input == "" {
		return nil, errors.New("empty base58 string")
	}

	result := big.NewInt(0)
	radix := big.NewInt(58)
	for i := 0; i < len(input); i++ {
		ch := input[i]
		if ch >= 128 {
			return nil, errors.New("invalid base58 character")
		}
		val := base58Indexes[ch]
		if val < 0 {
			return nil, errors.New("invalid base58 character")
		}
		result.Mul(result, radix)
		result.Add(result, big.NewInt(int64(val)))
	}

	decoded := result.Bytes()
	for i := 0; i < len(input) && input[i] == '1'; i++ {
		decoded = append([]byte{0x00}, decoded...)
	}
	return decoded, nil
}
