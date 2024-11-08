package auth

import (
	"crypto/rand"
	"encoding/hex"
)

func MakeRefreshToken() (string, error) {
	randArr := make([]byte, 32)

	_, err := rand.Read(randArr)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(randArr), nil
}
