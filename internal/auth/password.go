package auth

import (
	"bytes"
	"errors"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword(bytes.NewBufferString(password).Bytes(), 0)
	if err != nil {
		return "", errors.New("Error hashin password string: " + err.Error())
	}
	return bytes.NewBuffer(hashedPassword).String(), nil
}

func CheckPasswordHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword(bytes.NewBufferString(hash).Bytes(), bytes.NewBufferString(password).Bytes())
}
