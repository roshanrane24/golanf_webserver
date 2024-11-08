package auth

import (
	"bytes"
	"errors"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"net/http"
	"strings"
	"time"
)

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	claims := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.RegisteredClaims{
			Issuer:    "chirpy",
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().In(time.UTC).Add(expiresIn)),
			IssuedAt:  jwt.NewNumericDate(time.Now().In(time.UTC)),
		},
	)
	return claims.SignedString(bytes.NewBufferString(tokenSecret).Bytes())
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	claims := jwt.RegisteredClaims{}

	token, err := jwt.ParseWithClaims(
		tokenString,
		&claims,
		func(token *jwt.Token) (interface{}, error) {
			return []byte(tokenSecret), nil
		},
	)
	if err != nil {
		return [16]byte{}, err
	}

	if token.Valid {
		return uuid.Parse(claims.Subject)
	} else {
		return [16]byte{}, jwt.ErrTokenExpired
	}
}

func GetBearerToken(headers http.Header) (string, error) {
	// Get authorization header & remove whitespace
	auth := headers.Get("Authorization")
	auth = strings.TrimSpace(auth)

	if auth == "" {
		return "", errors.New("authorization does not exist in header")
	}

	after, found := strings.CutPrefix(auth, "Bearer")
	after = strings.TrimSpace(after)

	if !found {
		return "", errors.New("invalid header")
	}

	if after == "" {
		return "", errors.New("token does not exist in authorization header")
	}

	return after, nil
}
