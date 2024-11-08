package auth

import (
	"errors"
	"net/http"
	"strings"
)

func GetAPIKey(headers http.Header) (string, error) {
	// Get authorization header & remove whitespace
	auth := headers.Get("Authorization")
	auth = strings.TrimSpace(auth)

	if auth == "" {
		return "", errors.New("authorization does not exist in header")
	}

	after, found := strings.CutPrefix(auth, "ApiKey")
	after = strings.TrimSpace(after)

	if !found {
		return "", errors.New("invalid header")
	}

	if after == "" {
		return "", errors.New("token does not exist in authorization header")
	}

	return after, nil
}
