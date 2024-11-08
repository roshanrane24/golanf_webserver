package auth

import (
	"encoding/hex"
	"testing"
)

func TestMakeRefreshToken(t *testing.T) {
	token, err := MakeRefreshToken()
	if err != nil {
		t.Fatalf("FAILED: %v", err.Error())
	}

	decodedToken, _ := hex.DecodeString(token)

	// Token must be 32 bytes (64 in strinh for hex)
	if len(decodedToken) != 32 {
		t.Fatalf("FAILED: %v,\nlen: %v,\ntoken: %v", "Generated token is not of size 256 bit", len(decodedToken), decodedToken)
	}
}
