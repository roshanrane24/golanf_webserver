package auth

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"net/http"
	"testing"
	"time"
)

func TestJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "secret"
	expiresIn := time.Minute * 10

	jwtToken, err := MakeJWT(userID, tokenSecret, expiresIn)

	if err != nil {
		t.Fatal("Test Failed Error Creating JWT Token", err)
	}

	validateUserID, err := ValidateJWT(jwtToken, tokenSecret)
	if err != nil {
		t.Fatal("Test Failed Error while validating JWT Token", err)
	}

	if validateUserID != userID {
		t.Fatalf("Test Failed \nExpected User ID: \t%v\nParsed User ID: \t%v", userID, validateUserID)
	}
}

func TestGetBearerTokenExist(t *testing.T) {
	token, _ := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.RegisteredClaims{
			Issuer:    "chirpy",
			Subject:   "test_user",
			ExpiresAt: jwt.NewNumericDate(time.Now().In(time.UTC).Add(time.Minute * 1)),
			NotBefore: jwt.NewNumericDate(time.Now().In(time.UTC)),
			IssuedAt:  jwt.NewNumericDate(time.Now().In(time.UTC)),
		},
	).SignedString([]byte("secret"))
	authToken := "Bearer " + token
	header := http.Header{}
	header.Add("Authorization", authToken)
	bearerToken, err := GetBearerToken(header)
	if err != nil {
		t.Fatal("Failed: Expected token got \nerror: ", err)
	}

	if bearerToken != token {
		t.Fatalf(
			"Failed: Parsed Toker Doesn't match\nExpected: %v \nGot:%v ",
			token,
			bearerToken,
		)
	}
}
