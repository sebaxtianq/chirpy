package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alexedwards/argon2id"
	"github.com/golang-jwt/jwt/v5"
)

func HashPassword(password string) (string, error) {
	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		fmt.Print(err)
		return "", err
	}
	return hash, nil
}
func CheckPasswordHash(password, hash string) (bool, error) {
	valid, err := argon2id.ComparePasswordAndHash(password, hash)
	return valid, err
}
func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		Issuer:    "Chirpy-Access",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Subject:   uuid.UUID.String(userID),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		fmt.Print("error signing jwt token", err)
		return "", err
	}
	return s, nil
}
func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
		return []byte(tokenSecret), nil
	})
	if err != nil {
		fmt.Print("error while parsing JWT", err)
		return uuid.Nil, err
	}
	id, err := token.Claims.GetSubject()
	expiry, err := token.Claims.GetExpirationTime()
	if time.Now().After(expiry.Time) {
		err = errors.New("Token expired")
		return uuid.Nil, err
	}
	uuidx, err := uuid.Parse(id)
	return uuidx, nil
}
func GetBearerToken(headers http.Header) (string, error) {
	token := headers.Get("Authorization")
	if token == "" {
		err := errors.New("Authorization Header not found")
		return "", err
	}
	token, found := strings.CutPrefix(token, "Bearer ")
	if !found {
		err := errors.New("Incorrect bearer token format")
		return "", err
	}
	return token, nil

}
func MakeRefreshToken() string {
	key := make([]byte, 32)
	rand.Read(key)
	encoded_key := hex.EncodeToString(key)
	return encoded_key
}
