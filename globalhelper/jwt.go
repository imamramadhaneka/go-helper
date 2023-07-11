package globalhelper

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

func GenerateJWT(claims jwt.Claims, jwtSecret string) (signedString string, err error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedString, err = token.SignedString([]byte(jwtSecret))
	return
}

func DecodeJWT(signedToken, jwtSecret string, tokenPayload jwt.Claims) (err error) {
	token, err := jwt.ParseWithClaims(signedToken, tokenPayload, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("error handling token")
		}
		return []byte(jwtSecret), nil
	})

	if err != nil {
		return err
	}

	if token == nil {
		return fmt.Errorf("empty token")
	}

	if !token.Valid {
		return errors.New("invalid token")
	}

	return nil
}
