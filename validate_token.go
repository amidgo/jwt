package jwt

import (
	"time"
)

//go:generate mockgen -source validate_token.go -destination validate_token_mocks.go -package jwt

var (
	ErrNoExpiration TokenInvalidError = "invalid"
	ErrTokenExpired TokenInvalidError = "expired"
)

type TokenValidator interface {
	ValidateToken(token Token) error
}

type TokenValidatorFunc func(t Token) error

func (f TokenValidatorFunc) ValidateToken(token Token) error {
	return f(token)
}

var VerifyTokenExpiration TokenValidatorFunc = func(t Token) error {
	exp, ok := t.Payload["exp"].(float64)
	if !ok {
		return ErrNoExpiration
	}
	if time.Unix(int64(exp), 0).Before(time.Now()) {
		return ErrTokenExpired
	}
	return nil
}

func ValidateToken(t Token, tokenValidators ...TokenValidator) error {
	for _, tokenValidator := range tokenValidators {
		err := tokenValidator.ValidateToken(t)
		if err != nil {
			return err
		}
	}
	return nil
}
