package jwt

import "net/http"

type TokenInvalidError string

func (t TokenInvalidError) Error() string {
	return string(t)
}

func (t TokenInvalidError) Type() string {
	return "jwt_token"
}

func (t TokenInvalidError) Code() string {
	return string(t)
}

func (t TokenInvalidError) HttpCode() int {
	return http.StatusUnauthorized
}

func (t TokenInvalidError) Is(target error) bool {
	if tokenInvalidErr, ok := target.(TokenInvalidError); ok {
		return tokenInvalidErr == t
	}

	return false
}
