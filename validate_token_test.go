package jwt_test

import (
	"testing"
	"time"

	"github.com/amidgo/jwt"
	"github.com/golang/mock/gomock"
	"gotest.tools/v3/assert"
)

type MockTokenValidatorCreator struct {
	ctrl  *gomock.Controller
	token jwt.Token
}

func NewMockTokenValidatorCreator(ctrl *gomock.Controller, token jwt.Token) *MockTokenValidatorCreator {
	return &MockTokenValidatorCreator{
		ctrl:  ctrl,
		token: token,
	}
}

func (c *MockTokenValidatorCreator) NewTokenValidator(err error) *jwt.MockTokenValidator {
	tokenValidator := jwt.NewMockTokenValidator(c.ctrl)
	tokenValidator.EXPECT().ValidateToken(c.token).Return(err).AnyTimes()
	return tokenValidator
}

func Test_ValidateToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	token := jwt.Token{}
	tokenValidatorCreator := NewMockTokenValidatorCreator(ctrl, token)
	cases := []struct {
		validators  []jwt.TokenValidator
		expectedErr error
	}{
		{
			validators: []jwt.TokenValidator{
				tokenValidatorCreator.NewTokenValidator(nil),
				tokenValidatorCreator.NewTokenValidator(nil),
				tokenValidatorCreator.NewTokenValidator(nil),
				tokenValidatorCreator.NewTokenValidator(jwt.ErrTokenExpired),
			},
			expectedErr: jwt.ErrTokenExpired,
		},
		{
			validators: []jwt.TokenValidator{
				tokenValidatorCreator.NewTokenValidator(nil),
				tokenValidatorCreator.NewTokenValidator(nil),
				tokenValidatorCreator.NewTokenValidator(jwt.ErrNoExpiration),
				tokenValidatorCreator.NewTokenValidator(jwt.ErrTokenExpired),
			},
			expectedErr: jwt.ErrNoExpiration,
		},
		{
			validators: []jwt.TokenValidator{
				tokenValidatorCreator.NewTokenValidator(nil),
				tokenValidatorCreator.NewTokenValidator(nil),
			},
		},
		{},
	}

	for _, cs := range cases {
		actualErr := jwt.ValidateToken(token, cs.validators...)
		assert.ErrorIs(t, actualErr, cs.expectedErr, "wrong err")
	}
}

func Test_VerifyTokenExpiration(t *testing.T) {
	cases := []struct {
		token       jwt.Token
		expectedErr error
	}{
		{
			token: jwt.Token{
				Payload: jwt.Payload{
					"exp": float64(time.Now().Add(time.Hour).Unix()),
				},
			},
		},

		{
			token: jwt.Token{
				Payload: jwt.Payload{
					"exp": float64(time.Time{}.Unix()),
				},
			},
			expectedErr: jwt.ErrTokenExpired,
		},
		{
			token: jwt.Token{
				Payload: jwt.Payload{},
			},
			expectedErr: jwt.ErrNoExpiration,
		},
	}

	for _, cs := range cases {
		actualErr := jwt.VerifyTokenExpiration(cs.token)
		assert.ErrorIs(t, actualErr, cs.expectedErr, "wrong err")
	}
}
