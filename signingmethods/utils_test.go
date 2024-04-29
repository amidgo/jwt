package signingmethods_test

import (
	"encoding/base64"
	"testing"

	"github.com/amidgo/jwt"
	"gotest.tools/v3/assert"
)

type SigningMethodCreateTokenTester struct {
	CaseName      string
	SigningMethod jwt.SigningMethod
	Payload       jwt.Payload
	ExpectedToken string
	ExpectedErr   error
}

func (s *SigningMethodCreateTokenTester) Name() string {
	return s.CaseName
}

func (s *SigningMethodCreateTokenTester) Test(t *testing.T) {
	creator := jwt.NewTokenCreator(base64.RawURLEncoding, s.SigningMethod)

	token, err := creator.CreateToken(s.Payload)
	assert.ErrorIs(t, err, s.ExpectedErr)
	assert.Equal(t, token, s.ExpectedToken)
}

type SigningMethodParseTokenTester struct {
	CaseName      string
	SigningMethod jwt.SigningMethod
	Token         string
	ExpectedToken jwt.Token
	ExpectedErr   error
}

func (s *SigningMethodParseTokenTester) Name() string {
	return s.CaseName
}

func (s *SigningMethodParseTokenTester) Test(t *testing.T) {
	parser := jwt.NewTokenParser(base64.RawURLEncoding, s.SigningMethod)

	token, err := parser.ParseToken(s.Token)
	assert.ErrorIs(t, err, s.ExpectedErr)
	assert.DeepEqual(t, token, s.ExpectedToken)
}
