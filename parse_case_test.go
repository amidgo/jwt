package jwt_test

import (
	"fmt"
	"testing"

	"github.com/amidgo/jwt"
	"gotest.tools/v3/assert"
)

type ParseTokenTester struct {
	Name        string
	Description string

	Decoder       *jwt.MockDecoder
	SigningMethod *jwt.MockSigningMethod

	Input          ParseTokenInput
	ExpectedOutput ParseTokenOutput
}

type ParseTokenInput struct {
	AccessToken string
}

type ParseTokenOutput struct {
	Token jwt.Token
	Err   error
}

func (p *ParseTokenTester) AddDecoderCall(input DecoderInput, output DecoderOutput) {
	p.Decoder.EXPECT().
		DecodeString(input.DecodeString).
		Return(output.DecodedData, output.Err).
		Times(1)
}

type DecoderInput struct {
	DecodeString string
}

type DecoderOutput struct {
	DecodedData []byte
	Err         error
}

func (p *ParseTokenTester) AddSigningMethodVerifyCall(input SigningMethodVerifyCallInput, output SigningMethodVerifyCallOutput) {
	p.SigningMethod.EXPECT().
		Verify(input.VerifyData, input.Sign).
		Return(output.Err).
		Times(1)
}

type SigningMethodVerifyCallInput struct {
	VerifyData string
	Sign       []byte
}

type SigningMethodVerifyCallOutput struct {
	Err error
}

func (p *ParseTokenTester) Test(t *testing.T) {
	parser := jwt.NewTokenParser(p.Decoder, p.SigningMethod)
	token, err := parser.ParseToken(p.Input.AccessToken)
	actualOutput := ParseTokenOutput{
		Token: token,
		Err:   err,
	}
	p.assertActual(t, actualOutput)
	t.Logf("Case %s is Successfull", p.Name)
}

func (p *ParseTokenTester) assertActual(t *testing.T, actual ParseTokenOutput) {
	actualToken := actual.Token
	expectedToken := p.ExpectedOutput.Token

	assert.Equal(t, expectedToken.Header, actualToken.Header, "token header not equal, %s", p.String())
	assert.DeepEqual(t, expectedToken.Payload, actualToken.Payload)

	assert.ErrorIs(t, actual.Err, p.ExpectedOutput.Err, "wrong err, %s", p.String())
}

func (c *ParseTokenTester) String() string {
	return fmt.Sprintf("name: %s, description: %s", c.Name, c.Description)
}

type ParseTokenCaseCreator struct {
	Decoder       *jwt.MockDecoder
	SigningMethod *jwt.MockSigningMethod
}

func (p *ParseTokenCaseCreator) NewParseTokenCase(name string) *ParseTokenCase {
	return &ParseTokenCase{
		ParseTokenTester: &ParseTokenTester{
			Name:          name,
			Decoder:       p.Decoder,
			SigningMethod: p.SigningMethod,
		},
	}
}

type ParseTokenCase struct {
	rawToken         jwt.RawToken
	signDecodeOutput DecoderOutput
	*ParseTokenTester
}

func (p *ParseTokenCase) SetRawTokenFromInput(input ParseTokenInput) {
	p.rawToken, _ = jwt.ParseRawToken(input.AccessToken)
}

func (p *ParseTokenCase) AddHeaderDecodeCall(output DecoderOutput) {
	input := DecoderInput{
		DecodeString: p.rawToken.Header(),
	}
	p.AddDecoderCall(input, output)
}

func (p *ParseTokenCase) AddPayloadDecodeCall(output DecoderOutput) {
	input := DecoderInput{
		DecodeString: p.rawToken.Payload(),
	}
	p.AddDecoderCall(input, output)
}

func (p *ParseTokenCase) AddSignDecodeCall(output DecoderOutput) {
	input := DecoderInput{
		DecodeString: p.rawToken.Sign(),
	}
	p.AddDecoderCall(input, output)
	p.signDecodeOutput = output
}

func (p *ParseTokenCase) AddSignVerifyCall(output SigningMethodVerifyCallOutput) {
	input := SigningMethodVerifyCallInput{
		VerifyData: p.rawToken.Header() + "." + p.rawToken.Payload(),
		Sign:       p.signDecodeOutput.DecodedData,
	}
	p.AddSigningMethodVerifyCall(input, output)
}
