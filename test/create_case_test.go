package jwt_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/amidgo/jwt"
	jwtmocks "github.com/amidgo/jwt/mocks"
	"gotest.tools/v3/assert"
)

type CreateTokenTester struct {
	Name        string
	Description string

	Encoder       *jwtmocks.MockEncoder
	SigningMethod *jwtmocks.MockSigningMethod

	Input          CreateTokenCallInput
	ExpectedOutput CreateTokenCallOutput
}

func (c *CreateTokenTester) AddEncoderCall(input EncoderCallInput, output EncoderCallOutput) {
	c.Encoder.EXPECT().
		EncodeToString(ByteMatcher{Data: input.Segment}).
		Return(output.Encoded).
		Times(1)
}

type EncoderCallInput struct {
	Segment []byte
}

func NewEncoderCallInput(segment []byte) EncoderCallInput {
	return EncoderCallInput{
		Segment: segment,
	}
}

type EncoderCallOutput struct {
	Encoded string
}

func NewEncoderCallOutput(encoded string) EncoderCallOutput {
	return EncoderCallOutput{
		Encoded: encoded,
	}
}

func (c *CreateTokenTester) AddSigningMethodSignCall(input SigningMethodSignCallInput, output SigningMethodSignCallOutput) {
	c.SigningMethod.EXPECT().
		Sign(input.StringToSign).
		Return(output.SignedData, output.Err).
		Times(1)
}

type SigningMethodSignCallInput struct {
	StringToSign string
}

type SigningMethodSignCallOutput struct {
	SignedData []byte
	Err        error
}

func (c *CreateTokenTester) Test(t *testing.T) {
	tokenCreator := jwt.NewTokenCreator(c.Encoder, c.SigningMethod)
	token, err := tokenCreator.CreateToken(c.Input.Payload)
	actualOutput := CreateTokenCallOutput{
		Token: token,
		Err:   err,
	}
	c.assertActual(t, actualOutput)
	t.Logf("Test Case %s is Successfull", c.Name)
}

type CreateTokenCallInput struct {
	Payload jwt.Payload
}

type CreateTokenCallOutput struct {
	Token string
	Err   error
}

func (c *CreateTokenTester) assertActual(t *testing.T, actual CreateTokenCallOutput) {
	assert.Equal(t, c.ExpectedOutput.Token, actual.Token, "token not equal, case failed, %s", c.String())
	assert.ErrorIs(t, c.ExpectedOutput.Err, actual.Err, "error not equal, case failed, %s", c.String())
}

func (c *CreateTokenTester) String() string {
	return fmt.Sprintf("name: %s, description: %s", c.Name, c.Description)
}

type CreateTokenCaseCreator struct {
	Encoder       *jwtmocks.MockEncoder
	SigningMethod *jwtmocks.MockSigningMethod
}

func (c *CreateTokenCaseCreator) NewCreateTokenCase(name string) *CreateTokenCase {
	createTokenCase := CreateTokenTester{Name: name, Encoder: c.Encoder, SigningMethod: c.SigningMethod}
	return &CreateTokenCase{
		CreateTokenTester: &createTokenCase,
	}
}

type CreateTokenCase struct {
	*CreateTokenTester
	HeaderEncodeOutput, PayloadEncodeOutput, SignEncoderOutput EncoderCallOutput
	SignOutput                                                 SigningMethodSignCallOutput
}

func (c *CreateTokenCase) AddHeaderEncodeCall(output EncoderCallOutput) {
	headerString := jwt.MakeJwtHeader(c.SigningMethod.Alg())
	c.AddEncoderCall(EncoderCallInput{Segment: []byte(headerString)}, output)
	c.HeaderEncodeOutput = output
}

func (c *CreateTokenCase) AddPayloadEncodeCall(output EncoderCallOutput) {
	rawPayload, _ := json.Marshal(c.Input.Payload)
	c.AddEncoderCall(EncoderCallInput{Segment: rawPayload}, output)
	c.PayloadEncodeOutput = output
}

func (c *CreateTokenCase) AddSignCall(signOutput SigningMethodSignCallOutput) {
	signingString := c.HeaderEncodeOutput.Encoded + "." + c.PayloadEncodeOutput.Encoded
	signInput := SigningMethodSignCallInput{
		StringToSign: signingString,
	}
	c.AddSigningMethodSignCall(signInput, signOutput)
	c.SignOutput = signOutput
}

func (c *CreateTokenCase) AddSignEncodeCall(output EncoderCallOutput) {
	input := EncoderCallInput{
		Segment: c.SignOutput.SignedData,
	}
	c.AddEncoderCall(input, output)
	c.SignEncoderOutput = output
}

func (c *CreateTokenCase) ExpectedToken() string {
	return c.HeaderEncodeOutput.Encoded + "." + c.PayloadEncodeOutput.Encoded + "." + c.SignEncoderOutput.Encoded
}
