package jwt_test

import (
	"testing"

	"github.com/amidgo/jwt"
	jwtmocks "github.com/amidgo/jwt/mocks"
	"github.com/amidgo/tester"
	"github.com/golang/mock/gomock"
	"gotest.tools/v3/assert"
)

func Test_ParseRaw(t *testing.T) {
	cases := []struct {
		rawToken    string
		expectedErr error

		header, payload, sign string
	}{
		{
			rawToken: "asdkfjalsdjl.sadljfewir.asldfkjasldjf",

			header:  "asdkfjalsdjl",
			payload: "sadljfewir",
			sign:    "asldfkjasldjf",
		},
		{
			rawToken:    "asdkfjalsdjl.sadljfewir.asldfkjasldjf.",
			expectedErr: jwt.ErrBadToken,
		},
		{
			rawToken: "asdkfjalsdjl.sadljfewir.",

			header:  "asdkfjalsdjl",
			payload: "sadljfewir",
		},
		{
			expectedErr: jwt.ErrBadToken,
		},
		{
			rawToken:    "asdkfjalsdjl.",
			expectedErr: jwt.ErrBadToken,
		},
	}

	for _, cs := range cases {
		raw, err := jwt.ParseRawToken(cs.rawToken)
		assert.ErrorIs(t, err, cs.expectedErr, "wrong err")

		assert.Equal(t, raw.Header(), cs.header, "raw header not equal")
		assert.Equal(t, raw.Payload(), cs.payload, "raw payload not equal")
		assert.Equal(t, raw.Sign(), cs.sign, "raw sign not equal")
	}
}

func Test_ParseToken(t *testing.T) {
	const signingMethodAlg = "RS256"
	ctrl := gomock.NewController(t)

	decoder := jwtmocks.NewMockDecoder(ctrl)
	signingMethod := NewMockSigningMethod(ctrl, signingMethodAlg)

	caseCreator := ParseTokenCaseCreator{
		Decoder:       decoder,
		SigningMethod: signingMethod,
	}
	caseContainer := ParseTokenCaseContainer{
		CaseCreator: &caseCreator,
	}
	caseContainer.AddParseRawFailedCase()
	caseContainer.AddDecodeRawHeaderFailedCase()
	caseContainer.AddFailedUnmarshalHeaderCase()
	caseContainer.AddDecodeRawPayloadFailedCase()
	caseContainer.AddFailedUnmarshalPayloadCase()
	caseContainer.AddWrongAlgoritmCase()
	caseContainer.AddDecodeSignFailedCase()
	caseContainer.AddFailedSignVerifyCase()
	caseContainer.AddSuccessfullCase()

	caseContainer.Test(t)
}

type ParseTokenCaseContainer struct {
	tester.TesterContainer
	CaseCreator *ParseTokenCaseCreator
}

func (p *ParseTokenCaseContainer) AddParseRawFailedCase() {
	parseRawFailedCase := p.CaseCreator.NewParseTokenCase("Parse Raw Failed")
	parseRawFailedCase.Description = "Parse Raw should return error because input access token invalid"
	parseRawFailedCase.Input = ParseTokenInput{
		AccessToken: "sdflkerjasdkld",
	}
	parseRawFailedCase.ExpectedOutput = ParseTokenOutput{
		Err: jwt.ErrBadToken,
	}
	p.AddTester(parseRawFailedCase)
}

func (p *ParseTokenCaseContainer) AddDecodeRawHeaderFailedCase() {
	decodeHeaderFailedCase := p.CaseCreator.NewParseTokenCase("Decode Raw Header Failed")
	decodeHeaderFailedCase.Description = "Method should return error because decoder return error"
	input := ParseTokenInput{
		AccessToken: "sdfdsljfkasfdjl.sdfkjdfljasld.adfkadl",
	}
	decodeHeaderFailedCase.Input = input
	decodeHeaderFailedCase.SetRawTokenFromInput(input)
	decodeHeaderFailedCase.AddHeaderDecodeCall(
		DecoderOutput{Err: jwt.ErrBadToken},
	)
	decodeHeaderFailedCase.ExpectedOutput = ParseTokenOutput{
		Err: jwt.ErrBadToken,
	}
	p.AddTester(decodeHeaderFailedCase)
}

func (p *ParseTokenCaseContainer) AddFailedUnmarshalHeaderCase() {
	failedUnmarshalHeaderCase := p.CaseCreator.NewParseTokenCase("Failed Unmarshal Decoded Header")
	failedUnmarshalHeaderCase.Description = "Header not json, json.Unmarshal return error"
	input := ParseTokenInput{
		AccessToken: "sdfdsljfkasfdjl.sdfkjdfljasld.adfkadl",
	}
	failedUnmarshalHeaderCase.Input = input
	failedUnmarshalHeaderCase.SetRawTokenFromInput(input)

	failedUnmarshalHeaderCase.AddHeaderDecodeCall(
		DecoderOutput{DecodedData: []byte("dasfljkasdlfjksdf")},
	)
	failedUnmarshalHeaderCase.ExpectedOutput = ParseTokenOutput{
		Err: jwt.ErrUnmarshalToken,
	}
	p.AddTester(failedUnmarshalHeaderCase)
}

func (p *ParseTokenCaseContainer) AddDecodeRawPayloadFailedCase() {
	decodeRawPayloadFailedCase := p.CaseCreator.NewParseTokenCase("Failed Decode Raw Payload")
	decodeRawPayloadFailedCase.Description = "Decode payload return error, parse token should return this error"
	input := ParseTokenInput{
		AccessToken: "sdfdsljfkasfdjl.sdfkjdfljasld.adfkadl",
	}
	decodeRawPayloadFailedCase.Input = input
	decodeRawPayloadFailedCase.SetRawTokenFromInput(input)

	decodeRawPayloadFailedCase.AddHeaderDecodeCall(
		DecoderOutput{DecodedData: []byte(jwt.MakeJwtHeader("RANDOM"))},
	)
	decodeRawPayloadFailedCase.AddPayloadDecodeCall(
		DecoderOutput{Err: jwt.ErrBadToken},
	)
	expectedOutput := ParseTokenOutput{
		Token: jwt.Token{Header: jwt.Header{Alg: "RANDOM", Type: "JWT"}},
		Err:   jwt.ErrBadToken,
	}
	decodeRawPayloadFailedCase.ExpectedOutput = expectedOutput
	p.AddTester(decodeRawPayloadFailedCase)
}

func (p *ParseTokenCaseContainer) AddFailedUnmarshalPayloadCase() {
	failedUnmarshalPayloadCase := p.CaseCreator.NewParseTokenCase("Failed Unmarshal Payload")
	failedUnmarshalPayloadCase.Description = "Payload not json, json.Unmarshal return error"
	input := ParseTokenInput{
		AccessToken: "sdfdsljfkasfdjl.sdfkjdfljasld.adfkadl",
	}
	failedUnmarshalPayloadCase.Input = input
	failedUnmarshalPayloadCase.SetRawTokenFromInput(input)

	failedUnmarshalPayloadCase.AddHeaderDecodeCall(
		DecoderOutput{DecodedData: []byte(jwt.MakeJwtHeader("RANDOM"))},
	)
	failedUnmarshalPayloadCase.AddPayloadDecodeCall(
		DecoderOutput{DecodedData: []byte("ssdfasddljkfljadfadfljewq")},
	)
	failedUnmarshalPayloadCase.ExpectedOutput = ParseTokenOutput{
		Token: jwt.Token{Header: jwt.Header{Alg: "RANDOM", Type: "JWT"}},
		Err:   jwt.ErrUnmarshalToken,
	}
	p.AddTester(failedUnmarshalPayloadCase)
}

func (p *ParseTokenCaseContainer) AddWrongAlgoritmCase() {
	wrongAlgoritmCase := p.CaseCreator.NewParseTokenCase("Wrong Header Algoritm")
	wrongAlgoritmCase.Description = "In decoded header alg field not equal SigningMethod.Alg, method should return jwt.ErrWrongAlgoritm"
	input := ParseTokenInput{
		AccessToken: "sdfdsljfkasfdjl.sdfkjdfljasld.adfkadl",
	}

	wrongAlgoritmCase.Input = input
	wrongAlgoritmCase.SetRawTokenFromInput(input)
	const alg = "RAsdlkfasdweruz"

	wrongAlgoritmCase.AddHeaderDecodeCall(
		DecoderOutput{DecodedData: []byte(jwt.MakeJwtHeader(alg))},
	)
	wrongAlgoritmCase.AddPayloadDecodeCall(
		DecoderOutput{DecodedData: []byte(`{"id":1}`)},
	)

	wrongAlgoritmCase.ExpectedOutput = ParseTokenOutput{
		Token: jwt.Token{
			Header: jwt.Header{
				Alg:  alg,
				Type: "JWT",
			},
			Payload: jwt.Payload{
				"id": float64(1),
			},
		},
		Err: jwt.ErrWrongAlgoritm,
	}
	p.AddTester(wrongAlgoritmCase)
}

func (p *ParseTokenCaseContainer) AddDecodeSignFailedCase() {
	decodeSignFailedCase := p.CaseCreator.NewParseTokenCase("Decode Sign Failed")
	decodeSignFailedCase.Description = "Decode sign return error, ParseToken should return this error"

	input := ParseTokenInput{
		AccessToken: "sdfdsljfkasfdjl.sdfkjdfljasld.adfkadl",
	}

	decodeSignFailedCase.Input = input
	decodeSignFailedCase.SetRawTokenFromInput(input)
	var alg = p.CaseCreator.SigningMethod.Alg()

	decodeSignFailedCase.AddHeaderDecodeCall(
		DecoderOutput{DecodedData: []byte(jwt.MakeJwtHeader(alg))},
	)
	decodeSignFailedCase.AddPayloadDecodeCall(
		DecoderOutput{DecodedData: []byte(`{"id":1}`)},
	)
	decodeSignFailedCase.AddSignDecodeCall(
		DecoderOutput{
			DecodedData: []byte("sdkfwerjksajweds"),
			Err:         jwt.ErrBadToken,
		},
	)

	decodeSignFailedCase.ExpectedOutput = ParseTokenOutput{
		Token: jwt.Token{
			Header: jwt.Header{
				Alg:  alg,
				Type: "JWT",
			},
			Payload: jwt.Payload{
				"id": float64(1),
			},
		},
		Err: jwt.ErrBadToken,
	}
	p.AddTester(decodeSignFailedCase)
}

func (p *ParseTokenCaseContainer) AddFailedSignVerifyCase() {
	failedSignVerifyCase := p.CaseCreator.NewParseTokenCase("Failed verify Sign")
	failedSignVerifyCase.Description = "SigningMethod.Verify return error, ParseToken should return this error"
	input := ParseTokenInput{
		AccessToken: "sdfdsljfkasfdjl.sdfkjdfljasld.adfkadl",
	}
	failedSignVerifyCase.Input = input
	failedSignVerifyCase.SetRawTokenFromInput(input)
	var alg = p.CaseCreator.SigningMethod.Alg()
	const decodedSign = "sdkfwerjksajweds"

	failedSignVerifyCase.AddHeaderDecodeCall(
		DecoderOutput{DecodedData: []byte(jwt.MakeJwtHeader(alg))},
	)
	failedSignVerifyCase.AddPayloadDecodeCall(
		DecoderOutput{DecodedData: []byte(`{"id":1}`)},
	)
	failedSignVerifyCase.AddSignDecodeCall(
		DecoderOutput{
			DecodedData: []byte(decodedSign),
		},
	)
	failedSignVerifyCase.AddSignVerifyCall(SigningMethodVerifyCallOutput{
		Err: jwt.ErrSignNotVerified,
	})
	failedSignVerifyCase.ExpectedOutput = ParseTokenOutput{
		Token: jwt.Token{
			Header: jwt.Header{
				Alg:  alg,
				Type: "JWT",
			},
			Payload: jwt.Payload{
				"id": float64(1),
			},
		},
		Err: jwt.ErrSignNotVerified,
	}
	p.AddTester(failedSignVerifyCase)
}

func (p *ParseTokenCaseContainer) AddSuccessfullCase() {
	successfullCase := p.CaseCreator.NewParseTokenCase("Successfull Case")

	input := ParseTokenInput{
		AccessToken: "sdfdsljfkasfdjl.sdfkjdfljasld.adfkadl",
	}

	successfullCase.Input = input
	successfullCase.SetRawTokenFromInput(input)

	var alg = p.CaseCreator.SigningMethod.Alg()
	const decodedSign = "sdkfwerjksajweds"

	successfullCase.AddHeaderDecodeCall(
		DecoderOutput{DecodedData: []byte(jwt.MakeJwtHeader(alg))},
	)
	successfullCase.AddPayloadDecodeCall(
		DecoderOutput{DecodedData: []byte(`{"id":1}`)},
	)
	successfullCase.AddSignDecodeCall(
		DecoderOutput{
			DecodedData: []byte(decodedSign),
		},
	)
	successfullCase.AddSignVerifyCall(SigningMethodVerifyCallOutput{
		Err: nil,
	})

	successfullCase.ExpectedOutput.Token = jwt.Token{
		Header: jwt.Header{
			Alg:  alg,
			Type: "JWT",
		},
		Payload: jwt.Payload{
			"id": float64(1),
		},
	}

	p.AddTester(successfullCase)
}
