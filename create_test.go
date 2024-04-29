package jwt_test

import (
	"crypto/rsa"
	"slices"
	"testing"

	"github.com/amidgo/jwt"
	"github.com/amidgo/tester"
	"github.com/golang/mock/gomock"
)

func NewMockSigningMethod(ctrl *gomock.Controller, alg string) *jwt.MockSigningMethod {
	signingMethod := jwt.NewMockSigningMethod(ctrl)
	signingMethod.EXPECT().Alg().Return(alg).AnyTimes()
	return signingMethod
}

func Test_CreateToken(t *testing.T) {
	const signingMethodAlg = "HS256"
	ctrl := gomock.NewController(t)
	encoder := jwt.NewMockEncoder(ctrl)
	signingMethod := NewMockSigningMethod(ctrl, signingMethodAlg)
	caseCreator := CreateTokenCaseCreator{
		Encoder:       encoder,
		SigningMethod: signingMethod,
	}
	testerContainer := CreateTokenTesterContainer{
		CaseCreator: &caseCreator,
	}
	testerContainer.AddSignFailedCase()
	testerContainer.AddSuccessfullCase()
	testerContainer.Test(t)
}

type CreateTokenTesterContainer struct {
	CaseCreator *CreateTokenCaseCreator
	tester.TesterContainer
}

func (c *CreateTokenTesterContainer) AddSignFailedCase() {
	signFailedCase := c.CaseCreator.NewCreateTokenCase("Sign Failed")
	signFailedCase.Description = "SigningMethod.Sign method return error, method could return this error"
	signFailedCase.Input = CreateTokenCallInput{
		Payload: jwt.Payload{"id": 1},
	}
	signFailedCase.AddHeaderEncodeCall(EncoderCallOutput{
		Encoded: "aboabaasdf",
	})
	signFailedCase.AddPayloadEncodeCall(EncoderCallOutput{
		Encoded: "sdiqwrjjwerafglnasdfje",
	})
	signFailedCase.AddSignCall(SigningMethodSignCallOutput{
		Err: rsa.ErrMessageTooLong,
	})
	signFailedCase.ExpectedOutput.Err = rsa.ErrMessageTooLong
	c.AddTester(signFailedCase)
}

func (c *CreateTokenTesterContainer) AddSuccessfullCase() {
	successCase := c.CaseCreator.NewCreateTokenCase("Successfull Case")
	successCase.Description = "Succcess case, should return nil error and valid token"
	successCase.Input = CreateTokenCallInput{
		Payload: jwt.Payload{"id": 2},
	}
	successCase.AddHeaderEncodeCall(EncoderCallOutput{
		Encoded: "dsfjaljfsdakjlsdafjklfsanmrwqeipjxz",
	})
	successCase.AddPayloadEncodeCall(EncoderCallOutput{
		Encoded: "rreiweqjasdnzmzxcvmsdoqwerkszvxasdfqer",
	})
	successCase.AddSignCall(SigningMethodSignCallOutput{
		SignedData: []byte("dweiroadsqwerkalsdnfjowejrkljweporiualsdkfnalksjdruiweuro"),
	})
	successCase.AddSignEncodeCall(EncoderCallOutput{
		Encoded: "adfsafs",
	})
	successCase.ExpectedOutput.Token = successCase.ExpectedToken()
	c.AddTester(successCase)
}

type ByteMatcher struct {
	Data []byte
}

func (m ByteMatcher) Matches(x interface{}) bool {
	byteSlice, ok := x.([]byte)
	if !ok {
		return false
	}
	return slices.Equal(byteSlice, m.Data)
}

func (m ByteMatcher) String() string {
	return string(m.Data)
}
