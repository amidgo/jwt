package signingmethods_test

import (
	"testing"

	_ "embed"

	"github.com/amidgo/jwt"
	"github.com/amidgo/jwt/signingmethods"
	"github.com/amidgo/tester"
	"gotest.tools/v3/assert"
)

var (
	//go:embed testdata/sample_key
	privateKey []byte
)

func TestRSACreate(t *testing.T) {
	key, err := signingmethods.ParseRSAPrivateKeyFromPEM(privateKey)
	assert.NilError(t, err)

	rsa256 := signingmethods.NewRS256(key)
	rsa384 := signingmethods.NewRS384(key)
	rsa512 := signingmethods.NewRS512(key)

	tester.RunNamedTesters(t,
		&SigningMethodCreateTokenTester{
			CaseName:      "RSA256",
			SigningMethod: rsa256,
			Payload: jwt.Payload{
				"name": "dima",
			},
			ExpectedToken: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJuYW1lIjoiZGltYSJ9.0pkQBacZpVixrOjI1pZTI_RGfFwVelk4QVQKZkrCamF45D_pe0y8Ez6DiIvimi-WKQd_i0rIW8KJn_THtkL04IRIhBthx_7Jf5vbyO5R41NLCKHpeKT1j1vkTOPxS7D4nQ2WFe0Rm5nMsXsMGjSBa0l_N7iJEQ0A-fISc1z--aCnxMGLnYTRe5_dUDWXnjk_AcAHu68NsNzvHQq7tpcYzvH8KlxCx3t_c76A1390yQmFLY4ArF1or2w18wUtsCQRR9jZmSJxXIrlLfE413ebKttiRn5uUoUk2E8VkL36rOJ-nlWMwtJB-gYvNO1oYwlxnKG4CZN0kX-yHM1gxU_ynw",
		},
		&SigningMethodCreateTokenTester{
			CaseName:      "RSA384",
			SigningMethod: rsa384,
			Payload: jwt.Payload{
				"age":  10,
				"name": "dima",
			},
			ExpectedToken: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJhZ2UiOjEwLCJuYW1lIjoiZGltYSJ9.z4OjDtcnc6u1wVyf3YGkM9ioXbOYQXlq13tOma07npex4MJ-o2iDVwOugsDQwodq_8Fw8KKXmCtLygWDHIy_PHSwSlz9A9FLe4R4VlvtltJsLWV55zghuO6J48CQSQZzPNGTz2B1C2GFcjO52l74Aq05m5VMe-kOBjfrSPrmEujZRzIuGadxfN33GV7mfWyJ6I_Nw7RGLWwmhNE-UMC1v7QWdfVqsL7DcGQN-r3zFrdyXH6IOfFOiymHdsnaQUrv6CJ9hIMFFpT6aktFjMgubmlqngNZ1faUVVi6NaByTTZoQ5tgNKC0YezQTh0RFrKJqg_k_wSTqLXLTvT9gwdJ7g",
		},
		&SigningMethodCreateTokenTester{
			CaseName:      "RSA512",
			SigningMethod: rsa512,
			Payload: jwt.Payload{
				"age":  10,
				"name": "dima",
			},
			ExpectedToken: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJhZ2UiOjEwLCJuYW1lIjoiZGltYSJ9.o59O-W4nmZ6-Z5eeSF4L_WOVAcgWFb1LB7oKdoFzFHsEkDGP9Wf7N8wTfFmQSRL5TDyR6zTW907DFTaNDyN8ALTxmWvbQyw1AMK2HDZBeDBHWH1Jg43kEoja8n4nq74IJlNkutbkvk-OX7QnZEAvR4_OCaQud3LO1xJUmD1ABx_bDHBShNHWqvh9k6fMvUtKYEmk0brsgA4QyazeKGrCRW5pZ89RPDRKM-YrQY39THCZGwtFgk_w4aW3mOciBKZD9Gm5icDsn5NQyTfc_7djOkIP4UPncRsPkUAszmTVSrxQC28xuQRXFBkmRguPdqGBVc9SpJuex6IAzr9k_QeiyA",
		},
	)
}

func TestRSAParse(t *testing.T) {
	key, err := signingmethods.ParseRSAPrivateKeyFromPEM(privateKey)
	assert.NilError(t, err)

	rsa256 := signingmethods.NewRS256(key)
	rsa384 := signingmethods.NewRS384(key)
	rsa512 := signingmethods.NewRS512(key)

	tester.RunNamedTesters(t,
		&SigningMethodParseTokenTester{
			CaseName:      "RSA256",
			SigningMethod: rsa256,
			Token:         "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJuYW1lIjoiZGltYSJ9.0pkQBacZpVixrOjI1pZTI_RGfFwVelk4QVQKZkrCamF45D_pe0y8Ez6DiIvimi-WKQd_i0rIW8KJn_THtkL04IRIhBthx_7Jf5vbyO5R41NLCKHpeKT1j1vkTOPxS7D4nQ2WFe0Rm5nMsXsMGjSBa0l_N7iJEQ0A-fISc1z--aCnxMGLnYTRe5_dUDWXnjk_AcAHu68NsNzvHQq7tpcYzvH8KlxCx3t_c76A1390yQmFLY4ArF1or2w18wUtsCQRR9jZmSJxXIrlLfE413ebKttiRn5uUoUk2E8VkL36rOJ-nlWMwtJB-gYvNO1oYwlxnKG4CZN0kX-yHM1gxU_ynw",
			ExpectedToken: jwt.Token{
				Header: jwt.Header{
					Type: "JWT",
					Alg:  "RS256",
				},
				Payload: jwt.Payload{
					"name": "dima",
				},
			},
		},
		&SigningMethodParseTokenTester{
			CaseName:      "RSA384",
			SigningMethod: rsa384,
			Token:         "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJhZ2UiOjEwLCJuYW1lIjoiZGltYSJ9.z4OjDtcnc6u1wVyf3YGkM9ioXbOYQXlq13tOma07npex4MJ-o2iDVwOugsDQwodq_8Fw8KKXmCtLygWDHIy_PHSwSlz9A9FLe4R4VlvtltJsLWV55zghuO6J48CQSQZzPNGTz2B1C2GFcjO52l74Aq05m5VMe-kOBjfrSPrmEujZRzIuGadxfN33GV7mfWyJ6I_Nw7RGLWwmhNE-UMC1v7QWdfVqsL7DcGQN-r3zFrdyXH6IOfFOiymHdsnaQUrv6CJ9hIMFFpT6aktFjMgubmlqngNZ1faUVVi6NaByTTZoQ5tgNKC0YezQTh0RFrKJqg_k_wSTqLXLTvT9gwdJ7g",
			ExpectedToken: jwt.Token{
				Header: jwt.Header{
					Type: "JWT",
					Alg:  "RS384",
				},
				Payload: jwt.Payload{
					"age":  float64(10),
					"name": "dima",
				},
			},
		},
		&SigningMethodParseTokenTester{
			CaseName:      "RSA512",
			SigningMethod: rsa512,
			Token:         "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJhZ2UiOjEwLCJuYW1lIjoiZGltYSJ9.o59O-W4nmZ6-Z5eeSF4L_WOVAcgWFb1LB7oKdoFzFHsEkDGP9Wf7N8wTfFmQSRL5TDyR6zTW907DFTaNDyN8ALTxmWvbQyw1AMK2HDZBeDBHWH1Jg43kEoja8n4nq74IJlNkutbkvk-OX7QnZEAvR4_OCaQud3LO1xJUmD1ABx_bDHBShNHWqvh9k6fMvUtKYEmk0brsgA4QyazeKGrCRW5pZ89RPDRKM-YrQY39THCZGwtFgk_w4aW3mOciBKZD9Gm5icDsn5NQyTfc_7djOkIP4UPncRsPkUAszmTVSrxQC28xuQRXFBkmRguPdqGBVc9SpJuex6IAzr9k_QeiyA",
			ExpectedToken: jwt.Token{
				Header: jwt.Header{
					Type: "JWT",
					Alg:  "RS512",
				},
				Payload: jwt.Payload{
					"age":  float64(10),
					"name": "dima",
				},
			},
		},
	)
}
