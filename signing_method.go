package jwt

//go:generate mockgen -source signing_method.go -destination mocks/signing_method_mocks.go -package jwtmocks

type SigningMethod interface {
	Alg() string
	Sign(stringToSign string) ([]byte, error)
	Verify(verifyData string, sign []byte) error
}
