package jwt

//go:generate mockgen -source signing_method.go -destination signing_method_mocks.go -package jwt

type SigningMethod interface {
	Alg() string
	Sign(stringToSign string) ([]byte, error)
	Verify(verifyData string, sign []byte) error
}
