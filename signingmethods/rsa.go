package signingmethods

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
)

type RS struct {
	private *rsa.PrivateKey
	hash    crypto.Hash
}

func (r *RS) Sign(singingString string) ([]byte, error) {
	hasher := r.hash.New()

	_, err := hasher.Write([]byte(singingString))
	if err != nil {
		return nil, err
	}

	return rsa.SignPKCS1v15(rand.Reader, r.private, r.hash, hasher.Sum(nil))
}

func (r *RS) Verify(signed string, sign []byte) error {
	hasher := r.hash.New()

	_, err := hasher.Write([]byte(signed))
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(&r.private.PublicKey, r.hash, hasher.Sum(nil), sign)
}

type RS256 struct{ *RS }

func (r *RS256) Alg() string {
	return "RS256"
}

func NewRS256(private *rsa.PrivateKey) *RS256 {
	return &RS256{RS: &RS{private: private, hash: crypto.SHA256}}
}

type RS384 struct{ *RS }

func (r RS384) Alg() string {
	return "RS384"
}

func NewRS384(private *rsa.PrivateKey) *RS384 {
	return &RS384{RS: &RS{private: private, hash: crypto.SHA384}}
}

type RS512 struct{ *RS }

func (r RS512) Alg() string {
	return "RS512"
}

func NewRS512(private *rsa.PrivateKey) *RS512 {
	return &RS512{RS: &RS{private: private, hash: crypto.SHA512}}
}
