package signingmethods

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"errors"
)

var ErrSignatureInvalid = errors.New("signature invalid")

type HS struct {
	secret []byte
	hash   crypto.Hash
}

func (h *HS) Sign(signingString string) ([]byte, error) {
	hasher := hmac.New(h.hash.New, h.secret)

	_, err := hasher.Write([]byte(signingString))
	if err != nil {
		return nil, err
	}

	return hasher.Sum(nil), nil
}

func (h *HS) Verify(signed string, sign []byte) error {
	hasher := hmac.New(h.hash.New, h.secret)

	_, err := hasher.Write([]byte(signed))
	if err != nil {
		return err
	}

	if !hmac.Equal(sign, hasher.Sum(nil)) {
		return ErrSignatureInvalid
	}

	return nil
}

type HS256 struct{ *HS }

func NewHS256(secret string) *HS256 {
	return &HS256{HS: &HS{secret: []byte(secret), hash: crypto.SHA256}}
}

func (h *HS256) Alg() string {
	return "HS256"
}

type HS384 struct{ *HS }

func NewHS384(secret string) *HS384 {
	return &HS384{HS: &HS{secret: []byte(secret), hash: crypto.SHA384}}
}

func (h *HS384) Alg() string {
	return "HS384"
}

type HS512 struct{ *HS }

func NewHS512(secret string) *HS512 {
	return &HS512{HS: &HS{secret: []byte(secret), hash: crypto.SHA512}}
}

func (h *HS512) Alg() string {
	return "HS512"
}
