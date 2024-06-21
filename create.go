package jwt

import (
	"encoding/json"
	"fmt"
)

//go:generate mockgen -source create.go -destination mocks/create_mocks.go -package jwtmocks

type Encoder interface {
	EncodeToString(segment []byte) string
}

type JwtTokenCreator struct {
	encoder       Encoder
	signingMethod SigningMethod
}

func NewTokenCreator(encoder Encoder, signingMethod SigningMethod) *JwtTokenCreator {
	return &JwtTokenCreator{encoder: encoder, signingMethod: signingMethod}
}

func MakeJwtHeader(alg string) string {
	return fmt.Sprintf(`{"typ":"JWT","alg":"%s"}`, alg)
}

func (c *JwtTokenCreator) CreateToken(payload Payload) (string, error) {
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed marshal payload, %w", err)
	}

	headerString := MakeJwtHeader(c.signingMethod.Alg())
	encodedHeader := c.encoder.EncodeToString([]byte(headerString))
	encodedPayload := c.encoder.EncodeToString(rawPayload)
	signingString := encodedHeader + "." + encodedPayload

	sign, err := c.signingMethod.Sign(signingString)
	if err != nil {
		return "", err
	}

	encodedSign := c.encoder.EncodeToString(sign)

	return signingString + "." + encodedSign, nil
}
