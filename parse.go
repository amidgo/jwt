package jwt

import (
	"encoding/json"
	"fmt"
	"strings"
)

//go:generate mockgen -source parse.go -destination parse_mocks.go -package jwt

var (
	ErrBadToken        TokenInvalidError = "bad_token"
	ErrSignNotVerified TokenInvalidError = "wrong_sign"
	ErrUnmarshalToken  TokenInvalidError = "failed_unmarshal"
	ErrWrongAlgoritm   TokenInvalidError = "wrong_algoritm"
)

type RawToken [3]string

func (r RawToken) Header() string {
	return r[0]
}

func (r RawToken) Payload() string {
	return r[1]
}

func (r RawToken) Sign() string {
	return r[2]
}

type Decoder interface {
	DecodeString(s string) ([]byte, error)
}

type JwtTokenParser struct {
	decoder       Decoder
	signingMethod SigningMethod
}

func NewTokenParser(decoder Decoder, signingMethod SigningMethod) *JwtTokenParser {
	return &JwtTokenParser{decoder: decoder, signingMethod: signingMethod}
}

func (p *JwtTokenParser) ParseToken(accessToken string) (token Token, err error) {
	rawToken, err := ParseRawToken(accessToken)
	if err != nil {
		return
	}
	token, err = p.DecodeToken(rawToken)
	if err != nil {
		return
	}
	err = p.VerifyHeaderAlg(token.Header)
	if err != nil {
		return
	}
	err = p.VerifyRawTokenSign(rawToken)
	if err != nil {
		return
	}
	return token, nil
}

func ParseRawToken(accessToken string) (RawToken, error) {
	rawToken := strings.Split(accessToken, ".")
	if len(rawToken) != 3 {
		return [3]string{}, ErrBadToken
	}
	return RawToken(rawToken), nil
}

func (p *JwtTokenParser) DecodeToken(rawToken RawToken) (token Token, err error) {
	header, err := p.decoder.DecodeString(rawToken.Header())
	if err != nil {
		return token, fmt.Errorf("failed decode header, %w", err)
	}
	err = json.Unmarshal(header, &token.Header)
	if err != nil {
		return token, fmt.Errorf("failed set header, %w", ErrUnmarshalToken)
	}
	payload, err := p.decoder.DecodeString(rawToken.Payload())
	if err != nil {
		return token, fmt.Errorf("failed decode payload, %w", err)
	}
	err = json.Unmarshal(payload, &token.Payload)
	if err != nil {
		return token, fmt.Errorf("failed set payload, %w", ErrUnmarshalToken)
	}
	return
}

func (p *JwtTokenParser) VerifyHeaderAlg(header Header) error {
	if p.signingMethod.Alg() != header.Alg {
		return ErrWrongAlgoritm
	}
	return nil
}

func (p *JwtTokenParser) VerifyRawTokenSign(rawToken RawToken) error {
	sign, err := p.decoder.DecodeString(rawToken.Sign())
	if err != nil {
		return fmt.Errorf("failed decode sign segment, %w", err)
	}
	signed := rawToken.Header() + "." + rawToken.Payload()
	err = p.signingMethod.Verify(signed, sign)
	if err != nil {
		return fmt.Errorf("failed verify token sign, %w", err)
	}
	return nil
}
