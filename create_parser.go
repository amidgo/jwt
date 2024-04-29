package jwt

//go:generate mockgen -source create_parser.go -destination create_parser_mocks.go -package jwt -aux_files=github.com/Esus-Project/esus-auth/pkg/jwt=create.go,github.com/Esus-Project/esus-auth/pkg/jwt=parse.go

type TokenParser interface {
	ParseToken(accessToken string) (Token, error)
}

type TokenCreator interface {
	CreateToken(payload Payload) (string, error)
}

type TokenCreateParser interface {
	TokenCreator
	TokenParser
}

type EncodeDecoder interface {
	Decoder
	Encoder
}

func NewTokenCreateParser(encDec EncodeDecoder, signingMethod SigningMethod) TokenCreateParser {
	return struct {
		TokenParser
		TokenCreator
	}{
		TokenParser:  NewTokenParser(encDec, signingMethod),
		TokenCreator: NewTokenCreator(encDec, signingMethod),
	}
}
