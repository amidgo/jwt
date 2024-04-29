package jwt

type Token struct {
	Header  Header
	Payload Payload
}

type Header struct {
	Type string `json:"typ"`
	Alg  string `json:"alg"`
}

type Payload map[string]any

func NewToken(header Header, payload Payload) Token {
	return Token{
		Header:  header,
		Payload: payload,
	}
}
