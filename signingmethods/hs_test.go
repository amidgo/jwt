package signingmethods_test

import (
	"testing"

	"github.com/amidgo/jwt"
	"github.com/amidgo/jwt/signingmethods"
	"github.com/amidgo/tester"
)

func TestHMACCreate(t *testing.T) {
	secret := "totally secret secret"

	hs256 := signingmethods.NewHS256(secret)
	hs384 := signingmethods.NewHS384(secret)
	hs512 := signingmethods.NewHS512(secret)

	tester.RunNamedTesters(t,
		&SigningMethodCreateTokenTester{
			CaseName:      "HS256",
			SigningMethod: hs256,
			Payload: jwt.Payload{
				"name":    "dima",
				"roles":   []string{"admin", "user"},
				"user_id": 100,
			},
			ExpectedToken: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiZGltYSIsInJvbGVzIjpbImFkbWluIiwidXNlciJdLCJ1c2VyX2lkIjoxMDB9.hC2AAb13RgLlBw-BmMBEA4j-sFJ568cz8bzKjpCZMfY",
		},
		&SigningMethodCreateTokenTester{
			CaseName:      "HS384",
			SigningMethod: hs384,
			Payload: jwt.Payload{
				"name":    "dima",
				"roles":   []string{"admin", "user"},
				"user_id": 100,
			},
			ExpectedToken: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJuYW1lIjoiZGltYSIsInJvbGVzIjpbImFkbWluIiwidXNlciJdLCJ1c2VyX2lkIjoxMDB9.bbMqdbVCX5MKeT11VXCUMnX2nTIBdwR5NjYhLtLEUvsz6AdxuS8v6vtzTvQWYCJm",
		},
		&SigningMethodCreateTokenTester{
			CaseName:      "HS512",
			SigningMethod: hs512,
			Payload: jwt.Payload{
				"name":    "dima",
				"roles":   []string{"admin", "user"},
				"user_id": 100,
			},
			ExpectedToken: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJuYW1lIjoiZGltYSIsInJvbGVzIjpbImFkbWluIiwidXNlciJdLCJ1c2VyX2lkIjoxMDB9.FddtwwNTzM4K0uwBIwdQZyrjxjd9N9JrgfAw5yU0vtj2ieT5kd0bJ-OktQdazO-1MZ7P4J9Zw8zqc4sz9hJkVQ",
		},
	)
}

func TestHMACParse(t *testing.T) {
	secret := "totally secret secret"

	hs256 := signingmethods.NewHS256(secret)
	hs384 := signingmethods.NewHS384(secret)
	hs512 := signingmethods.NewHS512(secret)

	tester.RunNamedTesters(t,
		&SigningMethodParseTokenTester{
			CaseName:      "HS256",
			SigningMethod: hs256,
			ExpectedToken: jwt.Token{
				Header: jwt.Header{
					Type: "JWT",
					Alg:  "HS256",
				},
				Payload: jwt.Payload{
					"name":    "dima",
					"roles":   []any{"admin", "user"},
					"user_id": float64(100),
				},
			},
			Token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiZGltYSIsInJvbGVzIjpbImFkbWluIiwidXNlciJdLCJ1c2VyX2lkIjoxMDB9.hC2AAb13RgLlBw-BmMBEA4j-sFJ568cz8bzKjpCZMfY",
		},
		&SigningMethodParseTokenTester{
			CaseName:      "HS384",
			SigningMethod: hs384,
			ExpectedToken: jwt.Token{
				Header: jwt.Header{
					Type: "JWT",
					Alg:  "HS384",
				},
				Payload: jwt.Payload{
					"name":    "dima",
					"roles":   []any{"admin", "user"},
					"user_id": float64(100),
				},
			},
			Token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJuYW1lIjoiZGltYSIsInJvbGVzIjpbImFkbWluIiwidXNlciJdLCJ1c2VyX2lkIjoxMDB9.bbMqdbVCX5MKeT11VXCUMnX2nTIBdwR5NjYhLtLEUvsz6AdxuS8v6vtzTvQWYCJm",
		},
		&SigningMethodParseTokenTester{
			CaseName:      "HS512",
			SigningMethod: hs512,
			ExpectedToken: jwt.Token{
				Header: jwt.Header{
					Type: "JWT",
					Alg:  "HS512",
				},
				Payload: jwt.Payload{
					"name":    "dima",
					"roles":   []any{"admin", "user"},
					"user_id": float64(100),
				},
			},
			Token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJuYW1lIjoiZGltYSIsInJvbGVzIjpbImFkbWluIiwidXNlciJdLCJ1c2VyX2lkIjoxMDB9.FddtwwNTzM4K0uwBIwdQZyrjxjd9N9JrgfAw5yU0vtj2ieT5kd0bJ-OktQdazO-1MZ7P4J9Zw8zqc4sz9hJkVQ",
		},
	)
}
