package service

import (
	"context"
	"encoding/base64"
	"math/big"

	"github.com/janobono/simple-auth/simple-auth-service/generated/openapi"
	"github.com/janobono/simple-auth/simple-auth-service/internal/repository"
)

type JwkService struct {
	jwkRepository repository.JwkRepository
}

func NewJwkService(jwkRepository repository.JwkRepository) *JwkService {
	return &JwkService{jwkRepository}
}

func (js *JwkService) GetJwks(ctx context.Context) (*openapi.Jwks, error) {
	activeJwks, err := js.jwkRepository.GetActiveJwks(ctx)
	if err != nil {
		return nil, err
	}

	keys := make([]openapi.Jwk, 0, len(activeJwks))
	for _, jwk := range activeJwks {
		n := base64.RawURLEncoding.EncodeToString(jwk.PublicKey.N.Bytes())

		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(jwk.PublicKey.E)).Bytes())

		keys = append(keys, openapi.Jwk{
			Kty: jwk.Kty,
			Kid: jwk.ID.String(),
			Use: jwk.Use,
			Alg: jwk.Alg,
			N:   n,
			E:   e,
		})
	}

	return &openapi.Jwks{Keys: keys}, nil
}
