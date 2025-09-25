package repository

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	db2 "github.com/janobono/go-util/db"
	"github.com/janobono/simple-auth/simple-auth-service/generated/sqlc"
	"github.com/janobono/simple-auth/simple-auth-service/internal/db"
)

type JwkRepository interface {
	AddJwk(ctx context.Context, data JwkData) (*Jwk, error)
	DeleteAll(ctx context.Context) error
	GetActiveJwk(ctx context.Context, use string) (*Jwk, error)
	GetJwk(ctx context.Context, id pgtype.UUID) (*Jwk, error)
	GetActiveJwks(ctx context.Context) ([]*Jwk, error)
}

type jwkRepositoryImpl struct {
	dataSource *db.DataSource
}

func NewJwkRepository(dataSource *db.DataSource) JwkRepository {
	return &jwkRepositoryImpl{dataSource}
}

func (j *jwkRepositoryImpl) AddJwk(ctx context.Context, data JwkData) (*Jwk, error) {
	jwk, err := j.dataSource.ExecTx(ctx, func(q *sqlc.Queries) (interface{}, error) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		publicKey := &privateKey.PublicKey

		privatePEM := encodePrivateKey(privateKey)
		publicPEM, err := encodePublicKey(publicKey)
		if err != nil {
			return nil, err
		}

		now := time.Now()

		jwk, err := q.AddJwk(ctx, sqlc.AddJwkParams{
			ID:         db2.NewUUID(),
			Kty:        "RSA",
			Use:        data.Use,
			Alg:        "RS256",
			PublicKey:  publicPEM,
			PrivateKey: privatePEM,
			Active:     true,
			CreatedAt:  db2.TimestampUTC(now),
			ExpiresAt:  db2.TimestampUTC(now.Add(data.Expiration)),
		})

		if err != nil {
			return nil, err
		}

		err = q.DeactivateJwks(ctx, sqlc.DeactivateJwksParams{ID: jwk.ID, Use: data.Use})
		if err != nil {
			return nil, err
		}

		err = q.DeleteNotActiveJwks(ctx, sqlc.DeleteNotActiveJwksParams{
			Use:       data.Use,
			ExpiresAt: db2.TimestampUTC(now),
		})
		if err != nil {
			return nil, err
		}

		return &jwk, nil
	})

	if err != nil {
		return nil, err
	}

	createdJwk, ok := jwk.(*sqlc.Jwk)
	if !ok {
		return nil, fmt.Errorf("invalid jwk type: %T", jwk)
	}

	return toJwk(createdJwk)
}

func (j *jwkRepositoryImpl) DeleteAll(ctx context.Context) error {
	return j.dataSource.Queries.TruncateTableJwk(ctx)
}

func (j *jwkRepositoryImpl) GetActiveJwk(ctx context.Context, use string) (*Jwk, error) {
	jwk, err := j.dataSource.Queries.GetActiveJwk(ctx, use)

	if err != nil {
		return nil, err
	}

	return toJwk(&jwk)
}

func (j *jwkRepositoryImpl) GetJwk(ctx context.Context, id pgtype.UUID) (*Jwk, error) {
	jwk, err := j.dataSource.Queries.GetJwk(ctx, id)

	if err != nil {
		return nil, err
	}

	return toJwk(&jwk)
}

func (j *jwkRepositoryImpl) GetActiveJwks(ctx context.Context) ([]*Jwk, error) {
	jwks, err := j.dataSource.Queries.GetActiveJwks(ctx)

	if err != nil {
		return nil, err
	}

	result := make([]*Jwk, len(jwks))
	for i, dbJwk := range jwks {
		jwk, err := toJwk(&dbJwk)
		if err != nil {
			return nil, err
		}
		result[i] = jwk
	}

	return result, nil
}
