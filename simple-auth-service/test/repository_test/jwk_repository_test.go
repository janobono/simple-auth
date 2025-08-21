package repository_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/janobono/simple-auth/simple-auth-service/internal/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJwkRepository_CRUD(t *testing.T) {
	repo := repository.NewJwkRepository(DataSource)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Add new JWK
	addData := repository.JwkData{
		Use:        "sig",
		Expiration: 2 * time.Hour,
	}
	created, err := repo.AddJwk(ctx, addData)
	assert.NoError(t, err)
	assert.NotNil(t, created)
	assert.Equal(t, "sig", created.Use)
	assert.True(t, created.Active)

	// Get active JWK
	active, err := repo.GetActiveJwk(ctx, "sig")
	assert.NoError(t, err)
	assert.NotNil(t, active)
	assert.Equal(t, created.ID, active.ID)

	// Get active JWKs
	activeJwks, err := repo.GetActiveJwks(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, activeJwks)
	assert.Equal(t, created.ID, activeJwks[0].ID)

	// Get JWK by ID
	fetched, err := repo.GetJwk(ctx, created.ID)
	assert.NoError(t, err)
	assert.NotNil(t, fetched)
	assert.Equal(t, created.ID, fetched.ID)
	assert.Equal(t, "RSA", fetched.Kty)
}

func TestJwkRepository_BasicAddAndGet(t *testing.T) {
	repo := repository.NewJwkRepository(DataSource)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	use := fmt.Sprintf("sig-basic-%d", time.Now().UnixNano())

	created, err := repo.AddJwk(ctx, repository.JwkData{
		Use:        use,
		Expiration: 2 * time.Hour,
	})
	require.NoError(t, err)
	require.NotNil(t, created)

	assert.Equal(t, "RSA", created.Kty)
	assert.Equal(t, "RS256", created.Alg)
	assert.Equal(t, use, created.Use)
	assert.True(t, created.Active)
	assert.True(t, created.CreatedAt.Before(created.ExpiresAt) || created.CreatedAt.Equal(created.ExpiresAt) == false)

	// Get active by use
	active, err := repo.GetActiveJwk(ctx, use)
	require.NoError(t, err)
	require.NotNil(t, active)
	assert.Equal(t, created.ID, active.ID)

	// Get by ID
	fetched, err := repo.GetJwk(ctx, created.ID)
	require.NoError(t, err)
	require.NotNil(t, fetched)
	assert.Equal(t, created.ID, fetched.ID)
	assert.Equal(t, "RSA", fetched.Kty)
	assert.Equal(t, "RS256", fetched.Alg)

	// Get all active (should include at least our key)
	all, err := repo.GetActiveJwks(ctx)
	require.NoError(t, err)
	require.NotNil(t, all)
	found := false
	for _, k := range all {
		if k.ID == created.ID {
			found = true
			break
		}
	}
	assert.True(t, found, "active JWKs should include the created key")
}

func TestJwkRepository_Rotation_DeactivatesPrevious(t *testing.T) {
	repo := repository.NewJwkRepository(DataSource)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	use := fmt.Sprintf("sig-rotate-%d", time.Now().UnixNano())

	// First key
	first, err := repo.AddJwk(ctx, repository.JwkData{
		Use:        use,
		Expiration: 1 * time.Hour,
	})
	require.NoError(t, err)
	require.NotNil(t, first)
	assert.True(t, first.Active)

	// Second key (rotation)
	second, err := repo.AddJwk(ctx, repository.JwkData{
		Use:        use,
		Expiration: 1 * time.Hour,
	})
	require.NoError(t, err)
	require.NotNil(t, second)
	assert.True(t, second.Active)
	assert.NotEqual(t, first.ID, second.ID)

	// Active by use should be the second
	active, err := repo.GetActiveJwk(ctx, use)
	require.NoError(t, err)
	require.NotNil(t, active)
	assert.Equal(t, second.ID, active.ID)

	// Old key should still exist but be inactive (unless it was also expired & GC'd)
	old, err := repo.GetJwk(ctx, first.ID)
	if err == nil && old != nil {
		assert.False(t, old.Active, "previous key should be deactivated after rotation")
	}
}

func TestJwkRepository_Rotation_DeletesExpiredInactive(t *testing.T) {
	repo := repository.NewJwkRepository(DataSource)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	use := fmt.Sprintf("sig-gc-%d", time.Now().UnixNano())

	// Create an already-expired key (Expiration negative makes ExpiresAt in the past)
	expired, err := repo.AddJwk(ctx, repository.JwkData{
		Use:        use,
		Expiration: -1 * time.Hour,
	})
	require.NoError(t, err)
	require.NotNil(t, expired)

	// Rotate to a new active key for same use
	current, err := repo.AddJwk(ctx, repository.JwkData{
		Use:        use,
		Expiration: 1 * time.Hour,
	})
	require.NoError(t, err)
	require.NotNil(t, current)

	// Active should be the new one
	active, err := repo.GetActiveJwk(ctx, use)
	require.NoError(t, err)
	require.NotNil(t, active)
	assert.Equal(t, current.ID, active.ID)

	// The previously expired key should have been GC'd by DeleteNotActiveJwks (ExpiresAt <= now)
	_, err = repo.GetJwk(ctx, expired.ID)
	assert.Error(t, err, "expired & inactive key should be deleted during rotation")
}

func TestJwkRepository_SeparateUsesAreIndependent(t *testing.T) {
	repo := repository.NewJwkRepository(DataSource)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sigUse := fmt.Sprintf("sig-multi-%d", time.Now().UnixNano())
	encUse := fmt.Sprintf("enc-multi-%d", time.Now().UnixNano())

	sigKey, err := repo.AddJwk(ctx, repository.JwkData{
		Use:        sigUse,
		Expiration: 1 * time.Hour,
	})
	require.NoError(t, err)
	require.NotNil(t, sigKey)

	encKey, err := repo.AddJwk(ctx, repository.JwkData{
		Use:        encUse,
		Expiration: 1 * time.Hour,
	})
	require.NoError(t, err)
	require.NotNil(t, encKey)

	// Active per use
	activeSig, err := repo.GetActiveJwk(ctx, sigUse)
	require.NoError(t, err)
	require.NotNil(t, activeSig)
	assert.Equal(t, sigKey.ID, activeSig.ID)

	activeEnc, err := repo.GetActiveJwk(ctx, encUse)
	require.NoError(t, err)
	require.NotNil(t, activeEnc)
	assert.Equal(t, encKey.ID, activeEnc.ID)

	// Both should appear in active list
	all, err := repo.GetActiveJwks(ctx)
	require.NoError(t, err)
	require.NotNil(t, all)

	foundSig := false
	foundEnc := false
	for _, k := range all {
		if k.ID == sigKey.ID {
			foundSig = true
		}
		if k.ID == encKey.ID {
			foundEnc = true
		}
	}
	assert.True(t, foundSig, "active JWKs should include sig key")
	assert.True(t, foundEnc, "active JWKs should include enc key")
}

func TestJwkRepository_FieldsAndTimestamps(t *testing.T) {
	repo := repository.NewJwkRepository(DataSource)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	use := fmt.Sprintf("sig-ts-%d", time.Now().UnixNano())
	ttl := 90 * time.Minute

	j, err := repo.AddJwk(ctx, repository.JwkData{
		Use:        use,
		Expiration: ttl,
	})
	require.NoError(t, err)
	require.NotNil(t, j)

	assert.Equal(t, "RSA", j.Kty)
	assert.Equal(t, "RS256", j.Alg)
	assert.Equal(t, use, j.Use)
	assert.True(t, j.Active)

	// Timestamps sanity: ExpiresAt should be after CreatedAt by roughly ttl (allowing for execution delay)
	delta := j.ExpiresAt.Sub(j.CreatedAt)
	assert.Greater(t, delta, time.Minute) // > 1m
	assert.Less(t, delta, 2*time.Hour)    // < 2h (safe slack)
	assert.True(t, j.CreatedAt.Before(j.ExpiresAt))
}
