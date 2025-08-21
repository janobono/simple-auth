package service_test

import (
	"testing"
	"time"

	db2 "github.com/janobono/go-util/db"
	"github.com/janobono/simple-auth/simple-auth-service/internal/config"
	"github.com/janobono/simple-auth/simple-auth-service/internal/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeJwtService(cfg *config.SecurityConfig) *service.JwtService {
	return service.NewJwtService(cfg, JwkRepository)
}

func defaultJwtCfg() *config.SecurityConfig {
	// Short JWK lifetimes so rotation can be tested quickly.
	return &config.SecurityConfig{
		TokenIssuer:              "simple-auth-tests",
		AccessTokenExpiresIn:     1 * time.Minute,
		AccessTokenJwkExpiresIn:  2 * time.Second,
		RefreshTokenExpiresIn:    1 * time.Minute,
		RefreshTokenJwkExpiresIn: 2 * time.Second,
		ContentTokenExpiresIn:    1 * time.Minute,
		ContentTokenJwkExpiresIn: 2 * time.Second,
	}
}

func TestJwtService_IssueAndParseAccessToken(t *testing.T) {
	ResetDB(t)

	cfg := defaultJwtCfg()
	js := makeJwtService(cfg)
	ctx, cancel := ctxSvc(t, 15*time.Second)
	defer cancel()

	// Get an access signing token (this will also seed a JWK row).
	accessTok, err := js.GetAccessJwtToken(ctx)
	require.NoError(t, err)
	require.NotNil(t, accessTok)
	require.NotEmpty(t, accessTok.KeyID())

	// Generate a user token with authorities.
	uid := db2.NewUUID()
	jws, err := js.GenerateAuthToken(accessTok, uid, []string{"ROLE_USER", "ROLE_ADMIN"})
	require.NoError(t, err)
	require.NotEmpty(t, jws)

	// Parse & validate via the service (which will go back to DB to resolve public key).
	gotID, gotAuths, err := js.ParseAuthToken(ctx, accessTok, jws)
	require.NoError(t, err)
	assert.Equal(t, uid, gotID)
	assert.ElementsMatch(t, []string{"ROLE_USER", "ROLE_ADMIN"}, gotAuths)

	// Also exercise GetPublicKey directly using the token's kid.
	pub, err := js.GetPublicKey(ctx, accessTok.KeyID())
	require.NoError(t, err)
	assert.NotNil(t, pub)
}

func TestJwtService_CacheAndRotateKeys(t *testing.T) {
	ResetDB(t)

	cfg := defaultJwtCfg()
	js := makeJwtService(cfg)
	ctx, cancel := ctxSvc(t, 20*time.Second)
	defer cancel()

	// First fetch — creates & caches an "access" key.
	tok1, err := js.GetAccessJwtToken(ctx)
	require.NoError(t, err)
	kid1 := tok1.KeyID()
	require.NotEmpty(t, kid1)

	// Immediately fetch again — should reuse same cached key (no rotation yet).
	tok2, err := js.GetAccessJwtToken(ctx)
	require.NoError(t, err)
	kid2 := tok2.KeyID()
	assert.Equal(t, kid1, kid2, "key should be cached before JWK expiration")

	// Wait past JWK expiration to force rotation.
	time.Sleep(cfg.AccessTokenJwkExpiresIn + 1*time.Second)

	tok3, err := js.GetAccessJwtToken(ctx)
	require.NoError(t, err)
	kid3 := tok3.KeyID()
	assert.NotEqual(t, kid1, kid3, "key should rotate after JWK expiration")
}

func TestJwtService_IndependentCachesPerUse(t *testing.T) {
	ResetDB(t)

	cfg := defaultJwtCfg()
	js := makeJwtService(cfg)
	ctx, cancel := ctxSvc(t, 15*time.Second)
	defer cancel()

	// Get tokens for each "use": access, refresh, confirm.
	access, err := js.GetAccessJwtToken(ctx)
	require.NoError(t, err)
	refresh, err := js.GetRefreshJwtToken(ctx)
	require.NoError(t, err)
	confirm, err := js.GetConfirmJwtToken(ctx)
	require.NoError(t, err)

	// They should have different kids because each use is backed by its own JWK row.
	assert.NotEmpty(t, access.KeyID())
	assert.NotEmpty(t, refresh.KeyID())
	assert.NotEmpty(t, confirm.KeyID())

	assert.NotEqual(t, access.KeyID(), refresh.KeyID())
	assert.NotEqual(t, access.KeyID(), confirm.KeyID())
	assert.NotEqual(t, refresh.KeyID(), confirm.KeyID())
}

func TestJwtService_ParseRejectsMalformedToken(t *testing.T) {
	ResetDB(t)

	cfg := defaultJwtCfg()
	js := makeJwtService(cfg)
	ctx, cancel := ctxSvc(t, 10*time.Second)
	defer cancel()

	accessTok, err := js.GetAccessJwtToken(ctx)
	require.NoError(t, err)

	// Malformed/bogus token should fail parsing.
	_, _, err = js.ParseAuthToken(ctx, accessTok, "this.is.not.a.jwt")
	require.Error(t, err)
}

func TestJwtService_OldTokenStillValidAfterRotation(t *testing.T) {
	ResetDB(t)

	cfg := defaultJwtCfg()
	js := makeJwtService(cfg)
	ctx, cancel := ctxSvc(t, 20*time.Second)
	defer cancel()

	accessTok, err := js.GetAccessJwtToken(ctx)
	require.NoError(t, err)

	uid := db2.NewUUID()
	oldJWT, err := js.GenerateAuthToken(accessTok, uid, []string{"ROLE_USER"})
	require.NoError(t, err)

	// Force rotation
	time.Sleep(cfg.AccessTokenJwkExpiresIn + 1*time.Second)
	_, err = js.GetAccessJwtToken(ctx)
	require.NoError(t, err)

	// Old token should still verify via DB key lookup by kid
	gotID, gotAuths, err := js.ParseAuthToken(ctx, accessTok, oldJWT)
	require.NoError(t, err)
	assert.Equal(t, uid, gotID)
	assert.ElementsMatch(t, []string{"ROLE_USER"}, gotAuths)
}

func TestJwtService_IssuerClaim(t *testing.T) {
	ResetDB(t)

	cfg := defaultJwtCfg()
	js := makeJwtService(cfg)
	ctx, cancel := ctxSvc(t, 10*time.Second)
	defer cancel()

	accessTok, err := js.GetAccessJwtToken(ctx)
	require.NoError(t, err)

	uid := db2.NewUUID()
	jws, err := js.GenerateAuthToken(accessTok, uid, nil)
	require.NoError(t, err)

	claims, err := accessTok.ParseToken(ctx, jws)
	require.NoError(t, err)
	assert.Equal(t, "simple-auth-tests", claims["iss"])
}

func TestJwtService_ExpiredTokenIsRejected(t *testing.T) {
	ResetDB(t)

	cfg := &config.SecurityConfig{
		TokenIssuer:              "simple-auth-tests",
		AccessTokenExpiresIn:     2 * time.Second, // >= 2s so second-precision exp is safe
		AccessTokenJwkExpiresIn:  5 * time.Second,
		RefreshTokenExpiresIn:    time.Minute,
		RefreshTokenJwkExpiresIn: 5 * time.Second,
		ContentTokenExpiresIn:    time.Minute,
		ContentTokenJwkExpiresIn: 5 * time.Second,
	}

	js := makeJwtService(cfg)
	ctx, cancel := ctxSvc(t, 10*time.Second)
	defer cancel()

	accessTok, err := js.GetAccessJwtToken(ctx)
	require.NoError(t, err)

	uid := db2.NewUUID()
	jws, err := js.GenerateAuthToken(accessTok, uid, nil)
	require.NoError(t, err)

	// Still valid comfortably before expiry (sleep < exp)
	time.Sleep(1 * time.Second)
	_, _, err = js.ParseAuthToken(ctx, accessTok, jws)
	require.NoError(t, err, "token should still be valid before expiry")

	// Now let it clearly expire (sleep > remaining time plus a small buffer)
	time.Sleep(1*time.Second + 300*time.Millisecond)
	_, _, err = js.ParseAuthToken(ctx, accessTok, jws)
	require.Error(t, err, "expired token should be rejected")
}

func TestJwtService_IssueAndParse_Refresh_And_Confirm(t *testing.T) {
	ResetDB(t)

	cfg := defaultJwtCfg()
	js := makeJwtService(cfg)
	ctx, cancel := ctxSvc(t, 10*time.Second)
	defer cancel()

	uid := db2.NewUUID()

	refreshTok, err := js.GetRefreshJwtToken(ctx)
	require.NoError(t, err)
	rjwt, err := js.GenerateAuthToken(refreshTok, uid, []string{"ROLE_REFRESH"})
	require.NoError(t, err)
	rid, rauth, err := js.ParseAuthToken(ctx, refreshTok, rjwt)
	require.NoError(t, err)
	assert.Equal(t, uid, rid)
	assert.ElementsMatch(t, []string{"ROLE_REFRESH"}, rauth)

	confirmTok, err := js.GetConfirmJwtToken(ctx)
	require.NoError(t, err)
	cjwt, err := js.GenerateAuthToken(confirmTok, uid, nil)
	require.NoError(t, err)
	cid, cauth, err := js.ParseAuthToken(ctx, confirmTok, cjwt)
	require.NoError(t, err)
	assert.Equal(t, uid, cid)
	assert.Empty(t, cauth)
}
