package service_test

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/janobono/simple-auth/simple-auth-service/internal/service"
	"github.com/stretchr/testify/require"
)

func TestJwkService_GetJwks_Integration(t *testing.T) {
	ResetDB(t)

	svc := service.NewJwkService(JwkRepository)
	ctx, cancel := ctxSvc(t, 10*time.Second)
	defer cancel()

	out, err := svc.GetJwks(ctx)
	require.NoError(t, err)
	require.NotNil(t, out)

	if len(out.Keys) == 0 {
		t.Skip("no active JWKs in DB — seed a key to run this test")
	}

	j := out.Keys[0]

	// Basic shape checks
	require.Equal(t, "RSA", j.Kty)
	require.Equal(t, "RS256", j.Alg)
	require.NotEmpty(t, j.N)
	require.NotEmpty(t, j.E)

	// Valid base64url
	nb, err := base64.RawURLEncoding.DecodeString(j.N)
	require.NoError(t, err)
	eb, err := base64.RawURLEncoding.DecodeString(j.E)
	require.NoError(t, err)

	// Sanity: modulus length should be at least 2048 bits if you use 2048-bit keys
	require.GreaterOrEqual(t, len(nb)*8, 2048)

	// Common case: public exponent 65537 -> "AQAB"
	// (Don’t fail hard if you use a different exponent; just a helpful check.)
	if j.E != "AQAB" {
		t.Logf("note: JWK exponent is %q (not 65537/AQAB)", j.E)
	}

	_ = eb // eb validated above; kept to avoid “unused” in case you tweak assertions
}
