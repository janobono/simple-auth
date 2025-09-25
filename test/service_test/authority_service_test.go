package service_test

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/janobono/go-util/common"
	"github.com/janobono/simple-auth/simple-auth-service/generated/openapi"
	"github.com/janobono/simple-auth/simple-auth-service/internal/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorityService_Add_Get_Set_Delete_Integration(t *testing.T) {
	ResetDB(t)

	svc := service.NewAuthorityService(AuthorityRepository)

	ctx, cancel := ctxSvc(t, 15*time.Second)
	defer cancel()

	// Add
	in := &openapi.AuthorityData{Authority: "ROLE_ALPHA"}
	added, err := svc.AddAuthority(ctx, in)
	require.NoError(t, err)
	require.NotNil(t, added)
	assert.Equal(t, "ROLE_ALPHA", added.Authority)
	assert.NotEmpty(t, added.Id)

	// Get
	got, err := svc.GetAuthority(ctx, toUUID(t, added.Id))
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, added.Id, got.Id)
	assert.Equal(t, "ROLE_ALPHA", got.Authority)

	// Set (update)
	upd, err := svc.SetAuthority(ctx, toUUID(t, added.Id), &openapi.AuthorityData{
		Authority: "ROLE_ALPHA_CHANGED",
	})
	require.NoError(t, err)
	require.NotNil(t, upd)
	assert.Equal(t, "ROLE_ALPHA_CHANGED", upd.Authority)

	// Delete via repository (service DeleteAuthority also OK; using repo mirrors your attr test)
	err = AuthorityRepository.DeleteAuthorityById(ctx, toUUID(t, added.Id))
	require.NoError(t, err)

	// Get after delete -> expect error propagated (service maps pgx.ErrNoRows to 404 only inside GetAuthority)
	_, err = svc.GetAuthority(ctx, toUUID(t, added.Id))
	require.Error(t, err)
}

func TestAuthorityService_Add_Conflict_Integration(t *testing.T) {
	ResetDB(t)

	svc := service.NewAuthorityService(AuthorityRepository)

	ctx, cancel := ctxSvc(t, 10*time.Second)
	defer cancel()

	// Seed one
	first, err := svc.AddAuthority(ctx, &openapi.AuthorityData{Authority: "ROLE_DUP"})
	require.NoError(t, err)
	require.NotNil(t, first)

	// Try duplicate
	_, err = svc.AddAuthority(ctx, &openapi.AuthorityData{Authority: "ROLE_DUP"})
	require.Error(t, err)

	var se *common.ServiceError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusConflict, se.Status)
}

func TestAuthorityService_GetAuthority_NotFound_Integration(t *testing.T) {
	ResetDB(t)

	svc := service.NewAuthorityService(AuthorityRepository)

	ctx, cancel := ctxSvc(t, 10*time.Second)
	defer cancel()

	// all-zero UUID is valid format but won't exist
	unknown := toUUID(t, "00000000-0000-0000-0000-000000000000")

	out, err := svc.GetAuthority(ctx, unknown)
	require.Error(t, err)
	assert.Nil(t, out)

	var se *common.ServiceError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusNotFound, se.Status)
}

func TestAuthorityService_GetAuthorities_Integration(t *testing.T) {
	ResetDB(t)

	svc := service.NewAuthorityService(AuthorityRepository)

	ctx, cancel := ctxSvc(t, 15*time.Second)
	defer cancel()

	// Seed two authorities
	_, err := svc.AddAuthority(ctx, &openapi.AuthorityData{Authority: "ROLE_A1"})
	require.NoError(t, err)
	_, err = svc.AddAuthority(ctx, &openapi.AuthorityData{Authority: "ROLE_A2"})
	require.NoError(t, err)

	// Happy path search
	page, err := svc.GetAuthorities(ctx,
		&service.SearchAuthorityCriteria{SearchField: "ROLE_A"},
		&common.Pageable{Page: 0, Size: 10, Sort: "authority asc"},
	)
	require.NoError(t, err)
	require.NotNil(t, page)
	assert.GreaterOrEqual(t, page.TotalElements, int64(2))
	assert.True(t, len(page.Content) >= 2)

	// Nil args (programmer fault) → repository now errors on nil; service just propagates the raw error
	_, err = svc.GetAuthorities(ctx, nil, &common.Pageable{Page: 0, Size: 10, Sort: "authority asc"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, err)) // non-nil plain error

	_, err = svc.GetAuthorities(ctx, &service.SearchAuthorityCriteria{SearchField: ""}, nil)
	require.Error(t, err)
}

func TestAuthorityService_SetAuthority_KeyConflict_Integration(t *testing.T) {
	ResetDB(t)

	svc := service.NewAuthorityService(AuthorityRepository)

	ctx, cancel := ctxSvc(t, 15*time.Second)
	defer cancel()

	// Seed A and B
	a, err := svc.AddAuthority(ctx, &openapi.AuthorityData{Authority: "ROLE_A"})
	require.NoError(t, err)
	_, err = svc.AddAuthority(ctx, &openapi.AuthorityData{Authority: "ROLE_B"})
	require.NoError(t, err)

	// Attempt to update A with B's authority → conflict
	_, err = svc.SetAuthority(ctx, toUUID(t, a.Id), &openapi.AuthorityData{Authority: "ROLE_B"})
	require.Error(t, err)

	var se *common.ServiceError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusConflict, se.Status)
}
