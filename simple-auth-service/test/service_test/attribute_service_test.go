package service_test

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/janobono/go-util/common"
	"github.com/janobono/simple-auth/simple-auth-service/generated/openapi"
	"github.com/janobono/simple-auth/simple-auth-service/internal/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttributeService_Add_Get_Set_Delete_Integration(t *testing.T) {
	ResetDB(t)

	svc := service.NewAttributeService(AttributeRepository)
	ctx, cancel := ctxSvc(t, 15*time.Second)
	defer cancel()

	// Add
	in := &openapi.AttributeData{
		Key:      "svc-alpha",
		Required: true,
		Hidden:   false,
	}
	added, err := svc.AddAttribute(ctx, in)
	require.NoError(t, err)
	require.NotNil(t, added)
	assert.Equal(t, in.Key, added.Key)
	assert.True(t, added.Required)
	assert.False(t, added.Hidden)

	// Get
	got, err := svc.GetAttribute(ctx, toUUID(t, added.Id))
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, added.Id, got.Id)
	assert.Equal(t, "svc-alpha", got.Key)

	// Set (update)
	upd, err := svc.SetAttribute(ctx, toUUID(t, added.Id), &openapi.AttributeData{
		Key:      "svc-alpha", // unchanged key
		Required: false,
		Hidden:   true,
	})
	require.NoError(t, err)
	require.NotNil(t, upd)
	assert.False(t, upd.Required)
	assert.True(t, upd.Hidden)

	// Delete via repo (we’re intentionally mixing layers)
	err = AttributeRepository.DeleteAttributeById(ctx, toUUID(t, added.Id))
	require.NoError(t, err)

	// Get after delete -> expect ServiceError 404 from service
	_, err = svc.GetAttribute(ctx, toUUID(t, added.Id))
	require.Error(t, err)
	var se *common.ServiceError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusNotFound, se.Status)
}

func TestAttributeService_Add_Conflict_Integration(t *testing.T) {
	ResetDB(t)

	svc := service.NewAttributeService(AttributeRepository)
	ctx, cancel := ctxSvc(t, 10*time.Second)
	defer cancel()

	// Seed one
	first, err := svc.AddAttribute(ctx, &openapi.AttributeData{
		Key: "svc-dup", Required: false, Hidden: false,
	})
	require.NoError(t, err)
	require.NotNil(t, first)

	// Try duplicate
	_, err = svc.AddAttribute(ctx, &openapi.AttributeData{
		Key: "svc-dup", Required: true, Hidden: true,
	})
	require.Error(t, err)

	var se *common.ServiceError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusConflict, se.Status)
}

func TestAttributeService_GetAttribute_NotFound_Integration(t *testing.T) {
	ResetDB(t)

	svc := service.NewAttributeService(AttributeRepository)
	ctx, cancel := ctxSvc(t, 10*time.Second)
	defer cancel()

	// Query an ID that doesn't exist (all-zero UUID)
	unknown := pgtype.UUID{Bytes: [16]byte{}, Valid: true}

	out, err := svc.GetAttribute(ctx, unknown)
	require.Error(t, err)
	assert.Nil(t, out)

	// Service should map pgx.ErrNoRows → 404 via ServiceError
	var se *common.ServiceError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusNotFound, se.Status)
}

func TestAttributeService_GetAttributes_Integration(t *testing.T) {
	ResetDB(t)

	svc := service.NewAttributeService(AttributeRepository)
	ctx, cancel := ctxSvc(t, 15*time.Second)
	defer cancel()

	// Seed two attributes
	_, err := svc.AddAttribute(ctx, &openapi.AttributeData{Key: "svc-a1", Required: true})
	require.NoError(t, err)
	_, err = svc.AddAttribute(ctx, &openapi.AttributeData{Key: "svc-a2", Hidden: true})
	require.NoError(t, err)

	// Happy path search
	page, err := svc.GetAttributes(ctx,
		&service.SearchAttributeCriteria{SearchField: "svc-"},
		&common.Pageable{Page: 0, Size: 10, Sort: "key asc"},
	)
	require.NoError(t, err)
	require.NotNil(t, page)
	assert.GreaterOrEqual(t, page.TotalElements, int64(2))
	assert.True(t, len(page.Content) >= 2)

	// Nil args (programmer fault in your design) -> raw error (NOT ServiceError)
	_, err = svc.GetAttributes(ctx, nil, &common.Pageable{Page: 0, Size: 10, Sort: "key asc"})
	require.Error(t, err)
	var se *common.ServiceError
	assert.False(t, errors.As(err, &se), "nil criteria should not map to ServiceError")

	_, err = svc.GetAttributes(ctx, &service.SearchAttributeCriteria{SearchField: ""}, nil)
	require.Error(t, err)
	assert.False(t, errors.As(err, &se), "nil pageable should not map to ServiceError")
}

func TestAttributeService_SetAttribute_KeyConflict_Integration(t *testing.T) {
	ResetDB(t)

	svc := service.NewAttributeService(AttributeRepository)
	ctx, cancel := ctxSvc(t, 15*time.Second)
	defer cancel()

	// Seed A and B
	a, err := svc.AddAttribute(ctx, &openapi.AttributeData{Key: "svc-A"})
	require.NoError(t, err)
	_, err = svc.AddAttribute(ctx, &openapi.AttributeData{Key: "svc-B"})
	require.NoError(t, err)

	// Attempt to update A with key of B → conflict
	_, err = svc.SetAttribute(ctx, toUUID(t, a.Id), &openapi.AttributeData{
		Key: "svc-B",
	})
	require.Error(t, err)

	var se *common.ServiceError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusConflict, se.Status)
}
