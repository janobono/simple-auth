package repository_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/janobono/go-util/common"
	"github.com/janobono/simple-auth/simple-auth-service/internal/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorityRepository_CRUD(t *testing.T) {
	repo := repository.NewAuthorityRepository(DataSource)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Add A1
	base := time.Now().UnixNano()
	a1Key := fmt.Sprintf("ROLE_TEST_%d", base)
	a1, err := repo.AddAuthority(ctx, &repository.AuthorityData{
		Authority: a1Key,
	})
	require.NoError(t, err)
	require.NotNil(t, a1)
	t.Cleanup(func() { _ = repo.DeleteAuthorityById(ctx, a1.ID) })

	// Count by id
	count, err := repo.CountById(ctx, a1.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// Count by authority
	count, err = repo.CountByAuthority(ctx, a1.Authority)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// Add A2 (different key) to exercise CountByAuthorityAndNotId semantics
	a2Key := fmt.Sprintf("ROLE_TEST_OTHER_%d", base)
	a2, err := repo.AddAuthority(ctx, &repository.AuthorityData{
		Authority: a2Key,
	})
	require.NoError(t, err)
	require.NotNil(t, a2)
	t.Cleanup(func() { _ = repo.DeleteAuthorityById(ctx, a2.ID) })

	// Using A1’s authority and A2’s id should be 1 (A1 exists, A2 excluded)
	count, err = repo.CountByAuthorityAndNotId(ctx, a1.Authority, a2.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// Using A1’s authority and A1’s id should be 0 (exclude itself)
	count, err = repo.CountByAuthorityAndNotId(ctx, a1.Authority, a1.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)

	// Get by authority
	fetched, err := repo.GetAuthorityByAuthority(ctx, a1.Authority)
	require.NoError(t, err)
	require.NotNil(t, fetched)
	assert.Equal(t, a1.ID, fetched.ID)

	// Update A1
	newKey := a1Key + "_CHANGED"
	changed, err := repo.SetAuthority(ctx, a1.ID, &repository.AuthorityData{
		Authority: newKey,
	})
	require.NoError(t, err)
	require.NotNil(t, changed)
	assert.Equal(t, newKey, changed.Authority)

	// Get by id
	fetched, err = repo.GetAuthorityById(ctx, a1.ID)
	require.NoError(t, err)
	require.NotNil(t, fetched)
	assert.Equal(t, newKey, fetched.Authority)
}

func TestAuthorityRepository_Search_NilArgs_ReturnsError(t *testing.T) {
	repo := repository.NewAuthorityRepository(DataSource)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// criteria=nil -> ErrNilCriteria
	page, err := repo.SearchAuthorities(ctx, nil, &common.Pageable{Page: 0, Size: 1, Sort: "authority asc"})
	require.Error(t, err)
	assert.Nil(t, page)
	assert.ErrorIs(t, err, repository.ErrNilCriteria)

	// pageable=nil -> ErrNilPageable
	page, err = repo.SearchAuthorities(ctx, &repository.SearchAuthoritiesCriteria{}, nil)
	require.Error(t, err)
	assert.Nil(t, page)
	assert.ErrorIs(t, err, repository.ErrNilPageable)
}

func TestAuthorityRepository_Search_EmptySearchField_ReturnsAll_WithPaging(t *testing.T) {
	repo := repository.NewAuthorityRepository(DataSource)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Ensure at least two rows exist to make the assertions meaningful
	base := time.Now().UnixNano()
	a1, err := repo.AddAuthority(ctx, &repository.AuthorityData{Authority: fmt.Sprintf("ROLE_EMPTY_A_%d", base)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = repo.DeleteAuthorityById(ctx, a1.ID) })

	a2, err := repo.AddAuthority(ctx, &repository.AuthorityData{Authority: fmt.Sprintf("ROLE_EMPTY_B_%d", base)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = repo.DeleteAuthorityById(ctx, a2.ID) })

	page, err := repo.SearchAuthorities(ctx,
		&repository.SearchAuthoritiesCriteria{SearchField: ""},
		&common.Pageable{Page: 0, Size: 2, Sort: "authority asc"},
	)
	require.NoError(t, err)
	require.NotNil(t, page)
	assert.True(t, len(page.Content) > 0)
	assert.GreaterOrEqual(t, page.TotalElements, int64(2))
}

func TestAuthorityRepository_Search_SortingAndPaging(t *testing.T) {
	repo := repository.NewAuthorityRepository(DataSource)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	base := time.Now().UnixNano()
	keys := []string{
		fmt.Sprintf("ROLE_A_%d", base),
		fmt.Sprintf("ROLE_B_%d", base),
		fmt.Sprintf("ROLE_C_%d", base),
	}
	for _, k := range keys {
		a, err := repo.AddAuthority(ctx, &repository.AuthorityData{Authority: k})
		require.NoError(t, err)
		t.Cleanup(func() { _ = repo.DeleteAuthorityById(ctx, a.ID) })
	}

	// Asc
	page, err := repo.SearchAuthorities(ctx,
		&repository.SearchAuthoritiesCriteria{SearchField: fmt.Sprintf("%d", base)},
		&common.Pageable{Page: 0, Size: 10, Sort: "authority asc"},
	)
	require.NoError(t, err)
	require.Len(t, page.Content, 3)
	assert.Equal(t, keys[0], page.Content[0].Authority)
	assert.Equal(t, keys[1], page.Content[1].Authority)
	assert.Equal(t, keys[2], page.Content[2].Authority)

	// Desc
	page, err = repo.SearchAuthorities(ctx,
		&repository.SearchAuthoritiesCriteria{SearchField: fmt.Sprintf("%d", base)},
		&common.Pageable{Page: 0, Size: 10, Sort: "authority desc"},
	)
	require.NoError(t, err)
	require.Len(t, page.Content, 3)
	assert.Equal(t, keys[2], page.Content[0].Authority)
	assert.Equal(t, keys[1], page.Content[1].Authority)
	assert.Equal(t, keys[0], page.Content[2].Authority)

	// Paging: page 1, size 2 -> last item
	page, err = repo.SearchAuthorities(ctx,
		&repository.SearchAuthoritiesCriteria{SearchField: fmt.Sprintf("%d", base)},
		&common.Pageable{Page: 1, Size: 2, Sort: "authority asc"},
	)
	require.NoError(t, err)
	assert.Equal(t, int32(2), page.TotalPages)
	assert.Equal(t, int64(3), page.TotalElements)
	require.Len(t, page.Content, 1)
	assert.Equal(t, keys[2], page.Content[0].Authority)
}

func TestAuthorityRepository_Search_UnaccentMatching(t *testing.T) {
	repo := repository.NewAuthorityRepository(DataSource)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Store with diacritics; search without — include unique nonce in the query to target this row
	base := time.Now().UnixNano()
	withAccents := fmt.Sprintf("RÔLE_ŽLÚŤ_%d", base)
	a, err := repo.AddAuthority(ctx, &repository.AuthorityData{Authority: withAccents})
	require.NoError(t, err)
	t.Cleanup(func() { _ = repo.DeleteAuthorityById(ctx, a.ID) })

	q := fmt.Sprintf("ROLE ZLUT %d", base)
	page, err := repo.SearchAuthorities(ctx,
		&repository.SearchAuthoritiesCriteria{SearchField: q},
		&common.Pageable{Page: 0, Size: 25, Sort: "id asc"},
	)
	require.NoError(t, err)
	require.NotNil(t, page)

	found := false
	for _, it := range page.Content {
		if it.ID == a.ID {
			found = true
			break
		}
	}
	assert.True(t, found, "unaccent search should match diacritics + unique suffix")
}
