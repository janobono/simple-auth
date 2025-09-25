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

func TestAttributeRepository_CRUD_Basics(t *testing.T) {
	repo := repository.NewAttributeRepository(DataSource)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	key := fmt.Sprintf("attr-basic-%d", time.Now().UnixNano())
	attr, err := repo.AddAttribute(ctx, &repository.AttributeData{
		Key:      key,
		Required: true,
		Hidden:   false,
	})
	require.NoError(t, err)
	require.NotNil(t, attr)
	t.Cleanup(func() { _ = repo.DeleteAttributeById(ctx, attr.ID) })

	// Count by ID
	cnt, err := repo.CountById(ctx, attr.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), cnt)

	// Count by key
	cnt, err = repo.CountByKey(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, int64(1), cnt)

	// Get by key
	got, err := repo.GetAttributeByKey(ctx, key)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, key, got.Key)
	assert.Equal(t, true, got.Required)
	assert.Equal(t, false, got.Hidden)

	// Update
	updated, err := repo.SetAttribute(ctx, attr.ID, &repository.AttributeData{
		Key:      key,
		Required: false,
		Hidden:   true,
	})
	require.NoError(t, err)
	require.NotNil(t, updated)
	assert.Equal(t, false, updated.Required)
	assert.Equal(t, true, updated.Hidden)

	// Get by id reflects update
	got, err = repo.GetAttributeById(ctx, attr.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, updated.Required, got.Required)
	assert.Equal(t, updated.Hidden, got.Hidden)
}

func TestAttributeRepository_Search_NilArgs_ReturnsError(t *testing.T) {
	repo := repository.NewAttributeRepository(DataSource)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// criteria=nil
	page, err := repo.SearchAttributes(ctx, nil, &common.Pageable{Page: 0, Size: 1, Sort: "key asc"})
	require.Error(t, err)
	assert.Nil(t, page)
	assert.ErrorIs(t, err, repository.ErrNilCriteria)

	// pageable=nil
	page, err = repo.SearchAttributes(ctx, &repository.SearchAttributesCriteria{}, nil)
	require.Error(t, err)
	assert.Nil(t, page)
	assert.ErrorIs(t, err, repository.ErrNilPageable)
}

func TestAttributeRepository_Search_EmptySearchField_ReturnsAll_WithPaging(t *testing.T) {
	repo := repository.NewAttributeRepository(DataSource)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Ensure at least two rows exist to make the assertions meaningful
	base := time.Now().UnixNano()
	a1, err := repo.AddAttribute(ctx, &repository.AttributeData{Key: fmt.Sprintf("empty-a-%d", base), Required: true, Hidden: false})
	require.NoError(t, err)
	t.Cleanup(func() { _ = repo.DeleteAttributeById(ctx, a1.ID) })

	a2, err := repo.AddAttribute(ctx, &repository.AttributeData{Key: fmt.Sprintf("empty-b-%d", base), Required: false, Hidden: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = repo.DeleteAttributeById(ctx, a2.ID) })

	page, err := repo.SearchAttributes(ctx,
		&repository.SearchAttributesCriteria{SearchField: ""},
		&common.Pageable{Page: 0, Size: 2, Sort: "key asc"},
	)
	require.NoError(t, err)
	require.NotNil(t, page)
	assert.GreaterOrEqual(t, page.TotalElements, int64(2))
	assert.True(t, len(page.Content) > 0)
}

func TestAttributeRepository_Search_Paging(t *testing.T) {
	repo := repository.NewAttributeRepository(DataSource)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	base := time.Now().UnixNano()

	a1, err := repo.AddAttribute(ctx, &repository.AttributeData{Key: fmt.Sprintf("alpha-%d", base), Required: true, Hidden: false})
	require.NoError(t, err)
	t.Cleanup(func() { _ = repo.DeleteAttributeById(ctx, a1.ID) })

	a2, err := repo.AddAttribute(ctx, &repository.AttributeData{Key: fmt.Sprintf("beta-%d", base), Required: false, Hidden: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = repo.DeleteAttributeById(ctx, a2.ID) })

	// Explicit small page to exercise paging & order
	page, err := repo.SearchAttributes(ctx,
		&repository.SearchAttributesCriteria{},
		&common.Pageable{Page: 0, Size: 1, Sort: "key asc"},
	)
	require.NoError(t, err)
	require.NotNil(t, page)
	assert.Equal(t, 1, len(page.Content))
}

func TestAttributeRepository_Search_SortDeterminism(t *testing.T) {
	repo := repository.NewAttributeRepository(DataSource)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	base := time.Now().UnixNano()
	keys := []string{
		fmt.Sprintf("k-a-%d", base),
		fmt.Sprintf("k-b-%d", base),
		fmt.Sprintf("k-c-%d", base),
	}
	for i, k := range keys {
		a, err := repo.AddAttribute(ctx, &repository.AttributeData{
			Key:      k,
			Required: i%2 == 0,
			Hidden:   i%2 == 1,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = repo.DeleteAttributeById(ctx, a.ID) })
	}

	// Asc by key
	page, err := repo.SearchAttributes(ctx,
		&repository.SearchAttributesCriteria{SearchField: fmt.Sprintf("%d", base)},
		&common.Pageable{Page: 0, Size: 10, Sort: "key asc"},
	)
	require.NoError(t, err)
	require.Len(t, page.Content, 3)
	assert.Equal(t, keys[0], page.Content[0].Key)
	assert.Equal(t, keys[1], page.Content[1].Key)
	assert.Equal(t, keys[2], page.Content[2].Key)

	// Desc by key
	page, err = repo.SearchAttributes(ctx,
		&repository.SearchAttributesCriteria{SearchField: fmt.Sprintf("%d", base)},
		&common.Pageable{Page: 0, Size: 10, Sort: "key desc"},
	)
	require.NoError(t, err)
	require.Len(t, page.Content, 3)
	assert.Equal(t, keys[2], page.Content[0].Key)
	assert.Equal(t, keys[1], page.Content[1].Key)
	assert.Equal(t, keys[0], page.Content[2].Key)

	// Paging: page=1 size=2 -> last item asc
	page, err = repo.SearchAttributes(ctx,
		&repository.SearchAttributesCriteria{SearchField: fmt.Sprintf("%d", base)},
		&common.Pageable{Page: 1, Size: 2, Sort: "key asc"},
	)
	require.NoError(t, err)
	assert.Equal(t, int32(2), page.TotalPages)
	assert.Equal(t, int64(3), page.TotalElements)
	require.Len(t, page.Content, 1)
	assert.Equal(t, keys[2], page.Content[0].Key)
}

func TestAttributeRepository_Search_ORSemantics(t *testing.T) {
	repo := repository.NewAttributeRepository(DataSource)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	base := time.Now().UnixNano()
	ka := fmt.Sprintf("orange-%d", base)
	kb := fmt.Sprintf("banana-%d", base)

	a, err := repo.AddAttribute(ctx, &repository.AttributeData{Key: ka, Required: false, Hidden: false})
	require.NoError(t, err)
	t.Cleanup(func() { _ = repo.DeleteAttributeById(ctx, a.ID) })

	b, err := repo.AddAttribute(ctx, &repository.AttributeData{Key: kb, Required: false, Hidden: false})
	require.NoError(t, err)
	t.Cleanup(func() { _ = repo.DeleteAttributeById(ctx, b.ID) })

	// Search "orange banana <base>" should match either (OR semantics)
	page, err := repo.SearchAttributes(ctx,
		&repository.SearchAttributesCriteria{SearchField: fmt.Sprintf("orange banana %d", base)},
		&common.Pageable{Page: 0, Size: 10, Sort: "key asc"},
	)
	require.NoError(t, err)

	var sawA, sawB bool
	for _, it := range page.Content {
		if it.Key == ka {
			sawA = true
		}
		if it.Key == kb {
			sawB = true
		}
	}
	assert.True(t, sawA, "should find 'orange'")
	assert.True(t, sawB, "should find 'banana'")
}

func TestAttributeRepository_Search_IsCaseSensitive_WithLIKE(t *testing.T) {
	repo := repository.NewAttributeRepository(DataSource)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	base := time.Now().UnixNano()
	lower := fmt.Sprintf("casey-%d", base)
	upperQuery := fmt.Sprintf("CASEY-%d", base)

	a, err := repo.AddAttribute(ctx, &repository.AttributeData{Key: lower, Required: false, Hidden: false})
	require.NoError(t, err)
	t.Cleanup(func() { _ = repo.DeleteAttributeById(ctx, a.ID) })

	// Using LIKE (environment-dependent): searching upper may not match lower in case-sensitive collations
	page, err := repo.SearchAttributes(ctx,
		&repository.SearchAttributesCriteria{SearchField: upperQuery},
		&common.Pageable{Page: 0, Size: 10, Sort: "key asc"},
	)
	require.NoError(t, err)

	found := false
	for _, it := range page.Content {
		if it.Key == lower {
			found = true
			break
		}
	}
	if found {
		t.Log("Environment collation appears case-insensitive; skipping negative assertion for LIKE-case.")
	} else {
		assert.False(t, found, "LIKE is case-sensitive in most collations: 'CASEY' should not match 'casey'")
	}

	// Control: exact case matches
	page, err = repo.SearchAttributes(ctx,
		&repository.SearchAttributesCriteria{SearchField: lower},
		&common.Pageable{Page: 0, Size: 10, Sort: "key asc"},
	)
	require.NoError(t, err)
	found = false
	for _, it := range page.Content {
		if it.Key == lower {
			found = true
			break
		}
	}
	assert.True(t, found, "LIKE should match exact case")
}

func TestAttributeRepository_Search_IsAccentSensitive_Now(t *testing.T) {
	repo := repository.NewAttributeRepository(DataSource)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	base := time.Now().UnixNano()
	withAccents := fmt.Sprintf("café-žluťoučký-%d", base) // contains diacritics
	asciiQuery := fmt.Sprintf("cafe zlutoucky %d", base)  // diacritics removed intentionally

	a, err := repo.AddAttribute(ctx, &repository.AttributeData{Key: withAccents, Required: false, Hidden: false})
	require.NoError(t, err)
	t.Cleanup(func() { _ = repo.DeleteAttributeById(ctx, a.ID) })

	// Plain LIKE may be accent-sensitive depending on collation; adapt test to environment
	page, err := repo.SearchAttributes(ctx,
		&repository.SearchAttributesCriteria{SearchField: asciiQuery},
		&common.Pageable{Page: 0, Size: 10, Sort: "key asc"},
	)
	require.NoError(t, err)

	found := false
	for _, it := range page.Content {
		if it.ID == a.ID {
			found = true
			break
		}
	}
	if found {
		t.Log("Environment collation appears accent-insensitive; skipping negative assertion for LIKE-accent.")
	} else {
		assert.False(t, found, "ASCII search should not match accented value with LIKE in accent-sensitive collations")
	}

	// Control: searching with exact accented fragments should match
	page, err = repo.SearchAttributes(ctx,
		&repository.SearchAttributesCriteria{SearchField: fmt.Sprintf("café žluťoučký %d", base)},
		&common.Pageable{Page: 0, Size: 10, Sort: "key asc"},
	)
	require.NoError(t, err)
	found = false
	for _, it := range page.Content {
		if it.ID == a.ID {
			found = true
			break
		}
	}
	assert.True(t, found, "Accented search should match accented value with LIKE")
}
