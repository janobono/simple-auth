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

func TestUserRepository_CRUD_AndCounts(t *testing.T) {
	repo := repository.NewUserRepository(DataSource)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	email := fmt.Sprintf("user.crud.%d@example.com", time.Now().UnixNano())
	u, err := repo.AddUser(ctx, &repository.UserData{
		Email:     email,
		Password:  "pw",
		Enabled:   true,
		Confirmed: false,
	})
	require.NoError(t, err)
	require.NotNil(t, u)
	defer func() { _ = repo.DeleteUserById(ctx, u.ID) }()

	// Count by id/email
	cnt, err := repo.CountById(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), cnt)

	cnt, err = repo.CountByEmail(ctx, email)
	require.NoError(t, err)
	assert.Equal(t, int64(1), cnt)

	// CountByEmailAndNotId should exclude the given id
	cnt, err = repo.CountByEmailAndNotId(ctx, email, u.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), cnt)

	// Getters
	got, err := repo.GetUserById(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, email, got.Email)

	got, err = repo.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.ID)

	// Mutations
	u, err = repo.SetUserConfirmed(ctx, u.ID, true)
	require.NoError(t, err)
	assert.True(t, u.Confirmed)

	u, err = repo.SetUserEnabled(ctx, u.ID, false)
	require.NoError(t, err)
	assert.False(t, u.Enabled)

	u, err = repo.SetUserPassword(ctx, u.ID, "pw2")
	require.NoError(t, err)
	assert.Equal(t, "pw2", u.Password)

	newEmail := fmt.Sprintf("user.crud.changed.%d@example.com", time.Now().UnixNano())
	u, err = repo.SetUserEmail(ctx, u.ID, newEmail)
	require.NoError(t, err)
	assert.Equal(t, newEmail, u.Email)

	// Delete
	err = repo.DeleteUserById(ctx, u.ID)
	require.NoError(t, err)

	_, err = repo.GetUserById(ctx, u.ID)
	assert.Error(t, err)
}

func TestUserRepository_AddWithAttributesAndAuthorities(t *testing.T) {
	users := repository.NewUserRepository(DataSource)
	attrs := repository.NewAttributeRepository(DataSource)
	auths := repository.NewAuthorityRepository(DataSource)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Prepare attributes/authorities
	a1, err := attrs.AddAttribute(ctx, &repository.AttributeData{Key: fmt.Sprintf("first_%d", time.Now().UnixNano()), Required: false, Hidden: false})
	require.NoError(t, err)
	a2, err := attrs.AddAttribute(ctx, &repository.AttributeData{Key: fmt.Sprintf("country_%d", time.Now().UnixNano()), Required: false, Hidden: false})
	require.NoError(t, err)

	r1, err := auths.AddAuthority(ctx, &repository.AuthorityData{Authority: fmt.Sprintf("ROLE_USER_%d", time.Now().UnixNano())})
	require.NoError(t, err)
	r2, err := auths.AddAuthority(ctx, &repository.AuthorityData{Authority: fmt.Sprintf("ROLE_ADMIN_%d", time.Now().UnixNano())})
	require.NoError(t, err)

	email := fmt.Sprintf("bundle.%d@example.com", time.Now().UnixNano())
	u, err := users.AddUserWithAttributesAndAuthorities(ctx,
		&repository.UserData{Email: email, Password: "pw", Enabled: true, Confirmed: true},
		[]*repository.UserAttribute{
			{Attribute: a1, Value: "Alice"},
			{Attribute: a2, Value: "Slovakia"},
		},
		[]*repository.Authority{r1, r2},
	)
	require.NoError(t, err)
	defer func() { _ = users.DeleteUserById(ctx, u.ID) }()

	// Verify backrefs
	gotAttrs, err := users.GetUserAttributes(ctx, u.ID)
	require.NoError(t, err)
	require.Len(t, gotAttrs, 2)
	m := map[string]string{}
	for _, ua := range gotAttrs {
		m[ua.Attribute.Key] = ua.Value
	}
	assert.Equal(t, "Alice", m[a1.Key])
	assert.Equal(t, "Slovakia", m[a2.Key])

	gotAuths, err := users.GetUserAuthorities(ctx, u.ID)
	require.NoError(t, err)
	require.Len(t, gotAuths, 2)
	hasR1, hasR2 := false, false
	for _, ga := range gotAuths {
		if ga.ID == r1.ID {
			hasR1 = true
		}
		if ga.ID == r2.ID {
			hasR2 = true
		}
	}
	assert.True(t, hasR1)
	assert.True(t, hasR2)
}

func TestUserRepository_SetUserAttributes_Replaces(t *testing.T) {
	users := repository.NewUserRepository(DataSource)
	attrs := repository.NewAttributeRepository(DataSource)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	u, err := users.AddUser(ctx, &repository.UserData{
		Email: fmt.Sprintf("attrs.%d@example.com", time.Now().UnixNano()), Password: "pw", Enabled: true,
	})
	require.NoError(t, err)
	defer func() { _ = users.DeleteUserById(ctx, u.ID) }()

	a1, _ := attrs.AddAttribute(ctx, &repository.AttributeData{Key: fmt.Sprintf("k1_%d", time.Now().UnixNano()), Required: false, Hidden: false})
	a2, _ := attrs.AddAttribute(ctx, &repository.AttributeData{Key: fmt.Sprintf("k2_%d", time.Now().UnixNano()), Required: false, Hidden: false})
	a3, _ := attrs.AddAttribute(ctx, &repository.AttributeData{Key: fmt.Sprintf("k3_%d", time.Now().UnixNano()), Required: false, Hidden: false})

	_, err = users.SetUserAttributes(ctx, &repository.UserAttributesData{
		UserID: u.ID,
		Attributes: []*repository.UserAttribute{
			{Attribute: a1, Value: "v1"},
			{Attribute: a2, Value: "v2"},
		},
	})
	require.NoError(t, err)

	_, err = users.SetUserAttributes(ctx, &repository.UserAttributesData{
		UserID: u.ID,
		Attributes: []*repository.UserAttribute{
			{Attribute: a3, Value: "v3"},
		},
	})
	require.NoError(t, err)

	final, err := users.GetUserAttributes(ctx, u.ID)
	require.NoError(t, err)
	require.Len(t, final, 1)
	assert.Equal(t, a3.ID, final[0].Attribute.ID)
	assert.Equal(t, "v3", final[0].Value)
}

func TestUserRepository_SetUserAuthorities_Replaces(t *testing.T) {
	users := repository.NewUserRepository(DataSource)
	auths := repository.NewAuthorityRepository(DataSource)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	u, err := users.AddUser(ctx, &repository.UserData{
		Email: fmt.Sprintf("auths.%d@example.com", time.Now().UnixNano()), Password: "pw", Enabled: true,
	})
	require.NoError(t, err)
	defer func() { _ = users.DeleteUserById(ctx, u.ID) }()

	r1, _ := auths.AddAuthority(ctx, &repository.AuthorityData{Authority: fmt.Sprintf("ROLE_R1_%d", time.Now().UnixNano())})
	r2, _ := auths.AddAuthority(ctx, &repository.AuthorityData{Authority: fmt.Sprintf("ROLE_R2_%d", time.Now().UnixNano())})
	r3, _ := auths.AddAuthority(ctx, &repository.AuthorityData{Authority: fmt.Sprintf("ROLE_R3_%d", time.Now().UnixNano())})

	_, err = users.SetUserAuthorities(ctx, &repository.UserAuthoritiesData{
		UserID: u.ID, Authorities: []*repository.Authority{r1, r2},
	})
	require.NoError(t, err)

	_, err = users.SetUserAuthorities(ctx, &repository.UserAuthoritiesData{
		UserID: u.ID, Authorities: []*repository.Authority{r3},
	})
	require.NoError(t, err)

	final, err := users.GetUserAuthorities(ctx, u.ID)
	require.NoError(t, err)
	require.Len(t, final, 1)
	assert.Equal(t, r3.ID, final[0].ID)
}

/*** Updated for new nil-arg behavior ***/
func TestUserRepository_Search_NilArgs_ReturnsError(t *testing.T) {
	users := repository.NewUserRepository(DataSource)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// criteria=nil -> ErrNilCriteria
	page, err := users.SearchUsers(ctx, nil, &common.Pageable{Page: 0, Size: 1, Sort: "email asc"})
	require.Error(t, err)
	assert.Nil(t, page)
	assert.ErrorIs(t, err, repository.ErrNilCriteria)

	// pageable=nil -> ErrNilPageable
	page, err = users.SearchUsers(ctx, &repository.SearchUsersCriteria{}, nil)
	require.Error(t, err)
	assert.Nil(t, page)
	assert.ErrorIs(t, err, repository.ErrNilPageable)
}

func TestUserRepository_Search_SortWhitelistAndInjection(t *testing.T) {
	users := repository.NewUserRepository(DataSource)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	base := time.Now().UnixNano()
	u, _ := users.AddUser(ctx, &repository.UserData{
		Email: fmt.Sprintf("sort.%d@example.com", base), Password: "pw", Enabled: true,
	})
	defer func() { _ = users.DeleteUserById(ctx, u.ID) }()

	// Whitelisted key
	page, err := users.SearchUsers(ctx,
		&repository.SearchUsersCriteria{SearchField: fmt.Sprintf("%d", base)},
		&common.Pageable{Page: 0, Size: 10, Sort: "email asc"},
	)
	require.NoError(t, err)
	require.NotNil(t, page)

	// Injection / unknown key should fall back to default ("email asc")
	page, err = users.SearchUsers(ctx,
		&repository.SearchUsersCriteria{SearchField: fmt.Sprintf("%d", base)},
		&common.Pageable{Page: 0, Size: 10, Sort: "junk; drop table users --"},
	)
	require.NoError(t, err)
	require.NotNil(t, page)
	require.GreaterOrEqual(t, len(page.Content), 1)
	// Not asserting order strictly; just verifying call succeeds with sanitized order
}

func TestUserRepository_Search_EmailOnly(t *testing.T) {
	users := repository.NewUserRepository(DataSource)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	base := time.Now().UnixNano()
	u1, _ := users.AddUser(ctx, &repository.UserData{
		Email: fmt.Sprintf("ada.%d@example.com", base), Password: "pw", Enabled: true,
	})
	u2, _ := users.AddUser(ctx, &repository.UserData{
		Email: fmt.Sprintf("alan.%d@example.com", base), Password: "pw", Enabled: true,
	})
	defer func() { _ = users.DeleteUserById(ctx, u1.ID) }()
	defer func() { _ = users.DeleteUserById(ctx, u2.ID) }()

	page, err := users.SearchUsers(ctx,
		&repository.SearchUsersCriteria{SearchField: fmt.Sprintf("ada %d", base)},
		&common.Pageable{Page: 0, Size: 10, Sort: "email asc"},
	)
	require.NoError(t, err)

	foundAda := false
	for _, it := range page.Content {
		if it.ID == u1.ID {
			foundAda = true
			break
		}
	}
	assert.True(t, foundAda)
}

func TestUserRepository_Search_ByAttributeKeys_AND_Terms(t *testing.T) {
	users := repository.NewUserRepository(DataSource)
	attrs := repository.NewAttributeRepository(DataSource)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// keys ANDed together
	aFirst, _ := attrs.AddAttribute(ctx, &repository.AttributeData{Key: fmt.Sprintf("first_%d", time.Now().UnixNano()), Required: false, Hidden: false})
	aCity, _ := attrs.AddAttribute(ctx, &repository.AttributeData{Key: fmt.Sprintf("city_%d", time.Now().UnixNano()), Required: false, Hidden: false})

	u1, _ := users.AddUser(ctx, &repository.UserData{Email: fmt.Sprintf("match.%d@example.com", time.Now().UnixNano()), Password: "pw", Enabled: true})
	u2, _ := users.AddUser(ctx, &repository.UserData{Email: fmt.Sprintf("other.%d@example.com", time.Now().UnixNano()), Password: "pw", Enabled: true})
	defer func() { _ = users.DeleteUserById(ctx, u1.ID) }()
	defer func() { _ = users.DeleteUserById(ctx, u2.ID) }()

	_, _ = users.SetUserAttributes(ctx, &repository.UserAttributesData{
		UserID: u1.ID,
		Attributes: []*repository.UserAttribute{
			{Attribute: aFirst, Value: "Alice"},
			{Attribute: aCity, Value: "Bratislava"},
		},
	})
	_, _ = users.SetUserAttributes(ctx, &repository.UserAttributesData{
		UserID: u2.ID,
		Attributes: []*repository.UserAttribute{
			{Attribute: aFirst, Value: "Bob"},
			{Attribute: aCity, Value: "Kosice"},
		},
	})

	page, err := users.SearchUsers(ctx,
		&repository.SearchUsersCriteria{
			SearchField:   "alice bratislava", // repo ToScDf + unaccent(ua.value) ILIKE
			AttributeKeys: []string{aFirst.Key, aCity.Key},
		},
		&common.Pageable{Page: 0, Size: 10, Sort: "email asc"},
	)
	require.NoError(t, err)

	seeU1, seeU2 := false, false
	for _, it := range page.Content {
		if it.ID == u1.ID {
			seeU1 = true
		}
		if it.ID == u2.ID {
			seeU2 = true
		}
	}
	assert.True(t, seeU1)
	assert.False(t, seeU2)
}

func TestUserRepository_Search_Email_OR_Attribute(t *testing.T) {
	users := repository.NewUserRepository(DataSource)
	attrs := repository.NewAttributeRepository(DataSource)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	aCity, _ := attrs.AddAttribute(ctx, &repository.AttributeData{Key: fmt.Sprintf("city_%d", time.Now().UnixNano()), Required: false, Hidden: false})

	base := time.Now().UnixNano()
	uEmailOnly, _ := users.AddUser(ctx, &repository.UserData{Email: fmt.Sprintf("target-email-%d@example.com", base), Password: "pw", Enabled: true})
	uAttrOnly, _ := users.AddUser(ctx, &repository.UserData{Email: fmt.Sprintf("attr-only-%d@example.com", base), Password: "pw", Enabled: true})
	uNone, _ := users.AddUser(ctx, &repository.UserData{Email: fmt.Sprintf("none-%d@example.com", base), Password: "pw", Enabled: true})
	defer func() { _ = users.DeleteUserById(ctx, uEmailOnly.ID) }()
	defer func() { _ = users.DeleteUserById(ctx, uAttrOnly.ID) }()
	defer func() { _ = users.DeleteUserById(ctx, uNone.ID) }()

	_, _ = users.SetUserAttributes(ctx, &repository.UserAttributesData{
		UserID: uAttrOnly.ID,
		Attributes: []*repository.UserAttribute{
			{Attribute: aCity, Value: "Zvolen"},
		},
	})

	page, err := users.SearchUsers(ctx,
		&repository.SearchUsersCriteria{
			SearchField:   fmt.Sprintf("target-email zvolen"),
			AttributeKeys: []string{aCity.Key},
		},
		&common.Pageable{Page: 0, Size: 20, Sort: "email asc"},
	)
	require.NoError(t, err)

	seeEmailOnly, seeAttrOnly, seeNone := false, false, false
	for _, it := range page.Content {
		switch it.ID {
		case uEmailOnly.ID:
			seeEmailOnly = true
		case uAttrOnly.ID:
			seeAttrOnly = true
		case uNone.ID:
			seeNone = true
		}
	}
	assert.True(t, seeEmailOnly)
	assert.True(t, seeAttrOnly)
	assert.False(t, seeNone)
}

func TestUserRepository_Search_ByAuthorities_OR(t *testing.T) {
	users := repository.NewUserRepository(DataSource)
	auths := repository.NewAuthorityRepository(DataSource)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	base := time.Now().UnixNano()
	r1, _ := auths.AddAuthority(ctx, &repository.AuthorityData{Authority: fmt.Sprintf("ROLE_R1_%d", base)})
	r2, _ := auths.AddAuthority(ctx, &repository.AuthorityData{Authority: fmt.Sprintf("ROLE_R2_%d", base)})

	uR1, _ := users.AddUser(ctx, &repository.UserData{Email: fmt.Sprintf("r1-%d@example.com", base), Password: "pw", Enabled: true})
	uR2, _ := users.AddUser(ctx, &repository.UserData{Email: fmt.Sprintf("r2-%d@example.com", base), Password: "pw", Enabled: true})
	uNone, _ := users.AddUser(ctx, &repository.UserData{Email: fmt.Sprintf("none-%d@example.com", base), Password: "pw", Enabled: true})
	defer func() { _ = users.DeleteUserById(ctx, uR1.ID) }()
	defer func() { _ = users.DeleteUserById(ctx, uR2.ID) }()
	defer func() { _ = users.DeleteUserById(ctx, uNone.ID) }()

	_, _ = users.SetUserAuthorities(ctx, &repository.UserAuthoritiesData{UserID: uR1.ID, Authorities: []*repository.Authority{r1}})
	_, _ = users.SetUserAuthorities(ctx, &repository.UserAuthoritiesData{UserID: uR2.ID, Authorities: []*repository.Authority{r2}})

	page, err := users.SearchUsers(ctx,
		&repository.SearchUsersCriteria{
			SearchField: fmt.Sprintf("%d", base),
			Authorities: []string{r1.Authority, r2.Authority},
		},
		&common.Pageable{Page: 0, Size: 20, Sort: "email asc"},
	)
	require.NoError(t, err)

	seeR1, seeR2, seeNone := false, false, false
	for _, it := range page.Content {
		switch it.ID {
		case uR1.ID:
			seeR1 = true
		case uR2.ID:
			seeR2 = true
		case uNone.ID:
			seeNone = true
		}
	}
	assert.True(t, seeR1, "should match user with r1")
	assert.True(t, seeR2, "should match user with r2")
	assert.False(t, seeNone, "should not match user with no listed authorities")
}

func TestUserRepository_Search_PagingAndSort(t *testing.T) {
	users := repository.NewUserRepository(DataSource)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	base := time.Now().UnixNano()
	u1, _ := users.AddUser(ctx, &repository.UserData{Email: fmt.Sprintf("a-%d@example.com", base), Password: "pw", Enabled: true})
	u2, _ := users.AddUser(ctx, &repository.UserData{Email: fmt.Sprintf("b-%d@example.com", base), Password: "pw", Enabled: true})
	u3, _ := users.AddUser(ctx, &repository.UserData{Email: fmt.Sprintf("c-%d@example.com", base), Password: "pw", Enabled: true})
	defer func() { _ = users.DeleteUserById(ctx, u1.ID) }()
	defer func() { _ = users.DeleteUserById(ctx, u2.ID) }()
	defer func() { _ = users.DeleteUserById(ctx, u3.ID) }()

	page, err := users.SearchUsers(ctx,
		&repository.SearchUsersCriteria{SearchField: fmt.Sprintf("%d", base)},
		&common.Pageable{Page: 0, Size: 2, Sort: "email asc"},
	)
	require.NoError(t, err)
	require.Len(t, page.Content, 2)
	assert.True(t, page.First)
	assert.False(t, page.Last)
	assert.Equal(t, int32(2), page.TotalPages)
	assert.Equal(t, int64(3), page.TotalElements)
	assert.Equal(t, fmt.Sprintf("a-%d@example.com", base), page.Content[0].Email)
	assert.Equal(t, fmt.Sprintf("b-%d@example.com", base), page.Content[1].Email)

	page, err = users.SearchUsers(ctx,
		&repository.SearchUsersCriteria{SearchField: fmt.Sprintf("%d", base)},
		&common.Pageable{Page: 1, Size: 2, Sort: "email asc"},
	)
	require.NoError(t, err)
	require.Len(t, page.Content, 1)
	assert.False(t, page.First)
	assert.True(t, page.Last)
	assert.Equal(t, fmt.Sprintf("c-%d@example.com", base), page.Content[0].Email)
}
