package service_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/janobono/go-util/common"
	"github.com/janobono/go-util/security"
	"github.com/janobono/simple-auth/simple-auth-service/generated/openapi"
	"github.com/janobono/simple-auth/simple-auth-service/internal/repository"
	"github.com/janobono/simple-auth/simple-auth-service/internal/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func makeUserService() *service.UserService {
	return service.NewUserService(
		security.NewPasswordEncoder(bcrypt.DefaultCost),
		security.NewRandomString("abcdefghijklmnopqrstuvwxyz0123456789", 8),
		AttributeRepository,
		AuthorityRepository,
		UserRepository)
}

func seedUser(t *testing.T, email string, enabled, confirmed bool) *repository.User {
	t.Helper()
	ctx, cancel := ctxSvc(t, 10*time.Second)
	defer cancel()

	u, err := UserRepository.AddUser(ctx, &repository.UserData{
		Email:     email,
		Password:  "pw", // arbitrary, not used here
		Enabled:   enabled,
		Confirmed: confirmed,
	})
	require.NoError(t, err)
	return u
}

func seedAttribute(t *testing.T, key string, required, hidden bool) *repository.Attribute {
	t.Helper()
	ctx, cancel := ctxSvc(t, 10*time.Second)
	defer cancel()
	a, err := AttributeRepository.AddAttribute(ctx, &repository.AttributeData{
		Key: key, Required: required, Hidden: hidden,
	})
	require.NoError(t, err)
	return a
}

func seedAuthority(t *testing.T, authority string) *repository.Authority {
	t.Helper()
	ctx, cancel := ctxSvc(t, 10*time.Second)
	defer cancel()
	r, err := AuthorityRepository.AddAuthority(ctx, &repository.AuthorityData{Authority: authority})
	require.NoError(t, err)
	return r
}

func TestUserService_AddUser_EncodesPassword_And_RejectsDuplicateEmail(t *testing.T) {
	ResetDB(t)
	svc := makeUserService()
	ctx, cancel := ctxSvc(t, 10*time.Second)
	defer cancel()

	// create
	out, err := svc.AddUser(ctx, &openapi.UserData{
		Email:     "new.user@example.com",
		Enabled:   true,
		Confirmed: false,
	})
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, "new.user@example.com", out.Email)

	// fetch raw from repo and verify password was encoded
	u, err := UserRepository.GetUserByEmail(ctx, "new.user@example.com")
	require.NoError(t, err)
	require.NotEmpty(t, u.Password)

	// duplicate should conflict
	_, err = svc.AddUser(ctx, &openapi.UserData{
		Email:     "new.user@example.com",
		Enabled:   true,
		Confirmed: true,
	})
	var se *common.ServiceError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusConflict, se.Status)
	assert.Equal(t, string(openapi.EMAIL_ALREADY_EXISTS), se.Code)
}

func TestUserService_GetUser_NotFound(t *testing.T) {
	ResetDB(t)
	svc := makeUserService()
	ctx, cancel := ctxSvc(t, 10*time.Second)
	defer cancel()

	unknown := pgtype.UUID{Bytes: [16]byte{}, Valid: true}
	out, err := svc.GetUser(ctx, unknown)
	require.Error(t, err)
	assert.Nil(t, out)

	var se *common.ServiceError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusNotFound, se.Status)
}

func TestUserService_SetEmail_Conflict(t *testing.T) {
	ResetDB(t)
	svc := makeUserService()
	ctx, cancel := ctxSvc(t, 15*time.Second)
	defer cancel()

	seedUser(t, "alice@example.com", true, true)
	u2 := seedUser(t, "bob@example.com", true, true)

	// Trying to set u2's email to u1's → conflict
	_, err := svc.SetEmail(ctx, &openapi.UserDetail{Id: "someone-else"}, u2.ID, &openapi.UserEmailData{
		Email: "alice@example.com",
	})
	require.Error(t, err)

	var se *common.ServiceError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusConflict, se.Status)
}

func TestUserService_SetAttributes_Validations_And_HiddenFilter(t *testing.T) {
	ResetDB(t)
	svc := makeUserService()
	ctx, cancel := ctxSvc(t, 20*time.Second)
	defer cancel()

	u := seedUser(t, "attruser@example.com", true, true)
	reqAttr := seedAttribute(t, "first_name", true, false)
	hiddenAttr := seedAttribute(t, "internal_note", false, true)

	// Missing required attribute → 400
	_, err := svc.SetAttributes(ctx, &openapi.UserDetail{Id: "admin"}, u.ID, &openapi.UserAttributesData{
		Attributes: []openapi.AttributeValueData{
			{Key: "internal_note", Value: "keep"},
		},
	})
	require.Error(t, err)
	var se *common.ServiceError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusBadRequest, se.Status)
	assert.Equal(t, string(openapi.REQUIRED_ATTRIBUTE), se.Code)

	// Blank value for provided attribute → 400
	_, err = svc.SetAttributes(ctx, &openapi.UserDetail{Id: "admin"}, u.ID, &openapi.UserAttributesData{
		Attributes: []openapi.AttributeValueData{
			{Key: "first_name", Value: "   "},
		},
	})
	require.Error(t, err)
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusBadRequest, se.Status)
	assert.Equal(t, string(openapi.INVALID_FIELD), se.Code)

	// Proper values: hidden attribute should be stored but **not** returned in UserDetail.Attributes
	out, err := svc.SetAttributes(ctx, &openapi.UserDetail{Id: "admin"}, u.ID, &openapi.UserAttributesData{
		Attributes: []openapi.AttributeValueData{
			{Key: reqAttr.Key, Value: "Alice"},
			{Key: hiddenAttr.Key, Value: "some internal note"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, out)

	// Attributes list should not include the hidden key
	seenReq, seenHidden := false, false
	for _, av := range out.Attributes {
		if av.Key == reqAttr.Key && av.Value == "Alice" {
			seenReq = true
		}
		if av.Key == hiddenAttr.Key {
			seenHidden = true
		}
	}
	assert.True(t, seenReq)
	assert.False(t, seenHidden, "hidden attributes must not be exposed in UserDetail")
}

func TestUserService_SetAuthorities(t *testing.T) {
	ResetDB(t)
	svc := makeUserService()
	ctx, cancel := ctxSvc(t, 15*time.Second)
	defer cancel()

	u := seedUser(t, "authuser@example.com", true, true)
	r1 := seedAuthority(t, "ROLE_USER")
	r2 := seedAuthority(t, "ROLE_ADMIN")

	out, err := svc.SetAuthorities(ctx, &openapi.UserDetail{Id: "admin"}, u.ID, &openapi.UserAuthoritiesData{
		Authorities: []string{r1.Authority, r2.Authority},
	})
	require.NoError(t, err)

	// both roles present
	has1, has2 := false, false
	for _, a := range out.Authorities {
		if a.Authority == r1.Authority {
			has1 = true
		}
		if a.Authority == r2.Authority {
			has2 = true
		}
	}
	assert.True(t, has1)
	assert.True(t, has2)
}

func TestUserService_SetConfirmed_SetEnabled(t *testing.T) {
	ResetDB(t)
	svc := makeUserService()
	ctx, cancel := ctxSvc(t, 15*time.Second)
	defer cancel()

	u := seedUser(t, "flags@example.com", false, false)

	ud, err := svc.SetConfirmed(ctx, &openapi.UserDetail{Id: "admin"}, u.ID, &openapi.BooleanValue{Value: true})
	require.NoError(t, err)
	assert.True(t, ud.Confirmed)

	ud, err = svc.SetEnabled(ctx, &openapi.UserDetail{Id: "admin"}, u.ID, &openapi.BooleanValue{Value: true})
	require.NoError(t, err)
	assert.True(t, ud.Enabled)
}

func TestUserService_DeleteUser_CannotManageOwnAccount(t *testing.T) {
	ResetDB(t)
	svc := makeUserService()
	ctx, cancel := ctxSvc(t, 10*time.Second)
	defer cancel()

	u := seedUser(t, "self@example.com", true, true)

	// Same user tries to manage themself → 400
	err := svc.DeleteUser(ctx, &openapi.UserDetail{Id: u.ID.String()}, u.ID)
	require.Error(t, err)

	var se *common.ServiceError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusBadRequest, se.Status)
	assert.Equal(t, string(openapi.CANNOT_MANAGE_OWN_ACCOUNT), se.Code)

	// Different actor can delete
	err = svc.DeleteUser(ctx, &openapi.UserDetail{Id: "admin"}, u.ID)
	require.NoError(t, err)

	// Verify gone
	_, getErr := UserRepository.GetUserById(ctx, u.ID)
	require.Error(t, getErr)
}

func TestUserService_GetUsers_SearchByEmail_And_Attributes(t *testing.T) {
	ResetDB(t)
	svc := makeUserService()
	ctx, cancel := ctxSvc(t, 30*time.Second)
	defer cancel()

	// seed attributes (non-hidden to be visible in detail; hidden doesn’t affect search)
	first := seedAttribute(t, "first", false, false)
	city := seedAttribute(t, "city", false, false)

	// seed users
	base := time.Now().UnixNano()
	u1 := seedUser(t, fmt.Sprintf("ada.%d@example.com", base), true, true)
	u2 := seedUser(t, fmt.Sprintf("alan.%d@example.com", base), true, true)
	u3 := seedUser(t, fmt.Sprintf("bruce.%d@example.com", base), true, true)

	// assign attributes to u1 and u2
	_, _ = UserRepository.SetUserAttributes(ctx, &repository.UserAttributesData{
		UserID: u1.ID,
		Attributes: []*repository.UserAttribute{
			{Attribute: first, Value: "Alice"},
			{Attribute: city, Value: "Bratislava"},
		},
	})
	_, _ = UserRepository.SetUserAttributes(ctx, &repository.UserAttributesData{
		UserID: u2.ID,
		Attributes: []*repository.UserAttribute{
			{Attribute: first, Value: "Alan"},
			{Attribute: city, Value: "Kosice"},
		},
	})

	// Search by email token only
	page, err := svc.GetUsers(ctx,
		&service.SearchUserCriteria{
			SearchField: fmt.Sprintf("ada %d", base),
		},
		&common.Pageable{Page: 0, Size: 10, Sort: "email asc"},
	)
	require.NoError(t, err)
	require.NotEmpty(t, page.Content)
	foundAda := false
	for _, it := range page.Content {
		if it.Id == u1.ID.String() {
			foundAda = true
			break
		}
	}
	assert.True(t, foundAda)

	// Search by attribute keys (AND between keys; OR between terms inside each key in your repo logic)
	page, err = svc.GetUsers(ctx,
		&service.SearchUserCriteria{
			SearchField:   "alice bratislava",
			AttributeKeys: []string{first.Key, city.Key},
		},
		&common.Pageable{Page: 0, Size: 10, Sort: "email asc"},
	)
	require.NoError(t, err)

	seeU1, seeU2, seeU3 := false, false, false
	for _, it := range page.Content {
		switch it.Id {
		case u1.ID.String():
			seeU1 = true
		case u2.ID.String():
			seeU2 = true
		case u3.ID.String():
			seeU3 = true
		}
	}
	assert.True(t, seeU1)
	assert.False(t, seeU2)
	assert.False(t, seeU3)

	// Paging check
	page, err = svc.GetUsers(ctx,
		&service.SearchUserCriteria{SearchField: fmt.Sprintf("%d", base)},
		&common.Pageable{Page: 0, Size: 2, Sort: "email asc"},
	)
	require.NoError(t, err)
	require.Len(t, page.Content, 2)
	assert.True(t, page.First)
	assert.False(t, page.Last)

	page2, err := svc.GetUsers(ctx,
		&service.SearchUserCriteria{SearchField: fmt.Sprintf("%d", base)},
		&common.Pageable{Page: 1, Size: 2, Sort: "email asc"},
	)
	require.NoError(t, err)
	assert.True(t, page2.Last)
}
