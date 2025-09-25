package service_test

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/janobono/go-util/common"
	"github.com/janobono/go-util/security"
	"github.com/janobono/simple-auth/simple-auth-service/generated/openapi"
	"github.com/janobono/simple-auth/simple-auth-service/internal/config"
	"github.com/janobono/simple-auth/simple-auth-service/internal/repository"
	"github.com/janobono/simple-auth/simple-auth-service/internal/service"
	"github.com/janobono/simple-auth/simple-auth-service/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

/************** Test Doubles **************/

var (
	testMailClient     = &test.TstMailClient{}
	testCaptchaService = &test.TstCaptchaService{}
)

/************** Helpers **************/

func makeTempTemplates(t *testing.T) (signupTpl, resetTpl string) {
	t.Helper()
	dir := t.TempDir()
	sign := filepath.Join(dir, "signup.html")
	reset := filepath.Join(dir, "reset.html")

	// include explicit token link to extract easily, and plain password for reset
	require.NoError(t, os.WriteFile(sign, []byte(`<a href="{{.ConfirmationUrl}}">Confirm</a>`), 0o600))
	require.NoError(t, os.WriteFile(reset, []byte(`<p>{{.NewPassword}}</p><a href="{{.ConfirmationUrl}}">Reset</a>`), 0o600))
	return sign, reset
}

func makeAuthService(t *testing.T, mandatoryAttrs map[string]string, mandatoryAuths []string) *service.AuthService {
	t.Helper()
	signTpl, resetTpl := makeTempTemplates(t)

	appCfg := &config.AppConfig{
		ConfirmationWebUrl:            "https://example.test",
		ConfirmationPath:              "/confirm?token=",
		SignUpConfirmationMailEnabled: true,
		MandatoryUserAttributes:       mandatoryAttrs,
		MandatoryUserAuthorities:      mandatoryAuths,
	}
	mailCfg := &config.MailConfig{
		User:                         "no-reply@example.test",
		SignUpMailSubject:            "Welcome!",
		SignUpMailTemplateUrl:        signTpl,
		ResetPasswordMailSubject:     "Reset",
		ResetPasswordMailTemplateUrl: resetTpl,
	}
	return service.NewAuthService(
		appCfg,
		mailCfg,
		security.NewPasswordEncoder(bcrypt.DefaultCost),
		security.NewRandomString("abc012", 8),
		testMailClient,
		service.NewJwtService(defaultJwtCfg(), JwkRepository),
		testCaptchaService,
		AttributeRepository,
		AuthorityRepository,
		UserRepository,
	)
}

func seedAttr(t *testing.T, key string, required, hidden bool) *repository.Attribute {
	t.Helper()
	ctx, cancel := ctxSvc(t, 10*time.Second)
	defer cancel()
	a, err := AttributeRepository.AddAttribute(ctx, &repository.AttributeData{Key: key, Required: required, Hidden: hidden})
	require.NoError(t, err)
	return a
}

func seedAuth(t *testing.T, val string) *repository.Authority {
	t.Helper()
	ctx, cancel := ctxSvc(t, 10*time.Second)
	defer cancel()
	r, err := AuthorityRepository.AddAuthority(ctx, &repository.AuthorityData{Authority: val})
	require.NoError(t, err)
	return r
}

/************** Tests **************/

func TestAuthService_SignUp_Confirm_SignIn_Refresh(t *testing.T) {
	ResetDB(t)
	testMailClient.Reset()
	testCaptchaService.Reset()

	seedAttr(t, "first", true, false)
	role := seedAuth(t, "ROLE_USER")

	svc := makeAuthService(t, map[string]string{"first": "Alice"}, []string{role.Authority})
	ctx, cancel := ctxSvc(t, 20*time.Second)
	defer cancel()

	testCaptchaService.SetToken("abc123")

	// SignUp
	signUpOut, err := svc.SignUp(ctx, &openapi.SignUp{
		Email:        " Person@Example.com ",
		Password:     "secret-1",
		Attributes:   []openapi.AttributeValueData{},
		CaptchaToken: "abc123",
	})
	require.NoError(t, err)
	require.NotEmpty(t, signUpOut.AccessToken)
	require.NotEmpty(t, signUpOut.RefreshToken)

	// Email sent and normalized
	lastMail := testMailClient.LastEmail()
	assert.Equal(t, "Welcome!", lastMail.Subject)
	assert.Equal(t, "text/html; charset=utf-8", lastMail.ContentType)
	assert.Equal(t, []string{"person@example.com"}, lastMail.Recipients)

	// Resend confirmation
	testCaptchaService.SetToken("abc124")
	require.NoError(t, svc.ResendConfirmation(ctx, &openapi.ResendConfirmation{
		Email:        "person@example.com",
		CaptchaToken: "abc124",
	}))

	token, err := testMailClient.Token()
	require.NoError(t, err)

	// Confirm
	confirmOut, err := svc.Confirm(ctx, &openapi.Confirmation{Token: token})
	require.NoError(t, err)
	require.NotEmpty(t, confirmOut.AccessToken)

	// Sign in
	signInOut, err := svc.SignIn(ctx, &openapi.SignIn{
		Email:    "person@example.com",
		Password: "secret-1",
	})
	require.NoError(t, err)
	require.NotEmpty(t, signInOut.AccessToken)

	// Refresh
	refOut, err := svc.RefreshToken(ctx, signInOut.RefreshToken)
	require.NoError(t, err)
	require.NotEmpty(t, refOut.AccessToken)
}

func TestAuthService_ChangeEmail_Success_And_Conflict(t *testing.T) {
	ResetDB(t)
	testMailClient.Reset()
	testCaptchaService.Reset()

	_ = seedAttr(t, "first", false, false)
	_ = seedAuth(t, "ROLE_USER")
	svc := makeAuthService(t, map[string]string{}, []string{})

	ctx, cancel := ctxSvc(t, 20*time.Second)
	defer cancel()

	// Create two users
	_, err := UserRepository.AddUser(ctx, &repository.UserData{Email: "a@example.com", Password: hash("secret"), Confirmed: true, Enabled: true})
	require.NoError(t, err)
	u2, err := UserRepository.AddUser(ctx, &repository.UserData{Email: "b@example.com", Password: hash("secret"), Confirmed: true, Enabled: true})
	require.NoError(t, err)

	testCaptchaService.SetToken("tok")

	// Conflict (try to set u2 email to u1's)
	_, err = svc.ChangeEmail(ctx, &openapi.UserDetail{Id: u2.ID.String()}, &openapi.ChangeEmail{
		Email:        "a@example.com",
		Password:     "secret",
		CaptchaToken: "tok",
	})
	require.Error(t, err)
	var se *common.ServiceError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusBadRequest, se.Status)
	assert.Equal(t, string(openapi.EMAIL_ALREADY_EXISTS), se.Code)

	// Success
	out, err := svc.ChangeEmail(ctx, &openapi.UserDetail{Id: u2.ID.String()}, &openapi.ChangeEmail{
		Email:        "  New@Example.com ",
		Password:     "secret",
		CaptchaToken: "tok",
	})
	require.NoError(t, err)
	require.NotEmpty(t, out.AccessToken)

	uu2, err := UserRepository.GetUserById(ctx, u2.ID)
	require.NoError(t, err)
	assert.Equal(t, "new@example.com", uu2.Email)
}

func TestAuthService_ChangePassword_Success_And_WrongOld(t *testing.T) {
	ResetDB(t)
	svc := makeAuthService(t, nil, nil)
	ctx, cancel := ctxSvc(t, 20*time.Second)
	defer cancel()

	u, err := UserRepository.AddUser(ctx, &repository.UserData{
		Email: "p@example.com", Password: hash("oldpw"), Confirmed: true, Enabled: true,
	})
	require.NoError(t, err)

	testCaptchaService.SetToken("tok")
	// wrong old
	_, err = svc.ChangePassword(ctx, &openapi.UserDetail{Id: u.ID.String()}, &openapi.ChangePassword{
		OldPassword:  "nope",
		NewPassword:  "newpw",
		CaptchaToken: "tok",
	})
	require.Error(t, err)
	var se *common.ServiceError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusForbidden, se.Status)
	assert.Equal(t, string(openapi.INVALID_CREDENTIALS), se.Code)

	// success
	out, err := svc.ChangePassword(ctx, &openapi.UserDetail{Id: u.ID.String()}, &openapi.ChangePassword{
		OldPassword:  "oldpw",
		NewPassword:  "newpw",
		CaptchaToken: "tok",
	})
	require.NoError(t, err)
	require.NotEmpty(t, out.AccessToken)
}

func TestAuthService_ChangeUserAttributes_Validations(t *testing.T) {
	ResetDB(t)
	// Define attributes
	first := seedAttr(t, "first", false, false)
	_ = first
	seedAttr(t, "last", true, false) // required, not hidden
	seedAttr(t, "internal", false, true)

	svc := makeAuthService(t, map[string]string{}, []string{})
	ctx, cancel := ctxSvc(t, 20*time.Second)
	defer cancel()

	u, err := UserRepository.AddUser(ctx, &repository.UserData{
		Email: "attr@example.com", Password: hash("pw"), Confirmed: true, Enabled: true,
	})
	require.NoError(t, err)

	// Seed one non-hidden attribute on the user (so mandatory map contains it)
	_, err = UserRepository.SetUserAttributes(ctx, &repository.UserAttributesData{
		UserID: u.ID,
		Attributes: []*repository.UserAttribute{
			{Attribute: first, Value: "Alice"},
		},
	})
	require.NoError(t, err)

	testCaptchaService.SetToken("tok")

	// Unknown key
	_, err = svc.ChangeUserAttributes(ctx, &openapi.UserDetail{Id: u.ID.String()}, &openapi.ChangeUserAttributes{
		Attributes:   []openapi.AttributeValueData{{Key: "unknown", Value: "x"}},
		CaptchaToken: "tok",
	})
	require.Error(t, err)

	// Hidden key not allowed
	_, err = svc.ChangeUserAttributes(ctx, &openapi.UserDetail{Id: u.ID.String()}, &openapi.ChangeUserAttributes{
		Attributes:   []openapi.AttributeValueData{{Key: "internal", Value: "secret"}},
		CaptchaToken: "tok",
	})
	require.Error(t, err)

	// Missing required "last" -> should fail REQUIRED_ATTRIBUTE
	_, err = svc.ChangeUserAttributes(ctx, &openapi.UserDetail{Id: u.ID.String()}, &openapi.ChangeUserAttributes{
		Attributes:   []openapi.AttributeValueData{{Key: "first", Value: "Alice2"}},
		CaptchaToken: "tok",
	})
	require.Error(t, err)
	var se *common.ServiceError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusBadRequest, se.Status)
	assert.Equal(t, string(openapi.REQUIRED_ATTRIBUTE), se.Code)

	// Provide required "last" -> success
	out, err := svc.ChangeUserAttributes(ctx, &openapi.UserDetail{Id: u.ID.String()}, &openapi.ChangeUserAttributes{
		Attributes:   []openapi.AttributeValueData{{Key: "first", Value: "Alice2"}, {Key: "last", Value: "Smith"}},
		CaptchaToken: "tok",
	})
	require.NoError(t, err)
	require.NotEmpty(t, out.AccessToken)
}

func TestAuthService_ResendConfirmation_NotFound(t *testing.T) {
	ResetDB(t)
	svc := makeAuthService(t, nil, nil)
	ctx, cancel := ctxSvc(t, 10*time.Second)
	defer cancel()

	testCaptchaService.SetToken("tok")
	err := svc.ResendConfirmation(ctx, &openapi.ResendConfirmation{
		Email:        "missing@example.com",
		CaptchaToken: "tok",
	})
	require.Error(t, err)
	var se *common.ServiceError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusNotFound, se.Status)
}

func TestAuthService_ResetPassword_Flow(t *testing.T) {
	ResetDB(t)
	testMailClient.Reset()
	testCaptchaService.Reset()

	svc := makeAuthService(t, nil, nil)
	ctx, cancel := ctxSvc(t, 20*time.Second)
	defer cancel()

	_, err := UserRepository.AddUser(ctx, &repository.UserData{
		Email: "rp@example.com", Password: hash("old"), Confirmed: true, Enabled: true,
	})
	require.NoError(t, err)

	testCaptchaService.SetToken("tok")
	// Request reset -> mail sent with new password and a confirmation link
	require.NoError(t, svc.ResetPassword(ctx, &openapi.ResetPassword{
		Email:        "rp@example.com",
		CaptchaToken: "tok",
	}))

	m := testMailClient.LastEmail()
	require.Equal(t, "Reset", m.Subject)

	newPw, err := testMailClient.NewPassword()
	require.NoError(t, err)

	token, err := testMailClient.Token()
	require.NoError(t, err)

	// Confirm reset -> sets password in DB
	_, err = svc.Confirm(ctx, &openapi.Confirmation{Token: token})
	require.NoError(t, err)

	// Sign in with new password works
	_, err = svc.SignIn(ctx, &openapi.SignIn{Email: "rp@example.com", Password: newPw})
	require.NoError(t, err)
}

func TestAuthService_SignIn_ErrorCases(t *testing.T) {
	ResetDB(t)
	svc := makeAuthService(t, nil, nil)
	ctx, cancel := ctxSvc(t, 10*time.Second)
	defer cancel()

	// Unknown
	_, err := svc.SignIn(ctx, &openapi.SignIn{Email: "x@x", Password: "pw"})
	require.Error(t, err)
	var se *common.ServiceError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusNotFound, se.Status)

	// Disabled
	u, _ := UserRepository.AddUser(ctx, &repository.UserData{
		Email: "d@x", Password: hash("pw"), Confirmed: true, Enabled: false,
	})
	_, err = svc.SignIn(ctx, &openapi.SignIn{Email: u.Email, Password: "pw"})
	require.Error(t, err)
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusForbidden, se.Status)
	assert.Equal(t, string(openapi.USER_NOT_ENABLED), se.Code)

	// Wrong password
	_, _ = UserRepository.SetUserEnabled(ctx, u.ID, true)
	_, err = svc.SignIn(ctx, &openapi.SignIn{Email: u.Email, Password: "nope"})
	require.Error(t, err)
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusForbidden, se.Status)
	assert.Equal(t, string(openapi.INVALID_CREDENTIALS), se.Code)
}

func TestAuthService_Refresh_InvalidToken(t *testing.T) {
	ResetDB(t)
	svc := makeAuthService(t, nil, nil)
	ctx, cancel := ctxSvc(t, 10*time.Second)
	defer cancel()

	_, err := svc.RefreshToken(ctx, "not.a.jwt")
	require.Error(t, err)
	var se *common.ServiceError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusBadRequest, se.Status)
	assert.Equal(t, string(openapi.INVALID_FIELD), se.Code)
}

/************** tiny util **************/
func hash(pw string) string {
	enc := security.NewPasswordEncoder(bcrypt.DefaultCost)
	out, _ := enc.Encode(pw)
	return out
}
