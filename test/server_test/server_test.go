package server_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"syscall"
	"testing"
	"time"

	"github.com/janobono/go-util/db"
	"github.com/janobono/simple-auth/simple-auth-service/generated/openapi"
	"github.com/stretchr/testify/require"
)

var (
	publicGetEndpoints = []string{
		"/captcha",
		"/livez",
		"/readyz",
		"/.well-known/jwks.json",
	}

	protectedGetEndpoints = []string{
		"/attributes",
		"/attributes/" + db.NewUUID().String(),
		"/authorities",
		"/authorities/" + db.NewUUID().String(),
		"/users",
		"/users/" + db.NewUUID().String(),
	}

	ContentType     = "Content-Type"
	ApplicationJson = "application/json"
	ErrorTemplate   = "error: %s"
)

func TestE2E(t *testing.T) {
	go Server.Start()
	defer func() {
		syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
		time.Sleep(1 * time.Second)
	}()
	time.Sleep(500 * time.Millisecond)

	t.Run("01_Public GET enpoints", func(t *testing.T) {
		for _, endpoint := range publicGetEndpoints {
			req, err := http.NewRequest(http.MethodGet, baseURL+endpoint, nil)
			require.NoError(t, err)

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			require.Equal(t, http.StatusOK, resp.StatusCode)
		}
	})

	t.Run("02_Protected GET enpoints", func(t *testing.T) {
		for _, endpoint := range protectedGetEndpoints {
			req, err := http.NewRequest(http.MethodGet, baseURL+endpoint, nil)
			require.NoError(t, err)

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		}
	})

	t.Run("03_Captcha test", func(t *testing.T) {
		endpoint := "/captcha"
		captchaService.SetToken("test")

		// Get
		req, err := http.NewRequest(http.MethodGet, baseURL+endpoint, nil)
		require.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var captchaResponse openapi.Captcha
		err = json.Unmarshal(body, &captchaResponse)
		require.NoError(t, err)

		// Post
		payload, err := json.Marshal(openapi.CaptchaData{
			CaptchaToken: captchaResponse.CaptchaToken,
			CaptchaText:  "test",
		})
		require.NoError(t, err)

		req, err = http.NewRequest(http.MethodPost, baseURL+endpoint, bytes.NewBuffer(payload))
		require.NoError(t, err)

		resp, err = http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		body, err = io.ReadAll(resp.Body)
		require.NoError(t, err)

		var booleanValue openapi.BooleanValue
		err = json.Unmarshal(body, &booleanValue)
		require.NoError(t, err)

		require.Equal(t, true, booleanValue.Value)
	})

	t.Run("04_Sign in test", func(t *testing.T) {
		req, errMessage, err := signIn(&openapi.SignIn{
			Email:    "simple@auth.org",
			Password: "simple",
		})
		require.NoError(t, err)
		require.Nil(t, errMessage)
		require.NotNil(t, req)
		require.NotEmpty(t, req.AccessToken)
		require.NotEmpty(t, req.RefreshToken)
	})

}

func signIn(data *openapi.SignIn) (*openapi.AuthenticationResponse, *openapi.ErrorMessage, error) {
	payload, err := json.Marshal(data)
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequest(http.MethodPost, baseURL+"/auth/sign-in", bytes.NewBuffer(payload))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set(ContentType, ApplicationJson)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println(err)
		}
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	if resp.StatusCode != http.StatusOK {
		var errorMessage openapi.ErrorMessage
		err = json.Unmarshal(body, &errorMessage)
		if err != nil {
			return nil, nil, err
		}
		return nil, &errorMessage, fmt.Errorf(ErrorTemplate, resp.Status)
	}

	var authenticationResponse openapi.AuthenticationResponse
	err = json.Unmarshal(body, &authenticationResponse)
	if err != nil {
		return nil, nil, err
	}
	return &authenticationResponse, nil, nil
}
