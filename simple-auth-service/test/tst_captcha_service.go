package test

import (
	"context"
	"sync"

	"github.com/janobono/simple-auth/simple-auth-service/generated/openapi"
)

type TstCaptchaService struct {
	rw        sync.RWMutex
	lastToken string
}

func (t *TstCaptchaService) Create(context.Context) (*openapi.Captcha, error) {
	t.rw.Lock()
	t.lastToken = "test-token"
	tok := t.lastToken
	t.rw.Unlock()
	return &openapi.Captcha{CaptchaToken: tok}, nil
}

func (t *TstCaptchaService) Validate(_ context.Context, d *openapi.CaptchaData) *openapi.BooleanValue {
	if d == nil {
		return &openapi.BooleanValue{Value: false}
	}
	t.rw.RLock()
	ok := d.CaptchaToken == t.lastToken
	t.rw.RUnlock()
	return &openapi.BooleanValue{Value: ok}
}

func (t *TstCaptchaService) SetToken(token string) {
	t.rw.Lock()
	t.lastToken = token
	t.rw.Unlock()
}

func (t *TstCaptchaService) Reset() { t.SetToken("") }
