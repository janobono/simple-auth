package test

import (
	"errors"
	"html"
	"net/url"
	"strings"
	"sync"

	"github.com/janobono/go-util/common"
	"github.com/janobono/simple-auth/simple-auth-service/internal/service/client"
)

type TstMailClient struct {
	rw       sync.RWMutex
	lastMail client.MailData
}

func (t *TstMailClient) SendEmail(data *client.MailData) {
	t.rw.Lock()
	t.lastMail = *data
	t.rw.Unlock()
}

func (t *TstMailClient) LastEmail() client.MailData {
	t.rw.RLock()
	defer t.rw.RUnlock()
	return t.lastMail
}

func (t *TstMailClient) Reset() {
	t.rw.Lock()
	t.lastMail = client.MailData{}
	t.rw.Unlock()
}

func (t *TstMailClient) Token() (string, error) {
	t.rw.RLock()
	defer t.rw.RUnlock()

	body := t.lastMail.Body

	pos := strings.Index(body, "?token=")

	start := pos + len("?token=")

	endRel := strings.IndexByte(body[start:], '"')

	end := start + endRel

	raw := html.UnescapeString(body[start:end])

	return url.QueryUnescape(raw)
}

func (t *TstMailClient) NewPassword() (string, error) {
	t.rw.RLock()
	defer t.rw.RUnlock()

	body := t.lastMail.Body

	pStart := strings.Index(body, "<p>")

	pEndRel := strings.Index(body[pStart:], "</p>")

	pEnd := pStart + pEndRel

	newPw := body[pStart+len("<p>") : pEnd]

	newPw = strings.TrimSpace(html.UnescapeString(newPw))

	if common.IsBlank(newPw) {
		return "", errors.New("password is blank")
	}

	return newPw, nil
}
