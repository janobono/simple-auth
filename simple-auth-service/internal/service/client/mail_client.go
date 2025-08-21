package client

import (
	"errors"
	"log/slog"
	"os"

	"github.com/janobono/simple-auth/simple-auth-service/internal/config"
	"gopkg.in/gomail.v2"
)

type MailData struct {
	From        string
	ReplyTo     string
	Recipients  []string
	Cc          []string
	Subject     string
	ContentType string
	Body        string
	Attachments map[string]string // filename -> file path
}

type MailClient interface {
	SendEmail(data *MailData)
}

type mailClient struct {
	mailConfig *config.MailConfig
}

var _ MailClient = (*mailClient)(nil)

func NewMailClient(mailConfig *config.MailConfig) MailClient {
	return &mailClient{mailConfig: mailConfig}
}

func (mc *mailClient) SendEmail(data *MailData) {
	go func() {
		defer mc.cleanUp(data)

		err := mc.validateMailData(data)
		if err != nil {
			slog.Error("Invalid mail data", "error", err)
			return
		}

		message := gomail.NewMessage()
		message.SetHeader("From", data.From)
		message.SetHeader("To", data.Recipients...)

		if data.ReplyTo != "" {
			message.SetHeader("Reply-To", data.ReplyTo)
		}
		if len(data.Cc) > 0 {
			message.SetHeader("Cc", data.Cc...)
		}

		message.SetHeader("Subject", data.Subject)

		message.SetBody(data.ContentType, data.Body)

		for name, path := range data.Attachments {
			message.Attach(path, gomail.Rename(name))
		}

		dialer := gomail.NewDialer(mc.mailConfig.Host, mc.mailConfig.Port, mc.mailConfig.User, mc.mailConfig.Password)
		dialer.SSL = mc.mailConfig.TlsEnabled

		if !mc.mailConfig.AuthEnabled {
			dialer.Username = ""
			dialer.Password = ""
		}

		if err := dialer.DialAndSend(message); err != nil {
			slog.Error("Email send failed", "error", err)
		}
	}()
}

func (mc *mailClient) validateMailData(d *MailData) error {
	if d == nil {
		return errors.New("mail data is nil")
	}
	if d.From == "" {
		return errors.New("mail from is empty")
	}
	if len(d.Recipients) == 0 {
		return errors.New("no recipients specified")
	}
	if d.Subject == "" {
		return errors.New("subject is empty")
	}
	if d.ContentType == "" {
		d.ContentType = "text/plain"
	}
	// tolerate nil maps/slices
	if d.Attachments == nil {
		d.Attachments = map[string]string{}
	}
	return nil
}

func (mc *mailClient) cleanUp(data *MailData) {
	for _, path := range data.Attachments {
		if err := os.Remove(path); err != nil {
			slog.Error("Failed to delete attachment", "error", err)
		}
	}
}
