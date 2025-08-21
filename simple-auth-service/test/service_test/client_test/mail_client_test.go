package client_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/janobono/simple-auth/simple-auth-service/internal/service/client"
	"github.com/stretchr/testify/require"
)

type mailhogMessage struct {
	ID      string `json:"ID"`
	Content struct {
		Headers map[string][]string `json:"Headers"`
		Body    string              `json:"Body"`
	} `json:"Content"`
}

type mailhogAPIResponse struct {
	Total int              `json:"total"`
	Count int              `json:"count"`
	Items []mailhogMessage `json:"items"`
}

func TestSendEmail_WithMailHog_AndCleanup(t *testing.T) {
	mc := client.NewMailClient(MailConfig)
	baseURL := fmt.Sprintf("http://%s:%s", MailConfig.Host, HttpPort.Port())
	httpc := &http.Client{Timeout: 5 * time.Second}

	// Clean inbox at start
	_, _ = httpc.Post(baseURL+"/api/v1/messages", "application/json", nil) // MailHog v1 API delete-all

	// Temp attachment to test cleanup
	dir := t.TempDir()
	tmpFile := filepath.Join(dir, "attach.txt")
	require.NoError(t, os.WriteFile(tmpFile, []byte("hello attachment"), 0o600))

	data := &client.MailData{
		From:        "no-reply@example.com",
		Recipients:  []string{"dest@example.com"},
		Cc:          []string{"cc@example.com"},
		Subject:     "Test Subject - MailHog",
		ContentType: "text/plain",
		Body:        "Hello MailHog!",
		Attachments: map[string]string{
			"readme.txt": tmpFile,
		},
	}
	mc.SendEmail(data)

	// Poll MailHog API
	var respData mailhogAPIResponse
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := httpc.Get(baseURL + "/api/v2/messages")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			_ = json.Unmarshal(body, &respData)
			if len(respData.Items) > 0 {
				break
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	require.GreaterOrEqual(t, len(respData.Items), 1, "MailHog should have received at least one message")

	got := respData.Items[0]
	require.Contains(t, got.Content.Headers["Subject"], "Test Subject - MailHog")
	require.Contains(t, got.Content.Body, "Hello MailHog!")
	require.Contains(t, got.Content.Headers["From"], "no-reply@example.com")
	require.Contains(t, got.Content.Headers["To"], "dest@example.com")
	require.Contains(t, got.Content.Headers["Cc"], "cc@example.com")

	// Wait for cleanup
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	_, statErr := os.Stat(tmpFile)
	require.True(t, os.IsNotExist(statErr), "attachment should have been removed by cleanUp")

	// Clean inbox at end
	req, _ := http.NewRequest(http.MethodDelete, baseURL+"/api/v1/messages", nil)
	_, _ = httpc.Do(req)
}
