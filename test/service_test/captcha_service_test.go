package service_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/janobono/go-util/security"
	"github.com/janobono/simple-auth/simple-auth-service/generated/openapi"
	"github.com/janobono/simple-auth/simple-auth-service/internal/config"
	"github.com/janobono/simple-auth/simple-auth-service/internal/service"
	"golang.org/x/crypto/bcrypt"
)

func TestCaptchaService(t *testing.T) {
	appConfig := &config.CaptchaConfig{
		Characters: "abcdefghijklmnopqrstuvwxyz0123456789",
		TextLength: 8,
		Width:      200,
		Height:     70,
		Font:       getFontPath(),
		FontSize:   36,
		NoiseLines: 8,
	}

	captchaService := service.NewCaptchaService(
		appConfig,
		security.NewPasswordEncoder(bcrypt.DefaultCost),
		service.NewJwtService(
			&config.SecurityConfig{
				TokenIssuer:              "simple-auth-tests",
				AccessTokenExpiresIn:     1 * time.Minute,
				AccessTokenJwkExpiresIn:  2 * time.Second,
				RefreshTokenExpiresIn:    1 * time.Minute,
				RefreshTokenJwkExpiresIn: 2 * time.Second,
				ContentTokenExpiresIn:    1 * time.Minute,
				ContentTokenJwkExpiresIn: 2 * time.Second,
			},
			JwkRepository,
		))

	ctx := context.Background()

	// Step 1: Generate new CAPTCHA
	detail, err := captchaService.Create(ctx)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if detail.CaptchaToken == "" {
		t.Error("CaptchaToken is empty")
	}
	if !strings.HasPrefix(detail.CaptchaImage, "data:image/png;base64,") {
		t.Error("CaptchaImage is not a valid base64 image")
	}

	// Step 2: Validate wrong value
	wrong := &openapi.CaptchaData{
		CaptchaToken: detail.CaptchaToken,
		CaptchaText:  "WRONG",
	}
	if captchaService.Validate(ctx, wrong).Value {
		t.Error("Expected CAPTCHA validation to fail with incorrect input")
	}
}

func getFontPath() string {
	// First: check if an environment variable is set to override font path
	if customFont := os.Getenv("CAPTCHA_FONT"); customFont != "" {
		return customFont
	}

	switch runtime.GOOS {
	case "darwin": // macOS
		possiblePaths := []string{
			"/System/Library/Fonts/Supplemental/Arial Bold.ttf",
			"/System/Library/Fonts/Supplemental/Verdana Bold.ttf",
			"/Library/Fonts/Arial Bold.ttf",
			filepath.Join(os.Getenv("HOME"), "Library/Fonts/Arial Bold.ttf"),
		}
		for _, p := range possiblePaths {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	case "linux":
		possiblePaths := []string{
			"/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
			"/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
		}
		for _, p := range possiblePaths {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}

	// Fallback: empty string (server might handle missing font)
	return ""
}
