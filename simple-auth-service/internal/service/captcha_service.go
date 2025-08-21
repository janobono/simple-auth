package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"image/png"
	"math/rand"

	"github.com/fogleman/gg"
	"github.com/golang-jwt/jwt/v5"
	"github.com/janobono/go-util/security"
	"github.com/janobono/simple-auth/simple-auth-service/generated/openapi"
	"github.com/janobono/simple-auth/simple-auth-service/internal/config"
)

const tokenKey = "encodedText"

type CaptchaService interface {
	Create(ctx context.Context) (*openapi.Captcha, error)
	Validate(ctx context.Context, captchaData *openapi.CaptchaData) *openapi.BooleanValue
}

type captchaService struct {
	captchaConfig   *config.CaptchaConfig
	passwordEncoder *security.PasswordEncoder
	randomString    *security.RandomString
	jwtService      *JwtService
}

func NewCaptchaService(captchaConfig *config.CaptchaConfig, passwordEncoder *security.PasswordEncoder, jwtService *JwtService) CaptchaService {
	return &captchaService{
		captchaConfig:   captchaConfig,
		passwordEncoder: passwordEncoder,
		randomString:    security.NewRandomString(captchaConfig.Characters, captchaConfig.TextLength),
		jwtService:      jwtService,
	}
}

func (cs *captchaService) Create(ctx context.Context) (*openapi.Captcha, error) {
	randomText, err := cs.randomString.Generate()
	if err != nil {
		return nil, err
	}

	captchaImage, err := cs.generateImage(randomText)
	if err != nil {
		return nil, err
	}

	encodedText, err := cs.passwordEncoder.Encode(randomText)
	if err != nil {
		return nil, err
	}

	jwtToken, err := cs.jwtService.GetAccessJwtToken(ctx)
	if err != nil {
		return nil, err
	}

	captchaToken, err := jwtToken.GenerateToken(jwt.MapClaims{tokenKey: encodedText})
	if err != nil {
		return nil, err
	}

	return &openapi.Captcha{
		CaptchaToken: captchaToken,
		CaptchaImage: captchaImage,
	}, nil
}

func (cs *captchaService) Validate(ctx context.Context, captchaData *openapi.CaptchaData) *openapi.BooleanValue {
	if captchaData == nil || captchaData.CaptchaToken == "" || captchaData.CaptchaText == "" {
		return &openapi.BooleanValue{Value: false}
	}

	jwtToken, err := cs.jwtService.GetAccessJwtToken(ctx)
	if err != nil {
		return &openapi.BooleanValue{Value: false}
	}

	claims, err := jwtToken.ParseToken(ctx, captchaData.CaptchaToken)
	if err != nil {
		return &openapi.BooleanValue{Value: false}
	}

	raw, ok := claims[tokenKey]
	enc, ok2 := raw.(string)
	if !ok || !ok2 || enc == "" {
		return &openapi.BooleanValue{Value: false}
	}

	return &openapi.BooleanValue{Value: cs.passwordEncoder.Compare(captchaData.CaptchaText, enc) == nil}
}

func (cs *captchaService) generateImage(text string) (string, error) {
	width := cs.captchaConfig.Width
	height := cs.captchaConfig.Height

	var rng = rand.New(rand.NewSource(rand.Int63()))

	dc := gg.NewContext(width, height)

	// White background
	dc.SetRGB(1, 1, 1)
	dc.Clear()

	// Draw a border around the image
	dc.SetRGB(0.8, 0.8, 0.8) // light gray
	dc.DrawRectangle(0, 0, float64(width-1), float64(height-1))
	dc.Stroke()

	// Optional noise lines
	for i := 0; i < cs.captchaConfig.NoiseLines; i++ {
		dc.SetRGBA(rng.Float64(), rng.Float64(), rng.Float64(), 0.3)
		x1 := rng.Float64() * float64(width)
		y1 := rng.Float64() * float64(height)
		x2 := rng.Float64() * float64(width)
		y2 := rng.Float64() * float64(height)
		dc.DrawLine(x1, y1, x2, y2)
		dc.Stroke()
	}

	// Load font
	fontSize := float64(cs.captchaConfig.FontSize)
	if fontSize > float64(height)*0.9 {
		fontSize = float64(height) * 0.9
	}
	if err := dc.LoadFontFace(cs.captchaConfig.Font, fontSize); err != nil {
		return "", fmt.Errorf("failed to load font from %s: %w", cs.captchaConfig.Font, err)
	}

	// Draw each character with distortion and color
	perChar := float64(width) / float64(len(text)+1)
	for i, c := range text {
		x := perChar*float64(i+1) + rng.Float64()*5 - 2.5
		y := float64(height)/2 + rng.Float64()*10 - 5
		angle := rng.Float64()*0.4 - 0.2 // rotate -0.2 to +0.2 radians

		dc.Push() // Save current state

		dc.RotateAbout(angle, x, y)
		dc.SetRGB(rng.Float64(), rng.Float64(), rng.Float64()) // random color
		dc.DrawStringAnchored(string(c), x, y, 0.5, 0.5)

		dc.Pop() // Restore state
	}

	// Encode image to PNG
	var buf bytes.Buffer
	if err := png.Encode(&buf, dc.Image()); err != nil {
		return "", fmt.Errorf("failed to encode image: %w", err)
	}

	// Base64 + MIME prefix
	b64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	return "data:image/png;base64," + b64, nil
}
