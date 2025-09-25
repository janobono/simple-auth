package impl

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/janobono/go-util/common"
	"github.com/janobono/simple-auth/simple-auth-service/generated/openapi"
	"github.com/janobono/simple-auth/simple-auth-service/internal/service"
)

type captchaController struct {
	captchaService service.CaptchaService
}

func NewCaptchaController(captchaService service.CaptchaService) openapi.CaptchaControllerAPI {
	return &captchaController{captchaService}
}

func (c *captchaController) GetCaptcha(ctx *gin.Context) {
	result, err := c.captchaService.Create(ctx.Request.Context())
	if err != nil {
		slog.Error("Failed to generate CAPTCHA", "error", err)
		RespondWithError(ctx, http.StatusInternalServerError, openapi.UNKNOWN, "Failed to generate CAPTCHA")
		return
	}

	ctx.JSON(http.StatusOK, result)
}

func (c *captchaController) ValidateCaptcha(ctx *gin.Context) {
	var data openapi.CaptchaData
	if err := ctx.ShouldBindJSON(&data); err != nil {
		RespondWithError(ctx, http.StatusBadRequest, openapi.INVALID_BODY, "Invalid request body")
		return
	}
	if common.IsBlank(data.CaptchaText) {
		RespondWithError(ctx, http.StatusBadRequest, openapi.INVALID_FIELD, "'captchaText' must not be blank")
		return
	}
	if common.IsBlank(data.CaptchaToken) {
		RespondWithError(ctx, http.StatusBadRequest, openapi.INVALID_FIELD, "'captchaToken' must not be blank")
		return
	}

	ctx.JSON(http.StatusOK, c.captchaService.Validate(ctx.Request.Context(), &data))
}
