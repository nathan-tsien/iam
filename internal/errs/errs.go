package errs

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

const RequestIDKey = "request_id"

type AppError struct {
	Code       string
	Message    string
	HTTPStatus int
	Details    map[string]any
	Cause      error
}

func (e *AppError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *AppError) Unwrap() error { return e.Cause }

func New(status int, code, message string) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		HTTPStatus: status,
	}
}

func (e *AppError) WithDetails(details map[string]any) *AppError {
	clone := *e
	clone.Details = details
	return &clone
}

func (e *AppError) WithCause(cause error) *AppError {
	clone := *e
	clone.Cause = cause
	return &clone
}

func Render(c *gin.Context, err error) {
	var app *AppError
	if !errors.As(err, &app) {
		app = &AppError{
			Code:       "INTERNAL",
			Message:    "Internal server error",
			HTTPStatus: http.StatusInternalServerError,
			Cause:      err,
		}
	}

	requestID, _ := c.Get(RequestIDKey)
	rid, _ := requestID.(string)

	payload := gin.H{
		"code":       app.Code,
		"message":    app.Message,
		"request_id": rid,
	}
	if app.Details != nil {
		payload["details"] = app.Details
	}

	c.JSON(app.HTTPStatus, payload)
}
