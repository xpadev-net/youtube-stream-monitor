package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// ErrorCode represents an API error code.
type ErrorCode string

const (
	// Client errors
	ErrCodeBadRequest        ErrorCode = "BAD_REQUEST"
	ErrCodeUnauthorized      ErrorCode = "UNAUTHORIZED"
	ErrCodeForbidden         ErrorCode = "FORBIDDEN"
	ErrCodeNotFound          ErrorCode = "NOT_FOUND"
	ErrCodeDuplicateMonitor  ErrorCode = "DUPLICATE_MONITOR"
	ErrCodeMaxMonitors       ErrorCode = "MAX_MONITORS_EXCEEDED"
	ErrCodeValidation        ErrorCode = "VALIDATION_ERROR"
	ErrCodeInvalidURL        ErrorCode = "INVALID_URL"
	ErrCodeInvalidConfig     ErrorCode = "INVALID_CONFIG"
	ErrCodeRateLimitExceeded  ErrorCode = "RATE_LIMIT_EXCEEDED"
	ErrCodeMonitorNotActive  ErrorCode = "MONITOR_NOT_ACTIVE"

	// Server errors
	ErrCodeInternal   ErrorCode = "INTERNAL_ERROR"
	ErrCodeDatabase   ErrorCode = "DATABASE_ERROR"
	ErrCodeKubernetes ErrorCode = "KUBERNETES_ERROR"
)

// ErrorResponse represents the standard error response format.
type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail contains the error details.
type ErrorDetail struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

// NewErrorResponse creates a new error response.
func NewErrorResponse(code ErrorCode, message string) ErrorResponse {
	return ErrorResponse{
		Error: ErrorDetail{
			Code:    code,
			Message: message,
		},
	}
}

// RespondError sends an error response with the given status code.
func RespondError(c *gin.Context, statusCode int, code ErrorCode, message string) {
	c.JSON(statusCode, NewErrorResponse(code, message))
}

// RespondBadRequest sends a 400 Bad Request response.
func RespondBadRequest(c *gin.Context, message string) {
	RespondError(c, http.StatusBadRequest, ErrCodeBadRequest, message)
}

// RespondUnauthorized sends a 401 Unauthorized response.
func RespondUnauthorized(c *gin.Context, message string) {
	RespondError(c, http.StatusUnauthorized, ErrCodeUnauthorized, message)
}

// RespondForbidden sends a 403 Forbidden response.
func RespondForbidden(c *gin.Context, message string) {
	RespondError(c, http.StatusForbidden, ErrCodeForbidden, message)
}

// RespondNotFound sends a 404 Not Found response.
func RespondNotFound(c *gin.Context, message string) {
	RespondError(c, http.StatusNotFound, ErrCodeNotFound, message)
}

// RespondConflict sends a 409 Conflict response.
func RespondConflict(c *gin.Context, code ErrorCode, message string) {
	RespondError(c, http.StatusConflict, code, message)
}

// RespondInternalError sends a 500 Internal Server Error response.
func RespondInternalError(c *gin.Context, message string) {
	RespondError(c, http.StatusInternalServerError, ErrCodeInternal, message)
}

// RespondValidationError sends a 400 response for validation errors.
func RespondValidationError(c *gin.Context, message string) {
	RespondError(c, http.StatusBadRequest, ErrCodeValidation, message)
}
