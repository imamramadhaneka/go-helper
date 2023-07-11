package standard

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"

	"github.com/getsentry/sentry-go"
	"github.com/golangid/candi/candihelper"
	"github.com/golangid/candi/candishared"
	"github.com/golangid/candi/tracer"
	"github.com/labstack/echo"
)

// HTTPPanicMiddleware echo middleware
func HTTPPanicMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			defer func() {
				if r := recover(); r != nil {
					err := fmt.Errorf("PANIC: %v", r)
					tracer.SetError(c.Request().Context(), err)
					sentry.WithScope(func(scope *sentry.Scope) {
						scope.SetTag("traceId", tracer.GetTraceID(c.Request().Context()))
						sentry.CaptureException(err)
					})
					NewHTTPResponse(http.StatusInternalServerError, "Something error").JSON(c.Response())
				}
			}()

			return next(c)
		}
	}
}

// CustomHTTPErrorHandler custom echo http error
func CustomHTTPErrorHandler(err error, c echo.Context) {
	var message string
	code := http.StatusBadRequest
	if err != nil {
		message = err.Error()
	}

	switch he := err.(type) {
	case *echo.HTTPError:
		code = he.Code
		if code == http.StatusNotFound {
			message = fmt.Sprintf(`Resource "%s %s" not found`, c.Request().Method, c.Request().URL.Path)
		}

	case candihelper.MultiError:
		NewHTTPResponse(code, "Error", he).JSON(c.Response())
		return

	case *ErrorResponse:
		if he.MultiError != nil {
			NewHTTPResponse(he.Code, he.Message, he.MultiError).JSON(c.Response())
			return
		}
		code = he.Code
		message = he.Message
		if code == http.StatusGatewayTimeout {
			code = http.StatusInternalServerError
			message = "Service unavailable"
		}

	default:
		switch {
		case strings.Contains(strings.ToLower(message), "not found"):
			code = http.StatusBadRequest
		case strings.Contains(message, ErrorUnauthorized):
			code = http.StatusUnauthorized
			message = ErrorUnauthorized
		case strings.Contains(message, ErrorForbidden):
			code = http.StatusForbidden
		case strings.Contains(message, "pq:") || strings.Contains(message, "sql:"):
			code = http.StatusInternalServerError
			message = "Internal server error"
			sentry.CaptureException(err)
		}

	}

	NewHTTPResponse(code, message).JSON(c.Response())
}

// HTTPCustomBasicAuthMiddleware for multiple basic auth with different user & password
func HTTPCustomBasicAuthMiddleware(user, pass string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			basicUser, basicPass, _ := c.Request().BasicAuth()
			if subtle.ConstantTimeCompare([]byte(basicUser), []byte(user)) == 1 &&
				subtle.ConstantTimeCompare([]byte(basicPass), []byte(pass)) == 1 {
				return next(c)
			}

			return NewHTTPResponse(http.StatusUnauthorized, "unauthorized").JSON(c.Response())

		}
	}
}

// HTTPCustomHTTPMultipleAuthFromCheckerMiddleware echo middleware
func HTTPCustomHTTPMultipleAuthFromCheckerMiddleware(multiAuthChecker interface {
	IsBasicAuthAllowed(ctx context.Context, username, password string) bool
	ValidateToken(ctx context.Context, token string) (*candishared.TokenClaim, error)
}) echo.MiddlewareFunc {

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {

			ctx := c.Request().Context()

			// get auth
			authorization := c.Request().Header.Get(candihelper.HeaderAuthorization)
			if authorization == "" {
				return NewHTTPResponse(http.StatusUnauthorized, "unauthorized").JSON(c.Response())
			}

			// get auth type
			authValues := strings.Split(authorization, " ")

			// validate value
			if len(authValues) != 2 {
				return NewHTTPResponse(http.StatusUnauthorized, "Invalid authorization type").JSON(c.Response())
			}

			authType := strings.ToLower(authValues[0])
			if authType == "basic" {
				basicUser, basicPass, ok := c.Request().BasicAuth()
				if !ok {
					return NewHTTPResponse(http.StatusUnauthorized, "unauthorized").JSON(c.Response())
				}
				if ok = multiAuthChecker.IsBasicAuthAllowed(ctx, basicUser, basicPass); !ok {
					return NewHTTPResponse(http.StatusUnauthorized, "unauthorized").JSON(c.Response())
				}
			} else if authType == "bearer" {
				tokenClaim, err := multiAuthChecker.ValidateToken(ctx, authValues[1])
				if err != nil {
					tracer.SetError(ctx, err)
					return err
				}
				tracer.Log(ctx, "token_claim", tokenClaim)
				ctx = candishared.SetToContext(ctx, candishared.ContextKeyTokenClaim, tokenClaim)
			} else {
				return NewHTTPResponse(http.StatusUnauthorized, "Invalid authorization type").JSON(c.Response())
			}

			return next(c)
		}
	}
}
