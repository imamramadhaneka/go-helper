package standard

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/getsentry/sentry-go"
	"github.com/golangid/candi/candihelper"
	"github.com/golangid/candi/tracer"
	"github.com/lib/pq"
)

const (
	ErrorDataNotFound = "Data not found"
	ErrorUnauthorized = "unauthorized"
	ErrorForbidden    = "forbidden"
)

// SentryError error whitelist to sentry
type SentryError struct {
	Message string
}

// NewSentryError init error whitelist to sentry
func NewSentryError(message string) *SentryError {
	return &SentryError{
		Message: message,
	}
}

// Error method implement error
func (s *SentryError) Error() string {
	return s.Message
}

// CaptureError helper
func CaptureError(ctx context.Context, err error) error {

	switch e := err.(type) {
	case candihelper.MultiError:
	case *SentryError:
		sentry.CaptureException(err)
	default:
		if e.Error() != ErrorDataNotFound {
			sentry.CaptureException(err)
		}
	}

	tracer.SetError(ctx, err)
	return err
}

// MultiError model
type MultiError struct {
	errs []string
}

// Append error to multierror
func (m *MultiError) Append(err error) {
	if err != nil {
		m.errs = append(m.errs, err.Error())
	}
}

// IsNil check if err is nil
func (m *MultiError) IsNil() bool {
	return m.errs == nil
}

// Error implement error from multiError
func (m *MultiError) Error() string {
	var str []string
	for i, s := range m.errs {
		str = append(str, fmt.Sprintf("%d. %s", i+1, s))
	}
	return strings.Join(str, "\n ")
}

// ParseError bind
func ParseError(i interface{}) (err error) {
	switch e := i.(type) {
	case *pq.Error:
		mErr := candihelper.NewMultiError()
		mErr.Append(e.Table, errors.New(strings.Trim(strings.Join([]string{e.Message, e.Detail}, ", "), ", ")))
		err = mErr
	case error:
		err = e
	default:
		err = fmt.Errorf("%v", i)
	}
	return
}

type DBError struct {
	Message string
}

func (e *DBError) Error() string {
	return e.Message
}

func NewDBError(message string) *DBError {
	return &DBError{
		Message: message,
	}
}

type ErrorResponse struct {
	Code       int
	Message    string
	MultiError candihelper.MultiError
}

func (e *ErrorResponse) Error() string {
	return e.Message
}
