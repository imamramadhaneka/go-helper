package standard

import (
	"context"

	"github.com/getsentry/sentry-go"
	"go.uber.org/zap"

	"github.com/golangid/candi/logger"
	"github.com/golangid/candi/tracer"
)

// LogParam : logging parameter
type LogParam struct {
	Error                         error
	Message, OperationName, Scope string
	IsSentry                      bool
}

// Log : report log
func Log(ctx context.Context, param LogParam) {
	var level = zap.InfoLevel
	if param.Error != nil {
		level = zap.ErrorLevel
		tracer.SetError(ctx, param.Error)
		if param.IsSentry {
			sentry.WithScope(func(scope *sentry.Scope) {
				scope.SetTag("traceId", tracer.GetTraceID(ctx))
				sentry.CaptureException(param.Error)
			})
		}
	}
	logger.Log(level, param.Message, param.OperationName, param.Scope)
}
