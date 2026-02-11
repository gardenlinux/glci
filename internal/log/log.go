package log

import (
	"context"
	"io"

	"github.com/go-logr/logr"
	"github.com/go-logr/zerologr"
	"github.com/rs/zerolog"
)

// Setup attaches a new logger to an existing context. The new logger logs to the given writer.
func Setup(ctx context.Context, debug, silent bool, writer io.Writer) context.Context {
	var zeroLog zerolog.Logger

	if silent {
		return logr.NewContext(ctx, logr.Discard())
	}

	level := zerolog.InfoLevel
	if debug {
		level = zerolog.DebugLevel
	}
	cw := zerolog.ConsoleWriter{
		Out:           writer,
		TimeFormat:    "2006-01-02 15:04:05 MST",
		FieldsExclude: []string{"v"},
	}
	zeroLog = zerolog.New(cw).Level(level).With().Timestamp().Logger()

	return logr.NewContext(ctx, zerologr.New(&zeroLog))
}

// WithValues appends arbitrary key-value pairs to an existing logger and returns a new context.
func WithValues(ctx context.Context, keysAndValues ...any) context.Context {
	return logr.NewContext(ctx, logr.FromContextOrDiscard(ctx).WithValues(keysAndValues...))
}

// Info logs an information message.
func Info(ctx context.Context, msg string, keysAndValues ...any) {
	logr.FromContextOrDiscard(ctx).Info(msg, keysAndValues...)
}

// Debug logs a debug message that shouldn'e be necessary under normal circumstances.
func Debug(ctx context.Context, msg string, keysAndValues ...any) {
	logr.FromContextOrDiscard(ctx).V(1).Info(msg, keysAndValues...)
}

// Error logs an error.
func Error(ctx context.Context, err error, keysAndValues ...any) {
	logr.FromContextOrDiscard(ctx).Error(err, "", keysAndValues...)
}

// ErrorMsg logs a message with the severity of an error.
func ErrorMsg(ctx context.Context, msg string, keysAndValues ...any) {
	logr.FromContextOrDiscard(ctx).Error(nil, msg, keysAndValues...)
}
