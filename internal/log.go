package internal

import (
	"log/slog"
	"os"
	"strings"
)

func init() {
	level := strings.ToUpper(os.Getenv("LOG_LEVEL"))
	var l slog.Level
	switch level {
	case "DEBUG":
		l = slog.LevelDebug
	case "WARN":
		l = slog.LevelWarn
	case "ERROR":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: l,
	})
	slog.SetDefault(slog.New(handler))

	if level != "" {
		slog.Info("log level configured", "level", level)
	}
}
