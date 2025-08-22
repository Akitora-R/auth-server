package main

import (
	"auth-server/internal"
	oauth2Http "auth-server/internal/http"
	"auth-server/internal/oauth2"
	"fmt"
	"log/slog"
)

func main() {
	srv := oauth2.InitServer()
	engine := oauth2Http.CreateGinEngine(srv)
	addr := fmt.Sprintf("%s:%d", internal.AuthServerConfig.Host, internal.AuthServerConfig.Port)
	slog.Info("Server started.", "addr", addr)
	// gin Engine.Run 内部处理优雅关闭信号
	if err := engine.Run(addr); err != nil {
		slog.Error("server exit", "err", err)
	}
}
