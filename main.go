package main

import (
	"auth-server/internal"
	oauth2Http "auth-server/internal/http"
	"auth-server/internal/oauth2"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"sync"
)

func main() {
	srv := oauth2.InitServer()
	mux := oauth2Http.CreateMux(srv)
	wg := sync.WaitGroup{}
	wg.Add(1)
	addr := fmt.Sprintf("%s:%d", internal.AuthServerConfig.Host, internal.AuthServerConfig.Port)
	go func() {
		log.Fatal(http.ListenAndServe(addr, mux))
	}()
	slog.Info("Server started.", "addr", addr)
	wg.Wait()
}
