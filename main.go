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
	go func() {
		log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", internal.AuthServerConfig.Host, internal.AuthServerConfig.Port), mux))
		defer wg.Done()
	}()
	slog.Info("Server started.")
	wg.Wait()
}
