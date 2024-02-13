package main

import (
	"auth-server/internal"
	"auth-server/internal/oauth2"
	"fmt"
	"log"
	"net/http"
)

func main() {
	srv := oauth2.InitServer()
	oauth2.InitRoute(srv)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", internal.AuthServerConfig.Host, internal.AuthServerConfig.Port), nil))
}
