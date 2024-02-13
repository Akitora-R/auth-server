package store

import (
	"auth-server/internal"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/store"
)

var ClientStore oauth2.ClientStore

func init() {
	cs := store.NewClientStore()
	for _, client := range internal.AuthServerConfig.Client {
		err := cs.Set(client.GetID(), &client)
		if err != nil {
			panic(err)
		}
	}
	ClientStore = cs
}
