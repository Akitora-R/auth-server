package internal

import (
	"fmt"
	"github.com/redis/go-redis/v9"
)

var Rdb *redis.Client

func init() {
	Rdb = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", AuthServerConfig.Redis.Host, AuthServerConfig.Redis.Port),
		Password: "",
		DB:       0,
	})
}
