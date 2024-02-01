package internal

import "github.com/redis/go-redis/v9"

var Rdb *redis.Client

func init() {
	Rdb = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})
}
