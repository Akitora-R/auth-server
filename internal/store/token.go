package store

import (
	"auth-server/internal"
	"context"
	"fmt"
	"github.com/go-oauth2/oauth2/v4"
)

type RedisTokenStore struct {
	prefix string
}

func (r *RedisTokenStore) Create(ctx context.Context, info oauth2.TokenInfo) error {
	internal.Rdb.Set(ctx, fmt.Sprintf("%s:", r.prefix), info, info.GetAccessExpiresIn())
	return nil
}

func (r *RedisTokenStore) RemoveByCode(ctx context.Context, code string) error {
	//TODO implement me
	panic("implement me")
}

func (r *RedisTokenStore) RemoveByAccess(ctx context.Context, access string) error {
	//TODO implement me
	panic("implement me")
}

func (r *RedisTokenStore) RemoveByRefresh(ctx context.Context, refresh string) error {
	//TODO implement me
	panic("implement me")
}

func (r *RedisTokenStore) GetByCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	//TODO implement me
	panic("implement me")
}

func (r *RedisTokenStore) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	//TODO implement me
	panic("implement me")
}

func (r *RedisTokenStore) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	//TODO implement me
	panic("implement me")
}
