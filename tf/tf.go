package tf

import (
	"context"

	"github.com/redis/go-redis/v9"
)

var ctx context.Context
var rdb *redis.Client

func SetupTf(xctx context.Context, xrdb *redis.Client) {
	ctx = xctx
	rdb = xrdb
}

func Xtf() error {
	return nil
}
