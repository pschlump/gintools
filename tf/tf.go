package tf

import (
	"context"

	"github.com/redis/go-redis/v9"
)

var ctx context.Context
var rdb *redis.Client
var serverName string = ""

func SetupTf(xctx context.Context, xrdb *redis.Client, xServerName string) {
	ctx = xctx
	rdb = xrdb
	serverName = xServerName
}

func Xtf() error {
	return nil
}
