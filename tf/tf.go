package tf

import (
	"context"

	"github.com/redis/go-redis/v9"
)

var ctx context.Context
var rdb *redis.Client
var clusterName string = ""

func SetupTf(xctx context.Context, xrdb *redis.Client, ClusterName string) {
	ctx = xctx
	rdb = xrdb
	clusterName = ClusterName
}

func Xtf() error {
	return nil
}
