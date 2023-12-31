package callme

import (
	"context"

	"github.com/jackc/pgx/v4/pgxpool"
)

var conn *pgxpool.Pool
var ctx context.Context

func SetupConnectToCallMe(xctx context.Context, xconn *pgxpool.Pool) {
	// logFilePtr = log
	ctx = xctx
	conn = xconn
}
