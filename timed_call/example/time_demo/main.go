package main

import (
	"os"

	"github.com/pschlump/gintools/data"
	"github.com/pschlump/gintools/timed_call"
)

var DbOn = make(map[string]bool)

func main() {
	var gcfg *data.BaseConfigType
	// func NewTimedCall(gcfg *data.BaseConfigType, monitor_prefix string, st int, db map[string]bool, f *os.File, conn *pgxpool.Pool, ctx context.Context, lgr *zap.Logger, xmd *metrics.MetricsData) *TimedCallType {
	x := timed_call.NewTimedCall(gcfg, "demo", 30, DbOn, os.Stderr, nil, nil, nil, nil)
	_ = x
}
