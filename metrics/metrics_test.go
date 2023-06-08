package metrics_test

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

// Copyright (c) Philip Schlump, 2023.
// This file is MIT licensed, see ../LICENSE.mit

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pschlump/gintools/data"
	"github.com/pschlump/gintools/metrics"
)

var gCfg data.BaseConfigType
var DbFlag map[string]bool = make(map[string]bool)
var logFilePtr *os.File = os.Stderr

var conn *pgxpool.Pool
var ctx context.Context

func TestNewMetrics(t *testing.T) {
	// func NewMetricsData(saveKey string, validKeys []MetricsTypeInfo, saveRateSeconds int, xgCfg *data.BaseConfigType, xdb map[string]bool, xlfp *os.File, xconn *pgxpool.Pool, xctx context.Context) (md *MetricsData) {
	m := metrics.NewMetricsData("test-key", []metrics.MetricsTypeInfo{{Key: "test_count", Desc: "A Conter for Teting with"}}, 10, &gCfg, DbFlag, logFilePtr, conn, ctx)
	m.AddCounter("test_count", 12)
	k1 := m.GetCounter("test_count")
	if int(k1) != 12 {
		t.Error("Did not save value")
	}
}
