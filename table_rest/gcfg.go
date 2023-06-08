package table_rest

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"github.com/pschlump/gintools/data"
)

// var gCfg *data.GlobalConfigData
var gCfg *data.BaseConfigType
var aCfg *data.AppConfig
var uCfg *data.UploadConfig

// func SetupConnectToJwtAuth(xctx context.Context, xconn *pgxpool.Pool, gcfg *data.BaseConfigType, acfg *data.AppConfig, qcfg *data.QRConfig, log *os.File, xem email.EmailSender, lgr *zap.Logger, xmd *metrics.MetricsData) {
func SetupCRUD(gcfg *data.BaseConfigType, acfg *data.AppConfig, ucfg *data.UploadConfig) {
	gCfg = gcfg
	aCfg = acfg
	uCfg = ucfg
}
