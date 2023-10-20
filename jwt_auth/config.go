package jwt_auth

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"context"
	"os"
	"sync"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/gintools/data"
	"github.com/pschlump/gintools/email"
	"github.com/pschlump/gintools/metrics"
	"go.uber.org/zap"
)

var xxCfg *data.GlobalConfigData

var gCfg *data.BaseConfigType
var aCfg *data.AppConfig
var qCfg *data.QRConfig

var logFilePtr *os.File = os.Stderr

var XDbOnLock = sync.RWMutex{}
var XDbOn = make(map[string]bool)

// Database Context and Connection
var conn *pgxpool.Pool
var ctx context.Context
var em email.EmailSender

var md *metrics.MetricsData
var logger *zap.Logger

// func NewMetricsData(saveKey string, validKeys []MetricsTypeInfo, saveRateSeconds int, xgCfg *data.BaseConfigType, xdb map[string]bool, xlfp *os.File, xconn *pgxpool.Pool, xctx context.Context) (md *MetricsData) {
// func SetupConnectToJwtAuth(xctx context.Context, xconn *pgxpool.Pool, gcfg *data.GlobalConfigData, log *os.File, xem email.EmailSender, lgr *zap.Logger, xmd *metrics.MetricsData) {

func SetupConnectToJwtAuth(xctx context.Context, xconn *pgxpool.Pool, gcfg *data.BaseConfigType, acfg *data.AppConfig, qcfg *data.QRConfig, log *os.File, xem email.EmailSender, lgr *zap.Logger, xmd *metrics.MetricsData) {
	logFilePtr = log
	gCfg = gcfg
	aCfg = acfg
	qCfg = qcfg
	ctx = xctx
	conn = xconn
	em = xem
	logger = lgr
	md = xmd

	if conn == nil {
		dbgo.Fprintf(os.Stderr, "!!!! %(red)in SetupConnectToDb -- conn is nil\n")
		dbgo.Fprintf(logFilePtr, "!!!!%(red)in SetupConnectToDb -- conn is nil\n")
		os.Exit(1)
	}
	if em == nil {
		dbgo.Fprintf(os.Stderr, "!!!! %(red)in SetupConnectToDb -- em is nil\n")
		dbgo.Fprintf(logFilePtr, "!!!!%(red)in SetupConnectToDb -- em is nil\n")
		os.Exit(1)
	}
	dbgo.Fprintf(os.Stderr, "!!!! %(green)in SetupConnectToDb -- conn is good !!!!!\n")

	validKeys := []metrics.MetricsTypeInfo{
		{
			Key:  "jwt_auth_success_login",
			Desc: "Count of Successful Logins",
		},
		{
			Key:  "jwt_auth_failed_login_attempts",
			Desc: "Count of Failed Logins Attempts",
		},
		{
			Key:  "jwt_auth_success_registrations",
			Desc: "Count of Successful Registrations",
		},
		{
			Key:  "jwt_auth_success_password_recoveries_started",
			Desc: "Count of Successful Password Recoveries Started",
		},
		{
			Key:  "jwt_auth_success_password_recoveries",
			Desc: "Count of Successful Password Recoveries",
		},
		{
			Key:  "jwt_auth_success_otp_used",
			Desc: "Count of Successful One Time Passwords Used",
		},
		{
			Key:  "jwt_auth_success_otp_regeneratedc",
			Desc: "Count of Successful One Time Passwords Regenerated",
		},
		{
			Key:  "jwt_auth_misc_error",
			Desc: "Count of general errors",
		},
		{
			Key:  "jwt_auth_misc_fatal_error",
			Desc: "Count of faltal configuration errors errors",
		},
	}

	md.AddMetricsKeys(validKeys)

}

func ResetLogFile(newFp *os.File) {
	logFilePtr = newFp
}

/* vim: set noai ts=4 sw=4: */
