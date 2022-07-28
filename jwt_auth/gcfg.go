package jwt_auth

import (
	"context"
	"os"
	"sync"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/gintools/data"
	"github.com/pschlump/gintools/email"
)

var gCfg *data.GlobalConfigData

var logFilePtr *os.File = os.Stderr

var XDbOnLock = sync.RWMutex{}
var XDbOn = make(map[string]bool)

// Database Context and Connection
var conn *pgxpool.Pool
var ctx context.Context
var em email.EmailSender

// func NewEmailSender(gcfg *data.BaseConfigType, db map[string]bool, f *os.File, conn *pgxpool.Pool, ctx context.Context) (rv EmailSender) {

func SetupConnectToJwtAuth(xctx context.Context, xconn *pgxpool.Pool, gcfg *data.GlobalConfigData, log *os.File, xem email.EmailSender) {
	logFilePtr = log
	gCfg = gcfg
	ctx = xctx
	conn = xconn
	em = xem
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
}

// ParseBool convers a string to bool based on the table of trueValues.
func ParseBool(s string) (b bool) {
	switch s {
	case "t", "T", "yes", "Yes", "YES", "1", "true", "True", "TRUE", "on", "On", "ON", "f", "F", "no",
		"No", "NO", "0", "false", "False", "FALSE", "off", "Off", "OFF":
		return true
	}
	return false
}

func IsXDBOn(name string) (b bool) {
	XDbOnLock.RLock()
	b = XDbOn[name]
	XDbOnLock.RUnlock()
	return
}
