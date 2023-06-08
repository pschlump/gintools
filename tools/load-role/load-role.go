package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pschlump/ReadConfig"
	jsonSyntaxErroLib "github.com/pschlump/check-json-syntax/lib"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/gintools/data"
	"github.com/pschlump/gintools/email"
	"github.com/pschlump/gintools/jwt_auth"
)

// read  --input <FN> -> json data
// connect to d.b.
// upsert data

// func SetupConnectToJwtAuth(xctx context.Context, xconn *pgxpool.Pool, gcfg *data.GlobalConfigData, log *os.File, xem email.EmailSender, lgr *zap.Logger, xmd *metrics.MetricsData) {

var inputData map[string]map[string]bool = make(map[string]map[string]bool)

var DbFlagParam = flag.String("db_flag", "", "Additional Debug Flags")
var Input = flag.String("i", "", "Input JSON File")
var Cfg = flag.String("cfg", "cfg.json", "config file for this call")

// Database Context and Connection
var conn *pgxpool.Pool
var ctx context.Context

var DbOn map[string]bool = make(map[string]bool)
var gCfg data.GlobalConfigData
var Debug bool

func main() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "load-data : Usage: %s -i file\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse() // Parse CLI arguments to this, --cfg <name>.json

	fns := flag.Args()
	if len(fns) != 0 {
		fmt.Printf("Extra arguments are not supported [%s]\n", fns)
		os.Exit(1)
	}

	if Cfg == nil {
		fmt.Printf("--cfg is a required parameter\n")
		os.Exit(1)
	}

	// ------------------------------------------------------------------------------
	// Read in Configuration
	// ------------------------------------------------------------------------------
	err := ReadConfig.ReadFile(*Cfg, &gCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read confguration: %s error %s\n", *Cfg, err)
		os.Exit(1)
	}

	fmt.Printf("%s\n", dbgo.SVarI(gCfg))

	jsonSyntaxErroLib.Debug = &Debug

	buf, err := ioutil.ReadFile(*Input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open %s error : %s\n", *Input, err)
		os.Exit(1)
	}
	if len(buf) == 0 {
		fmt.Fprintf(os.Stderr, "Empty File %s\n", *Input)
		os.Exit(1)
	}

	err = json.Unmarshal(buf, &inputData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "JSON parse error on %s error : %s\n", *Input, err)
		printSyntaxError(string(buf), err)
		os.Exit(1)
	}

	// --------------------------------------------------------------------------------------
	// connect to ...
	// Connect to database - if we get to the defer then we have successfuly connected.
	// --------------------------------------------------------------------------------------
	ConnectToDb()
	defer DisConnectToDb()

	dbgo.Printf("%(green)Data=%s, connected to d.b.\n", dbgo.SVarI(inputData))

	em := email.NewEmailSender(&(gCfg.BaseConfigType), DbOn, os.Stderr, conn, ctx, nil, nil)
	if em == nil {
		fmt.Printf("Failed to get an email sender\n")
		os.Exit(1)
	}
	// jwt_auth.SetupConnectToJwtAuth(ctx, conn, &gCfg, os.Stderr, em, nil, nil)
	jwt_auth.SetupConnectToJwtAuth(ctx, conn, &(gCfg.BaseConfigType), &(gCfg.AppConfig), &(gCfg.QRConfig), os.Stderr, em, nil, nil)

	// --------------------------------------------------------------------------------------
	// Validate that we have the correct encryption passwords setup.
	// --------------------------------------------------------------------------------------
	if err := jwt_auth.ValidatePasswords(); err != nil {
		dbgo.Fprintf(os.Stderr, "%(red)Not Setup Correctly - invalid passwords - early exit\n")
		os.Exit(1)
	}

	dbgo.Printf("%(green)Encyption passwords validated.\n")

	for k1, v1 := range inputData {
		dbgo.Printf("%(yellow)k1=%s v1=%s\n", k1, dbgo.SVar(v1))
		dbgo.Printf("insert into xx ( n, v ) values ( '%s', '%s'::jsonb );\n", k1, dbgo.SVar(v1))

		/*
			   CREATE TABLE if not exists q_qr_role2 (
				  role_id 		uuid default uuid_generate_v4() not null primary key
				, role_name 	text not null
				, with_grant	varchar(1) default 'n' not null
				, allowed		jsonb not null
			   );

			// 1. add unique index & constraint on role_name
			// 2. add On Conflict update

		*/
		stmt := `insert into q_qr_role2 ( role_name, allowed )
			values ( $1, $2::jsonb )
			On CONFLICT(role_name) Do update set allowed = $2::jsonb
		`
		res, err := conn.Exec(ctx, stmt, k1, dbgo.SVar(v1))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s stmt %s\n", err, stmt)
		}
		_ = res
	}
}

func printSyntaxError(js string, err error) {
	es := jsonSyntaxErroLib.GenerateSyntaxError(js, err)
	fmt.Printf("%s", es)
}

/* vim: set noai ts=4 sw=4: */
