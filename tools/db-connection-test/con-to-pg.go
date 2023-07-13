package main

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

//
// Test connection test to PoggreSQL
//
// This is the first thing that should be run.
//
// Example:
//	$ ./con-test-db -C 'user=postgres password=f1ref0x2 dbname=test port=5432 host=127.0.0.1'
//
// TODO:
// 1. -g global-config.json file - read that for connection string/database-type etc.
// 2. -n Database - to set a specific database for non-PG
// 3. -d postgres|Oracle|T-SQL|ocbc etc. -- database type
//
// 4. Improve error reporting on ConnectToAnyDb and Run1
//

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/jackc/pgx/v4/pgxpool"
	_ "github.com/lib/pq"
	"github.com/pschlump/MiscLib"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/scany/pgxscan"
)

var conn *pgxpool.Pool
var ctx context.Context

var PGConn = flag.String("conn", "", "PotgresSQL connection info") // 0
func init() {
	flag.StringVar(PGConn, "C", "", "PotgresSQL connection info") // 0
}

func main() {

	var err error

	flag.Parse()

	ConnectToDb(*PGConn)
	if conn == nil {
		fmt.Fprintf(os.Stderr, "%sUnable to connection to database: %v%s\n", MiscLib.ColorRed, err, MiscLib.ColorReset)
		os.Exit(1)
	}

	// -------------------------- Try Simple Connection ---------------------------------------------------------------------
	type IntType struct {
		X *int
	}
	var v2 []*IntType
	stmt := "select 1 as \"x\""
	err = pgxscan.Select(ctx, conn, &v2, stmt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sUnable to connection to database/failed on table select: %v%s\n", MiscLib.ColorRed, err, MiscLib.ColorReset)
		os.Exit(1)
	}
	if len(v2) == 0 {
		fmt.Fprintf(os.Stderr, "%sUnable to connection to database/failed on table select: %v%s\n", MiscLib.ColorRed, err, MiscLib.ColorReset)
		os.Exit(1)
	}

	// -------------------------- Determin Database connect to --------------------------------------------------------------
	type StrType struct {
		X *string
	}
	var v3 []*StrType
	stmt = "select current_database() as \"x\""
	err = pgxscan.Select(ctx, conn, &v3, stmt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sUnable to connection to database/failed on table select: %v%s\n", MiscLib.ColorRed, err, MiscLib.ColorReset)
		os.Exit(1)
	}
	if len(v3) == 0 {
		fmt.Fprintf(os.Stderr, "%sUnable to connection to database/failed on table select: %v%s\n", MiscLib.ColorRed, err, MiscLib.ColorReset)
		os.Exit(1)
	}

	if db1 {
		fmt.Printf("Connected to ->%s<- database\n", dbgo.SVarI(v3[0]))
	}
	fmt.Printf("Connected to ->%s<- database\n", *v3[0].X)

	fmt.Printf("%sPASS Success!!! Connected to database%s\n", MiscLib.ColorGreen, MiscLib.ColorReset)
	os.Exit(0)

}

// ConnectToDb creates a global that is used to connect to the PG database.
// You have to have "DATABASE_URL" setup as an environment variable first. (See setupx.sh)

func ConnectToDb(s string) {
	ctx = context.Background()
	constr := os.Getenv("DATABASE_URL")
	if s != "" {
		constr = s
	}
	var err error
	// func Connect(ctx context.Context, connString string) (*Pool, error)
	fmt.Printf("Using: ->%s<-\n", constr)
	if constr == "" {
		fmt.Printf("\tNote: An empty connection string is the same as ->postgres://localhost<- for a connection string and may work\n")
	}
	conn, err = pgxpool.Connect(ctx, constr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v connetion string [%s]\n", err, constr)
		os.Exit(1)
	}
}

var db1 = false
