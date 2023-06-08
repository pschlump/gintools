package table_rest

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/pschlump/dbgo"
)

func SetJsonHdr(c *gin.Context) {
	if IsTLS(c) {
		c.Writer.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}
	c.Writer.Header().Set("Content-Type", "application/json; charset=utf-8")
}

func SetJsonPHdr(c *gin.Context) {
	if IsTLS(c) {
		c.Writer.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}
	c.Writer.Header().Set("Content-Type", "application/javascript; charset=utf-8")
}

// xyzzy1000000 TODO - Cors Fix

func getOrigin(c *gin.Context) string {
	origin, ok := c.Request.Header["Origin"]
	if !ok {
		return ""
	}
	if len(origin) >= 1 {
		return origin[0]
	}
	return ""
}

func SetJSONHeaders(c *gin.Context) {
	dbgo.DbFprintf("HandleCRUD.Headers", logFilePtr, "SetJSONHeaders Called From: %s\n", dbgo.LF(-2))
	// Reall shoudl pull "Origin" header, lookup in d.b. and if OK then allow this
	// should check flag to see if this is an feture that is turned on.
	// Must be per-origin.
	// xyzzy1000000 TODO
	if IsTLS(c) {
		c.Writer.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}
	c.Writer.Header().Set("Content-Type", "application/json; charset=utf-8")

	origin := getOrigin(c)
	useCors, err := IsValidOrigin(c, origin)
	if err != nil {
		return
	}
	if useCors {
		dbgo.DbPf(true, "Origing ->%s<- AT:%(LF)\n", origin)
		if origin != "" {
			dbgo.DbPf(true, "Settin Access-Control-Allow-Oring header  ->%s<-\n", origin)
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
		}
	}

	//c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	//c.Writer.Header().Add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH")
	//c.Writer.Header().Add("Access-Control-Allow-Headers", "Origin, Accept, Content-Type, X-Requested-With, X-CSRF-Token, X-Auth")
}

func SetCORSHeaders(c *gin.Context) {
	dbgo.DbFprintf("HandleCRUD.Headers", logFilePtr, "SetCORSHeaders Called From: %s\n", dbgo.LF(-2))

	if IsTLS(c) {
		c.Writer.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}

	dbgo.DbPf(true, "Origing ->%s<-\n", c.Request.Header["Origin"])
	origin := getOrigin(c)
	useCors, err := IsValidOrigin(c, origin)
	if err != nil {
		return
	}
	if useCors {
		dbgo.DbPf(true, "Origing ->%s<- AT:%(LF)\n", origin)
		if origin != "" {
			dbgo.DbPf(true, "Settin Access-Control-Allow-Oring header  ->%s<-\n", origin)
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
		}
	}

	//c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	//c.Writer.Header().Add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH")
	//c.Writer.Header().Add("Access-Control-Allow-Headers", "Origin, Accept, Content-Type, X-Requested-With, X-CSRF-Token, X-Auth")
}

func IsValidOrigin(c *gin.Context, origin string) (ok bool, err error) {

	if !gCfg.CORS_Allowed {
		dbgo.DbPf(true, "CORS is not enabled: %(LF)\n")
		return false, nil
	}

	if !gCfg.CORS_CheckTable {
		dbgo.DbPf(true, "CORS is for all sites: %(LF)\n")
		return true, nil
	}

	found := false
	if origin == "" {
		dbgo.DbPf(true, "No CORS database check -- no ORIGIN header: %(LF)\n")
		return
	}

	dbgo.DbPf(true, "CORS database check started: %(LF)\n")
	/*
		//		CREATE TABLE t_valid_cors_origin (
		//			  "id"		uuid DEFAULT uuid_generate_v4() not null primary key
		//			, "valid" 	text not null
		//			, "updated" 			timestamp
		//			, "created" 			timestamp default current_timestamp not null
		//		);
	*/
	stmt := "select 'found' as \"x\" from t_valid_cors_origin where $1 ~ valid"

	rows, err := SQLQueryW(c, stmt, origin)
	defer func() {
		if rows != nil && err == nil {
			rows.Close()
		}
	}()

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error determining CORS status  ->%s<- error %s at %s\n", stmt, err, dbgo.LF())
		fmt.Fprintf(logFilePtr, "Error determining CORS status  ->%s<- error %s at %s\n", stmt, err, dbgo.LF())
		c.Writer.WriteHeader(http.StatusNotAcceptable) // 406
		fmt.Fprintf(c.Writer, "Error determining CORS status ->%s<- error %s at %s\n", stmt, err, dbgo.LF())
		return false, fmt.Errorf("SQL Error")
	}

	// OLD: data, _, _ := sizlib.RowsToInterface(rows)
	data, _, _ := RowsToInterface(rows)
	if len(data) > 0 {
		for _, sq := range data {
			if _, ok := sq["x"]; ok {
				dbgo.Printf("%(green)CORS found - enabled\n")
				found = true
			}
			break
		}
	}
	if !found {
		dbgo.Printf("%(red)CORS *not* found - disabled\n")
	}
	dbgo.DbPf(true, "CORS database check returns %v: %(LF)\n", found)
	return found, nil
}
