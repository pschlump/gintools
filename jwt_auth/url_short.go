package jwt_auth

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/gintools/log_enc"
	"github.com/pschlump/json"
)

// -------------------------------------------------------------------------------------------------------------------------
type ApiUrlShortCreateType struct {
	Id             string   `json:"id"               form:"id"              binding:"required"`
	DestinationURL string   `json:"destination_url"  form:"destination_url" binding:"required"`
	ShouldProxy    string   `json:"should_proxy"     form:"should_proxy"    binding:"required"`
	Headers        []NvPair `json:"headers"`
	Params         []NvPair `json:"params"`
	Method         string   `json:"method"`
}

type NvPair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type RvUrlShortCreateReturned struct {
	StdErrorReturn
	ShortId string `json:"short_id"`
}

func UrlShortCreateHandler(c *gin.Context) {
	var err error
	var pp ApiUrlShortCreateType
	if err = BindFormOrJSON(c, &pp); err != nil {
		return
	}

	// create or replace function q_qr_url_short_create ( p_destination_url varchar, p_should_proxy varchar, p_headers varchar, p_params varchar, p_method varchar, p_hmac_password varchar, p_userdata_password varchar )
	stmt := "q_qr_url_short_create ( $1, $2, $3, $4, $5, $6, $7 )"
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF): %s\n", stmt)
	rv, err := CallDatabaseJSONFunction(c, stmt, ".!!", pp.DestinationURL, pp.ShouldProxy, dbgo.SVar(pp.Headers), dbgo.SVar(pp.Params), pp.Method, aCfg.EncryptionPassword, aCfg.UserdataPassword)
	if err != nil {
		return
	}
	dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)

	var rvStatus RvUrlShortCreateReturned
	err = json.Unmarshal([]byte(rv), &rvStatus)
	if rvStatus.Status != "success" {
		rvStatus.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
		c.JSON(http.StatusUnauthorized, LogJsonReturned(rvStatus.StdErrorReturn)) // 401
		return
	}

	// xyzzy - TODO

}

// -------------------------------------------------------------------------------------------------------------------------
type ApiUrlShortType struct {
	Id string `json:"id" form:"id" binding:"required"`
}

type RvUrlShortReturned struct {
	StdErrorReturn
	ShortId        string `json:"short_id"`
	ShouldProxy    string `json:"should_proxy"`
	DestinationURL string `json:"destination_url"`
}

func UrlShortHandler(c *gin.Context) {
	var err error
	var pp ApiUrlShortType
	if err = BindFormOrJSON(c, &pp); err != nil {
		return
	}

	// ----------------------------------------------------------------------------------------------------
	// Validate, Lookup, Count

	// stmt := "q_qr_url_short_redirect ( $1, $2, $3 )"
	// create or replace function q_qr_url_short_redirect ( p_email varchar, p_hmac_password varchar, p_userdata_password varchar )
	stmt := "q_qr_url_short_redirect ( $1, $2, $3 )"
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF): %s\n", stmt)
	rv, err := CallDatabaseJSONFunction(c, stmt, ".!!", pp.Id, aCfg.EncryptionPassword, aCfg.UserdataPassword)
	if err != nil {
		return
	}
	dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)

	var rvStatus RvUrlShortReturned
	err = json.Unmarshal([]byte(rv), &rvStatus)
	if rvStatus.Status != "success" {
		rvStatus.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
		c.JSON(http.StatusUnauthorized, LogJsonReturned(rvStatus.StdErrorReturn)) // 401
		return
	}

	// ----------------------------------------------------------------------------------------------------
	// Redirect/Proxy

	if rvStatus.ShouldProxy == "proxy" {
		// Use A proxy to detination URL
		// xyzzy - TODO
	} else {
		// Use "Location" to redirect
		// xyzzy - TODO
	}

}

// xyzzy - TODO -- Report on usage by values.... handle.go

/* vim: set noai ts=4 sw=4: */
