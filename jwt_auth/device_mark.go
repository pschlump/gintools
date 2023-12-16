package jwt_auth

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/pschlump/HashStrings"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/json"
)

const base64GifPixel = "R0lGODlhAQABAIAAAP///wAAACwAAAAAAQABAAACAkQBADs="

//  	/api/clr.gif?_cache_burst_=444randomnumber
/*

create table if not exists q_qr_manifest_version (
	  id			uuid DEFAULT uuid_generate_v4() not null primary key,
	, hash_seen		text
	, user_id		uuid				-- a user specified ID to join to q_qr_users
	, updated 		timestamp
	, created 		timestamp default current_timestamp not null
);
*/

/*
func loginTrackingGifHandler(c *gin.Context) {

	output, _ := base64.StdEncoding.DecodeString(base64GifPixel)
	// output_len = len(output)
	var newId string

	inm := c.Request.Header.Get("If-None-Match")
	dbgo.Printf("%(Yellow)Header Tags: %(Green)If-None-Match ->%s<- at:%(LF)\n", inm)
	if inm != "" {
		dbgo.Printf("At:%(LF)\n")
		// RFC 7232 section 4.1:
		// a sender SHOULD NOT generate representation metadata other than the
		// above listed fields unless said metadata exists for the purpose of
		// guiding cache updates (e.g., Last-Modified might be useful if the
		// response does not have an ETag field).

		if inm != "" {
			dbgo.Printf("At:%(LF) ---------- if none match ------------\n")
			dbgo.Fprintf(os.Stderr, "ETag(If-None-Match): %s previous\n", inm)
			newId = GenUUID()
			stmt := "q_auth_v1_etag_seen ( $1, $2, $3, $4 )"
			rv, e0 := CallDatabaseJSONFunction(c, stmt, "..!!", newId, inm, aCfg.EncryptionPassword, aCfg.UserdataPassword)
			if e0 != nil {
				dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF), err:%s\n", e0)
				goto gen
			}

			// File: /Users/philip/go/src/github.com/pschlump/qr_svr2/gin-upload/jwt_auth/clear_gif.go LineNo:58:
			// rv={"status":"success", "user_id":"", "id":"8343616b-d8be-48d4-787c-f69ce98c7aa0"}
			dbgo.Fprintf(os.Stderr, "%(cyan)%(LF): rv=%s\n", rv)
			type rvEtagData struct {
				Status string `json:"status"`
				UserId int    `json:"user_id"`
				RowId  string `json:"id"`
				Msg    string `json:"msg"`
			}
			var rvData rvEtagData
			err := json.Unmarshal([]byte(rv), &rvData)
			if err != nil {
				dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF), err:%s\n", err)
				goto gen
			}
			dbgo.Fprintf(os.Stderr, "%(cyan)%(LF): parsed data=%s\n", dbgo.SVarI(rvData))
			if rvData.Msg == "created" {
				dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF) %(red) -- If-None-Match Value Not Found! -- sending back a 200\n")
				goto gen
			}

			h := c.Writer.Header()
			delete(h, "Content-Type")
			delete(h, "Content-Length")
			delete(h, "Last-Modified")
			delete(h, "ETag")
			h.Set("ETag", inm)
			h.Set("Cache-Control", "max-age=31536000") // 1 year
			c.Writer.WriteHeader(http.StatusNotModified)
			dbgo.Printf("At:%(LF)\n")
			return

		}

	}

gen:
	newId = GenUUID()
	output = append(output, []byte(newId)...) // tack ID on the end.
	hash_output := append(output, []byte(aCfg.EtagPassword)...)
	etag := fmt.Sprintf("%x", HashStrings.HashBytes(hash_output))[0:20] // Hash the file
	dbgo.Printf("%(cyan)Generate Etag at:%(LF) ->%s<-\n", etag)         // Dump so we can see what we are inserting
	if db100 {
		stmt := "q_auth_v1_etag_seen ( $1, $2, $3, $4 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, "..!!", newId, etag, aCfg.EncryptionPassword, aCfg.UserdataPassword)
		if e0 != nil {
			dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF), err:%s\n", e0)
		}
		dbgo.Fprintf(logFilePtr, "%(LF): rv=%s\n", rv)
	}
	h := c.Writer.Header()
	h.Set("Content-Type", "image/gif")
	h.Set("ETag", etag)
	h.Set("Cache-Control", "max-age=31536000") // 1 year
	io.WriteString(c.Writer, string(output))
}
*/
// 2. Just keep the http[s]://Name/ section
func UrlGetServer(s string) (rv string, err error) {

	// s := "http://192.168.1.2:8080/login"

	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("Unable to parse %s error:%s\n", s, err)
	}

	dbgo.Printf("%(yellow)Scheme=%s ", u.Scheme)
	dbgo.Printf("%(green)Host=%s ", u.Host)
	dbgo.Printf("%(cyan)Input ->%s<- What we want ->%s//%s/<-\n", s, u.Scheme, u.Host)

	rv = fmt.Sprintf("%s://%s/", u.Scheme, u.Host)
	return
}

// {Method: "GET", Path: "/api/v1/setup.js", Fx: authHandlerGetXsrfIdFile, UseLogin: PublicApiCall},                                        //
func authHandlerGetXsrfIdFile(c *gin.Context) {
	newId := GenUUID()
	ref := ""
	if len(c.Request.Header) > 0 {
		ref = c.Request.Header.Get("Referer")
		if ref == "" {
			xfhost := c.Request.Header.Get("X-Forwarded-Host")
			xfproto := c.Request.Header.Get("X-Forwarded-Proto")
			ref = fmt.Sprintf("%s://%s/", xfproto, xfhost)
			dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF), ref:%s\n", ref)
		}
	} else {
		dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF), no header at all\n")
		fmt.Fprintf(c.Writer, "window.xsrf_id = '%s'; // --bad-setup-0\n", GenUUID())
		return
	}

	var err error
	// 1. Parse the Referer
	ref, err = UrlGetServer(ref)
	if err != nil {
		dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF), err:%s\n", err)
		fmt.Fprintf(c.Writer, "window.xsrf_id = '%s'; // --bad-setup-4\n", GenUUID())
		return
	}

	fmt.Printf("Headers: %s\n", dbgo.SVarI(c.Request.Header))
	stmt := "q_auth_v1_xsrf_setup ( $1, $2, $3, $4 )"
	rv, e0 := CallDatabaseJSONFunction(c, stmt, "..!!", newId, ref, aCfg.EncryptionPassword, aCfg.UserdataPassword)
	if e0 != nil {
		dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF), err:%s\n", e0)
		fmt.Fprintf(c.Writer, "window.xsrf_id = '%s'; // --bad-setup-0\n", GenUUID())
		return
	}
	type rvEtagData struct {
		Status string `json:"status"`
	}
	// dbgo.Fprintf(os.Stderr, "At:%(LF) %(yellow) at\n")
	var rvData rvEtagData
	err = json.Unmarshal([]byte(rv), &rvData)
	if err != nil {
		dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF), err:%s\n", e0)
		fmt.Fprintf(c.Writer, "window.xsrf_id = '%s'; // --bad-setup-1\n", GenUUID())
		return
	}
	if rvData.Status != "success" {
		dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF) %(red) -- %s\n", dbgo.SVarI(rvData))
		fmt.Fprintf(c.Writer, "window.xsrf_id = '%s'; // --bad-setup-2\n", GenUUID())
		return
	}
	dbgo.Fprintf(os.Stderr, "%(green)Success Status\n")
	h := c.Writer.Header()
	h.Set("Content-Type", "text/javascript")
	h.Set("ETag", newId)
	h.Set("Cache-Control", "max-age=630360000") // 20 year
	fmt.Fprintf(c.Writer, "window.xsrf_id = '%s';\n", newId)
	// xyzzy88 - this is were to add the JS coce to generate the Fingerpint
	if aCfg.UseFingerprint == "yes" {
		code := `
window.x_id = '123';
window.y_id = '123';
function generateUUID(){
    var d = new Date().getTime();
    var uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = (d + Math.random()*16)%16 | 0;
        d = Math.floor(d/16);
        return (c=='x' ? r : (r&0x7|0x8)).toString(16);
    });
    return uuid;
};
if ( window.localStorage ) {
	var v = localStorage.getItem ( "y_id" );
	if ( !v ) {
		v = generateUUID()
		localStorage.setItem ( "y_id", v );	
	}
	window.y_id = v;
}
try {
	var fpPromise = FingerprintJS.load()
	fpPromise
		.then(fp => fp.get())
		.then(result => window.x_id = result.visitorId)
} catch(e) {
	var v = localStorage.getItem ( "FpID" );
	if ( !v ) {
		v = generateUUID();
		localStorage.setItem ( "FpID", v );	
	}
	window.x_id = v;
}
`
		fmt.Fprintf(c.Writer, "%s", code)
	}

	// xyzzy - Add in saving this data for login later!
	// Called above.
	// CREATE OR REPLACE FUNCTION q_auth_v1_etag_seen ( p_id varchar, p_etag varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
	// -- to be called when you have a successful 2fa validation on a user_id
	// CREATE OR REPLACE FUNCTION q_auth_v1_etag_device_mark ( p_seen_id varchar, p_user_id uuid, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
	// Hm...
	// CREATE OR REPLACE FUNCTION q_auth_v1_validate_fingerprint_data ( p_fingerprint_data varchar, p_state varchar, p_user_id uuid, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text

}

// {Method: "GET", Path: "/api/v1/setup", Fx: authHandlerGetXsrfIdFile, UseLogin: PublicApiCall},                                        //
func authHandlerGetXsrfIdFileJSON(c *gin.Context) {
	newId := GenUUID()
	ref := ""
	if len(c.Request.Header) > 0 {
		ref = c.Request.Header.Get("Referer")
		if ref == "" {
			xfhost := c.Request.Header.Get("X-Forwarded-Host")
			xfproto := c.Request.Header.Get("X-Forwarded-Proto")
			ref = fmt.Sprintf("%s://%s/", xfproto, xfhost)
			dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF), ref:%s\n", ref)
		}
	} else {
		dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF), no header at all\n")
		fmt.Fprintf(c.Writer, "window.xsrf_id = '%s'; // --bad-setup-0\n", GenUUID())
		return
	}

	// x_id is fingerprint data
	// y_id is UUID (saved in local storage)
	y_id := GenUUID()
	x_id := GenUUID()
	h := c.Writer.Header()

	var err error
	// 1. Parse the Referer
	ref, err = UrlGetServer(ref)
	if err != nil {
		dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF), err:%s\n", err)
		fmt.Fprintf(c.Writer, "window.xsrf_id = '%s'; // --bad-setup-4\n", GenUUID())
		return
	}

	fmt.Printf("Headers: %s\n", dbgo.SVarI(c.Request.Header))
	stmt := "q_auth_v1_xsrf_setup ( $1, $2, $3, $4 )"
	rv, e0 := CallDatabaseJSONFunction(c, stmt, "..!!", newId, ref, aCfg.EncryptionPassword, aCfg.UserdataPassword)
	if e0 != nil {
		dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF), err:%s\n", e0)
		fmt.Fprintf(c.Writer, "window.xsrf_id = '%s'; // --bad-setup-0\n", GenUUID())
		return
	}
	type rvEtagData struct {
		Status string `json:"status"`
	}
	// dbgo.Fprintf(os.Stderr, "At:%(LF) %(yellow) at\n")
	var rvData rvEtagData
	err = json.Unmarshal([]byte(rv), &rvData)
	if err != nil {
		dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF), err:%s\n", e0)
		h.Set("Content-Type", "application/json")
		fmt.Fprintf(c.Writer, `{"xsrf_id": %q", "bad_setup_1":1, "x_id":%q, "y_id":%q}`, GenUUID(), x_id, y_id)
		return
	}
	if rvData.Status != "success" {
		dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF) %(red) -- %s\n", dbgo.SVarI(rvData))
		h.Set("Content-Type", "application/json")
		fmt.Fprintf(c.Writer, `{"xsrf_id": %q", "bad_setup_2":1, "x_id":%q, "y_id":%q}`, GenUUID(), x_id, y_id)
		return
	}
	dbgo.Fprintf(os.Stderr, "%(green)Success Status\n")

	h.Set("Content-Type", "application/json")
	h.Set("ETag", newId)
	h.Set("Cache-Control", "max-age=630360000") // 20 year

	fmt.Fprintf(c.Writer, `{
	"xsrf_id": %q,
	"x_id": %q,
	"y_id": %q
}`, newId, x_id, y_id)

}

// loginTrackingJsonHandler godoc
// @Summary Return a marker id
// @Schemes
// @Description Mark the device with a file in the cache.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Produce json
// @Success 200 {string} data
// @Failure 304 {string} data
// @Router /api/v1/id.json [get]
func loginTrackingJsonHandler(c *gin.Context) {

	output := `{"id":"123"}`
	// output_len = len(output)
	var newId string

	inm := c.Request.Header.Get("If-None-Match")
	dbgo.Printf("%(Yellow)Header Tags: %(Green)If-None-Match ->%s<- at:%(LF)\n", inm)
	if inm != "" {
		// RFC 7232 section 4.1:
		// a sender SHOULD NOT generate representation metadata other than the
		// above listed fields unless said metadata exists for the purpose of
		// guiding cache updates (e.g., Last-Modified might be useful if the
		// response does not have an ETag field).

		dbgo.Fprintf(os.Stderr, "At:%(LF) %(yellow)---------- if none match ------------\n")
		dbgo.Fprintf(os.Stderr, "%(yellow)ETag(If-None-Match): %s previous\n", inm)
		newId = GenUUID()
		// FUNCTION q_auth_v1_etag_seen ( p_id varchar, p_etag varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
		stmt := "q_auth_v1_etag_seen ( $1, $2, $3, $4 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, "..!!", newId, inm, aCfg.EncryptionPassword, aCfg.UserdataPassword)
		if e0 != nil {
			dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF), err:%s\n", e0)
			goto gen
		}

		// File: /Users/philip/go/src/github.com/pschlump/qr_svr2/gin-upload/jwt_auth/clear_gif.go LineNo:58:
		// rv={"status":"success", "user_id":"", "id":"8343616b-d8be-48d4-787c-f69ce98c7aa0"}
		dbgo.Fprintf(os.Stderr, "At:%(LF) %(yellow) at\n")
		dbgo.Fprintf(os.Stderr, "%(cyan)%(LF): rv=%s\n", rv)
		type rvEtagData struct {
			Status string `json:"status"`
			UserId string `json:"user_id"`
			RowId  string `json:"id"`
			Msg    string `json:"msg"`
		}
		dbgo.Fprintf(os.Stderr, "At:%(LF) %(yellow) at\n")
		var rvData rvEtagData
		err := json.Unmarshal([]byte(rv), &rvData)
		if err != nil {
			dbgo.Fprintf(os.Stderr, "%(red)In Handler at %(LF), err:%s\n", err)
			goto gen
		}
		dbgo.Fprintf(os.Stderr, "%(yellow)%(LF): parsed data=%s\n", dbgo.SVarI(rvData))
		dbgo.Fprintf(os.Stderr, "At:%(LF) %(yellow) at\n")
		if rvData.Msg == "created" {
			dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF) %(red) -- If-None-Match Value Not Found! -- sending back a 200\n")
			goto gen
		}

		dbgo.Fprintf(os.Stderr, "At:%(LF) %(yellow) at\n")
		h := c.Writer.Header()
		delete(h, "Content-Type")
		delete(h, "Content-Length")
		delete(h, "Last-Modified")
		delete(h, "ETag")
		h.Set("ETag", inm)
		// h.Set("Cache-Control", "max-age=31536000") // 1 year
		h.Set("Cache-Control", "max-age=1") // 1 minute
		c.Writer.WriteHeader(http.StatusNotModified)
		dbgo.Printf("At:%(LF)\n")
		return

	}

gen:
	newId = GenUUID()
	output = fmt.Sprintf(`{"id":%q}`, newId)
	// etag := fmt.Sprintf("%x", HashStrings.HashStrings(output, aCfg.EtagPassword))[0:20] // Hash the file
	etag := HashStrings.HashStrings(output, aCfg.EtagPassword)[0:20] // Hash the file
	dbgo.Printf("%(cyan)Generate Etag at:%(LF) ->%s<-\n", etag)      // Dump so we can see what we are inserting
	if db100 {
		// FUNCTION q_auth_v1_etag_seen ( p_id varchar, p_etag varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
		stmt := "q_auth_v1_etag_seen ( $1, $2, $3, $4 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, "..!!", newId, etag, aCfg.EncryptionPassword, aCfg.UserdataPassword)
		if e0 != nil {
			dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF), err:%s\n", e0)
		}
		dbgo.Fprintf(logFilePtr, "%(LF): rv=%s\n", rv)
	}
	h := c.Writer.Header()
	h.Set("Content-Type", "application/json")
	h.Set("ETag", etag)
	// h.Set("Cache-Control", "max-age=31536000") // 1 year
	h.Set("Cache-Control", "max-age=1") // 1 minute
	io.WriteString(c.Writer, string(output))
}

/*
func loginTrackingGifhandler_old(c *gin.Context) {

	// Note: See Line: https://golang.org/src/net/http/fs.go 337
	// w.Header().get("Etag")
	im := c.Request.Header.Get("If-Match")
	inm := c.Request.Header.Get("If-None-Match")
	etag := c.Request.Header.Get("Etag")
	if im != "" || inm != "" || etag != "" {
		// RFC 7232 section 4.1:
		// a sender SHOULD NOT generate representation metadata other than the
		// above listed fields unless said metadata exists for the purpose of
		// guiding cache updates (e.g., Last-Modified might be useful if the
		// response does not have an ETag field).
		if etag == "" {
			etag = GenUUID()
			fmt.Fprintf(logFilePtr, "ETag: %s new\n", etag)
		} else {
			fmt.Fprintf(logFilePtr, "ETag: %s previous\n", etag)
		}
		h := c.Writer.Header()
		delete(h, "Content-Type")
		delete(h, "Content-Length")
		delete(h, "Last-Modified")
		delete(h, "ETag")
		h.Set("ETag", etag)
		c.Writer.WriteHeader(http.StatusNotModified)
		return
	}

	etag = GenUUID()
	c.Writer.Header().Set("Content-Type", "image/gif")
	c.Writer.Header().Set("ETag", etag)
	fmt.Fprintf(logFilePtr, "ETag: %s new\n", etag)
	output, _ := base64.StdEncoding.DecodeString(base64GifPixel)
	io.WriteString(c.Writer, string(output))
}
*/

var db100 = true

/* vim: set noai ts=4 sw=4: */
