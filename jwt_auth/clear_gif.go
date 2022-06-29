package jwt_auth

import (
	"fmt"
	"io"
	"net/http"
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
			rv, e0 := CallDatabaseJSONFunction(c, stmt, "..!!", newId, inm, gCfg.EncryptionPassword, gCfg.UserdataPassword)
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
	hash_output := append(output, []byte(gCfg.EtagPassword)...)
	etag := fmt.Sprintf("%x", HashStrings.HashBytes(hash_output))[0:20] // Hash the file
	dbgo.Printf("%(cyan)Generate Etag at:%(LF) ->%s<-\n", etag)         // Dump so we can see what we are inserting
	if db100 {
		stmt := "q_auth_v1_etag_seen ( $1, $2, $3, $4 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, "..!!", newId, etag, gCfg.EncryptionPassword, gCfg.UserdataPassword)
		if e0 != nil {
			dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF), err:%s\n", e0)
		}
		dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)
	}
	h := c.Writer.Header()
	h.Set("Content-Type", "image/gif")
	h.Set("ETag", etag)
	h.Set("Cache-Control", "max-age=31536000") // 1 year
	io.WriteString(c.Writer, string(output))
}
*/

// loginTrackingJsonHandler godoc
// @Summary Return a marker id
// @Schemes
// @Description Mark the device with a file in the cache.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Produce json
// @Success 200 {string} data
// @Failure 304 {string} data
// @Router /v1/auth/id.json [get]
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
		stmt := "q_auth_v1_etag_seen ( $1, $2, $3, $4 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, "..!!", newId, inm, gCfg.EncryptionPassword, gCfg.UserdataPassword)
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
			UserId int    `json:"user_id"`
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
	etag := fmt.Sprintf("%x", HashStrings.HashStrings(output, gCfg.EtagPassword))[0:20] // Hash the file
	dbgo.Printf("%(cyan)Generate Etag at:%(LF) ->%s<-\n", etag)                         // Dump so we can see what we are inserting
	if db100 {
		stmt := "q_auth_v1_etag_seen ( $1, $2, $3, $4 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, "..!!", newId, etag, gCfg.EncryptionPassword, gCfg.UserdataPassword)
		if e0 != nil {
			dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF), err:%s\n", e0)
		}
		dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)
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
