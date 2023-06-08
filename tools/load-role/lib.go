package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/json"
	"github.com/pschlump/uuid"
)

// SetJsonHdr will set a content-type header to "application/json; charset=utf-8"
func SetJsonHdr(www http.ResponseWriter, req *http.Request) {
	www.Header().Set("Content-Type", "application/json; charset=utf-8")

}

// EmptyDflt if s is empty, then return d.  Creates a default value for parametrs
func EmptyDflt(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// ReadJson read in a JSON file into a go data structure.
func ReadJson(fn string, x interface{}) (err error) {
	var buf []byte
	buf, err = ioutil.ReadFile(fn)
	if err != nil {
		return
	}
	err = json.Unmarshal(buf, x)
	return
}

// ConnectToDb creates a global that is used to connect to the PG database.
// You have to have "DATABASE_URL" setup as an environment variable first. (See setupx.sh)

func ConnectToDb() {
	ctx = context.Background()
	constr := os.Getenv("DATABASE_URL")
	var err error
	// func Connect(ctx context.Context, connString string) (*Pool, error)
	conn, err = pgxpool.Connect(ctx, constr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v connetion string [%s]\n", err, constr)
		os.Exit(1)
	}
}

// DisConnectToDb() closes connection to databse.
func DisConnectToDb() {
	conn.Close()
}

// GenUUID generates a UUID and returns it.
func GenUUID() string {
	newUUID, _ := uuid.NewV4() // Intentionally ignore errors - function will never return any.
	return newUUID.String()
}

// SVar return the JSON encoded version of the data.
func SVar(v interface{}) string {
	s, err := json.Marshal(v)
	// s, err := json.MarshalIndent ( v, "", "\t" )
	if err != nil {
		return fmt.Sprintf("Error:%s", err)
	} else {
		return string(s)
	}
}

// StatusSuccess prepends to a JSON return value with a status:success.
// This will also set the "Content-Type" to "application/json; charset=utf-8".
func StatusSuccess(s string, www http.ResponseWriter, req *http.Request) string {
	SetJsonHdr(www, req)
	return `{"status":"success","data":` + s + "}\n"
}

// SVarI return the JSON encoded version of the data with tab indentation.
func SVarI(v interface{}) string {
	// s, err := json.Marshal ( v )
	s, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		return fmt.Sprintf("Error:%s", err)
	} else {
		return string(s)
	}
}

// GetParam will return the value for a named parameter from either a GET or a POST
// request.  It is not a GET or POST then an empty string is returned.
func GetParam(name string, www http.ResponseWriter, req *http.Request) (val string) {
	if req.Method == "GET" {
		val = req.URL.Query().Get(name)
	} else if req.Method == "POST" {
		req.ParseForm()
		val = req.Form.Get(name)
	}
	return
}

// RmExt removes the extenstion from a file name if it exits.
// if filename is "bc.js", then "bc" will be retuend.
func RmExt(filename string) string {
	var extension = filepath.Ext(filename)
	if extension != "" {
		var name = filename[0 : len(filename)-len(extension)]
		return name
	}
	return filename
}

func ParamListToString_old(x ...interface{}) string {
	//
	// add encrypted data to this....
	// --encrypt-- prefix param means that you should take the next value and encrypt it.
	//
	return fmt.Sprintf("%s", x)
}

func XData(x ...interface{}) string {
	return dbgo.SVar(x)
}

func YData(x ...string) string {
	return dbgo.SVar(x)
}

/* vim: set noai ts=4 sw=4: */
