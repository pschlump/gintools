package callme

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/pschlump/dbgo"
)

var ErrHttpStatusInternalServerError = errors.New("Internal Server Error")

type RvCallErrorType struct {
	StdErrorReturn
}

// CallDatabaseFunction will call the named function with output data placed in 'out'.   'out' is the address of a data
// type suitable to be passed to json.Unmarshal to decode the data.
func CallDatabaseFunction(c *gin.Context, out interface{}, fCall string, encPat string, data ...interface{}) (err error) {

	var rv string
	rv, err = CallDatabaseJSONFunction(c, fCall, encPat, data...)
	if err != nil {
		return
	}

	var rvStatus RvCallErrorType

	err = json.Unmarshal([]byte(rv), out)
	if err != nil {
		dbgo.Fprintf(os.Stderr, "Unable to unmarshal %s, ->%s<- %(LF)\n", err, rv)
		dbgo.Fprintf(logFilePtr, "Unable to unmarshal %s, ->%s<- %(LF)\n", err, rv)

		rvStatus.LogUUID = GenUUID()
		if c != nil {
			c.JSON(http.StatusInternalServerError, LogJsonReturned(rvStatus.StdErrorReturn)) // 500
		}
		return ErrHttpStatusInternalServerError
	}

	return
}

/* vim: set noai ts=4 sw=4: */
