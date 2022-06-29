package table_rest

// This file is BSD 3 Clause licensed.

import (
	"github.com/pschlump/dbgo"
	"github.com/gin-gonic/gin"
)

// MethodReplace returns a new method if __method__ is a get argument.  This allows for testing
// of code just using get requests.  That is very convenient from a browser.
func MethodReplace(c *gin.Context) (methodOut string) {
	methodOut = c.Request.Method
	dbgo.DbPrintf("MethodReplace", "Check __method__ AT: %(LF)\n")
	found_method, method := GetVar("__method__", c)
	if found_method && method != "" && (c.Request.Method == "GET" || c.Request.Method == "POST") && c.Request.Method != method {
		dbgo.DbPrintf("MethodReplace", "AT: %(LF) method=%s\n", method)
		if InArray(method, []string{"PUT", "POST", "DELETE", "GET"}) {
			dbgo.DbPrintf("MethodReplace", "AT: %(LF) method=%s\n", method)
			return method
		}
	}
	return
}
