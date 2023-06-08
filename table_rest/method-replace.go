package table_rest

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"github.com/gin-gonic/gin"
	"github.com/pschlump/dbgo"
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
