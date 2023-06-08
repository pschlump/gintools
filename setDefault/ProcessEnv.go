package SetDefault

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"os"
	"strings"

	"github.com/pschlump/dbgo"
)

func ProcessENV(curVal, sfldName string) string {
	dbgo.DbPfb(db7, "curVal [%s] sfldName [%s] at:%(LF)\n", curVal, sfldName)
	name := curVal[5:]
	envVal := ""
	if strings.Contains(name, "=") {
		dbgo.DbPfb(db7, "found = at:%(LF)\n")
		ss := strings.Split(name, "=")
		dbgo.DbPfb(db7, "ss ->%s<- len %d = at:%(LF)\n", dbgo.SVarI(ss), len(ss))
		name = ss[0] // Pick off 1st chunk
		envVal = os.Getenv(name)
		dbgo.DbPfb(db7, "name ->%s<- envValue= %s = at:%(LF)\n", name, envVal)
		if len(ss) > 1 && envVal == "" {
			envVal = ss[1]
		}
	} else {
		envVal = os.Getenv(name)
	}
	dbgo.DbPfb(db2, "Debug: %(Yellow)Overwriting field %s current [%s] with [%s] curVal=[%s], at:%(LF)\n", sfldName, curVal, envVal, curVal)
	if len(envVal) > 1 && envVal[0:1] == "~" {
		envVal = ProcessHome(envVal)
	}
	dbgo.DbPfb(db2, "Debug: %(Yellow)Processed after home ->%s<-\n", envVal)
	return envVal
}

var db7 = false
var db2 = false
