package run_template

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"net/http"
	"strconv"
)

// if n, err = IsANumber ( page, www, req ) ; err != nil {
func IsANumber(s string, www http.ResponseWriter, req *http.Request) (nv int, err error) {
	var nn int64
	nn, err = strconv.ParseInt(s, 10, 64)
	if err != nil {
		// xyzzyError
		www.WriteHeader(400) // xyzzy fix to name
	} else {
		nv = int(nn)
	}
	return
}

func Contains(lookFor, has []string) (missing []string, allFound bool) {
	allFound = true
	for _, xx := range lookFor {
		if InArray(xx, has) {
		} else {
			allFound = false
			missing = append(missing, xx)
		}
	}
	return
}

func InArray(lookFor string, inArr []string) bool {
	for _, v := range inArr {
		if lookFor == v {
			return true
		}
	}
	return false
}

func InArrayInt(lookFor int, inArr []int) bool {
	for _, v := range inArr {
		if lookFor == v {
			return true
		}
	}
	return false
}
