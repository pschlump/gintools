package table_rest

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"crypto/sha1"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

func NameTransform(URIPath string) (rv string) {
	ss := strings.Split(URIPath, "/")
	rv = "X"
	for _, s := range ss {
		if s != "" {
			rv = rv + strings.Title(s)
		}
	}
	return
}

func IsTLS(c *gin.Context) bool {
	if c.Request.TLS != nil {
		return true
	}
	return false
}

func IfEmpty(s, dflt string) string {
	if s == "" {
		return dflt
	}
	return s
}

func Sha1String(s string) []byte {
	h := sha1.New()
	h.Write([]byte(s))
	hash := h.Sum(nil)
	return hash
}

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

func InArrayStr(lookFor string, inArr []string) bool {
	for _, vv := range inArr {
		if lookFor == vv {
			return true
		}
	}
	return false
}

func InArrayStrN(lookFor string, inArr []string) int {
	for ii, vv := range inArr {
		if lookFor == vv {
			return ii
		}
	}
	return -1
}

func RmTrailingSlash(s string) string {
	if len(s) > 1 && s[len(s)-1:] == "/" {
		return s[0 : len(s)-1]
	} else {
		return s
	}
}

/* vim: set noai ts=4 sw=4: */
