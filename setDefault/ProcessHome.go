package SetDefault

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"fmt"
	"os"
	"os/user"
	"path"
	"strings"
)

var home string

func init() {
	if os.PathSeparator == '\\' {
		home = "C:/"
	} else {
		home = os.Getenv("HOME")
	}
}

func ProcessHome(fn string) (outFn string) {
	outFn = fn
	if len(fn) > 1 && fn[0:1] == "~" {
		if len(fn) > 2 && fn[0:2] == "~/" {
			outFn = path.Join(home, fn[2:])
			return
		} else {
			s1 := strings.Split(fn[1:], "/")
			username := s1[0]
			uu, err := user.Lookup(username)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Unable to lookup [%s] user and get home directory.\n", username)
				return
			}
			outFn = path.Join(uu.HomeDir, strings.Join(s1[1:], "/"))
			return
		}
	}
	return
}

func StripPrefix(prefix, key string) string {
	if len(key) > len(prefix) {
		return key[len(prefix):]
	}
	return ""
}
