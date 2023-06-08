package table_rest

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"path"
	"strings"
)

// 4. Split URL path into components then match by components.
// 	/abc/def/ghi -> []{"abc","def","ghi"}
// cleans URI
func SplitURI(uri string) (result []string) {
	if len(uri) == 0 {
		uri = "/"
	} else if len(uri) > 1 && uri[0] != '/' {
		uri = "/" + uri
	}
	uri = path.Clean(uri)
	s2 := strings.Split(uri, "/")
	if len(s2) > 0 && s2[0] == "" {
		result = append(result, s2[1:]...)
	}
	return
}
