package jwt_auth

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	SetDefault "github.com/pschlump/gintools/setDefault"
)

var demo struct {
	A string `default:"bob"`
}

func SetDefaultRunner() {
	SetDefault.SetDefault(&demo)
}

/* vim: set noai ts=4 sw=4: */
