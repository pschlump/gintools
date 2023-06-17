package email

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"github.com/pschlump/dbgo"
	"github.com/pschlump/uuid"
)

// XData convers a list of parameters to a JSON data showing what the list contains.  This is returned as a string.
func XData(x ...interface{}) (rv string) {
	rv = dbgo.SVar(x)
	return
}

// GenUUID generates a UUID and returns it.
func GenUUID() string {
	newUUID, _ := uuid.NewV4() // Intentionally ignore errors - function will never return any.
	return newUUID.String()
}

/* vim: set noai ts=4 sw=4: */
