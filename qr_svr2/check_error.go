package qr_svr2

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"fmt"
	"os"

	"github.com/pschlump/dbgo"
)

func CheckError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s from: %s\n", err, dbgo.LF(2))
		// os.Exit(1)
		panic("TrackeBack from CheckError")
	}
}
