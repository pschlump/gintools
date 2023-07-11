package table_rest

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"fmt"
	"testing"
)

/*
      priv_name
---------------------
 May Change Password
 May Call Test
 May Login
(3 rows)
*/

// TODO - connect to d.b.
// TODO - 1 pull out ID of user to check.
// TODO - 2 get list of privs

func TestCheckPriv(t *testing.T) {
	if false {
		v := CheckPriv(nil, "61", "May Change Password")
		fmt.Printf("v=%v\n", v)
	}
}

/* vim: set noai ts=4 sw=4: */
