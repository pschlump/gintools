package table_rest

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
