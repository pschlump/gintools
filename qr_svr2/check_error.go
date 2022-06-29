package qr_svr2

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
