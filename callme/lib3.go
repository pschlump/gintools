package callme

import (
	"os"

	"github.com/pschlump/dbgo"
)

func LogJsonReturned(x interface{}) interface{} {
	if y, ok := x.(string); ok {
		dbgo.Fprintf(os.Stdout, "%(cyan)Returns: %s at:%s\n", y, dbgo.LF(2))
		dbgo.Fprintf(logFilePtr, "Returns: %s at:%s\n", y, dbgo.LF(2))
	} else {
		dbgo.Fprintf(os.Stdout, "%(cyan)Returns: %s at:%s\n", dbgo.SVarI(x), dbgo.LF(2))
		dbgo.Fprintf(logFilePtr, "Returns: %s at:%s\n", dbgo.SVarI(x), dbgo.LF(2))
	}
	return x
}
