package callme

import (
	"fmt"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/gintools/log_enc"
	"github.com/pschlump/scany/pgxscan"
)

func CallDatabaseJSONFunction(c *gin.Context, fCall string, encPat string, data ...interface{}) (rv string, err error) {
	var v2 []*SQLStringType
	stmt := "select " + fCall + " as \"x\""
	if conn == nil {
		dbgo.Fprintf(logFilePtr, "!!!!! connection is nil at:%(LF)\n")
		os.Exit(1)
	}
	dbgo.Fprintf(os.Stderr, "%(yellow)[    Database Call]:%(reset) ->%s<- data ->%s<- from/at:%s\n", stmt, dbgo.SVar(data), dbgo.LF(2))
	dbgo.Fprintf(logFilePtr, "[    Database Call] ->%s<- data ->%s<- from/at:%s\n", stmt, dbgo.SVar(data), dbgo.LF(2))
	start := time.Now()
	err = pgxscan.Select(ctx, conn, &v2, stmt, data...)
	elapsed := time.Since(start) // elapsed time.Duration
	if err != nil {
		if elapsed > (1 * time.Millisecond) {
			dbgo.Fprintf(os.Stderr, "    %(red)Error on select stmt ->%s<- data %s %(red)elapsed:%s%(reset) at:%s %s\n", stmt, dbgo.SVar(data), elapsed, dbgo.LF(-1), dbgo.LF(-2))
		} else {
			dbgo.Fprintf(os.Stderr, "    %(red)Error on select stmt ->%s<- data %s elapsed:%s at:%s %s\n", stmt, dbgo.SVar(data), elapsed, dbgo.LF(-1), dbgo.LF(-2))
		}
		dbgo.Fprintf(logFilePtr, "    Error on select stmt ->%s<- data %s elapsed:%s at:%s\n", stmt, dbgo.SVar(data), elapsed, dbgo.LF(-1))
		log_enc.LogSQLError(c, stmt, err, encPat, data...)
		return "", fmt.Errorf("Sql error")
	}
	if len(v2) > 0 {
		dbgo.Fprintf(os.Stderr, "    %(yellow)Call Returns:%(reset) %s elapsed:%s at:%(LF)\n", v2[0].X, elapsed)
		dbgo.Fprintf(logFilePtr, "    Call Returns: %s elapsed:%s at:%(LF)\n", v2[0].X, elapsed)
		return v2[0].X, nil
	}
	dbgo.Fprintf(os.Stderr, "    %(yellow)Call ---no rows returned--- Return%(reset) elapsed:%s at:%(LF)\n", elapsed)
	dbgo.Fprintf(logFilePtr, "    Call Empty ---no rows returned--- elapsed:%s at:%(LF)\n", elapsed)
	return "{}", nil
}
