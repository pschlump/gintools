package jwt_auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/gintools/log_enc"
	"github.com/pschlump/gintools/tf"
	"github.com/pschlump/scany/pgxscan"
)

var ErrHttpStatusInternalServerError = errors.New("Internal Server Error")
var ErrHttpStatusSqlError = errors.New("Sql Error")

type RvCallErrorType struct {
	StdErrorReturn
}

type SQLStringType struct {
	X string
}

type SQLIntType struct {
	X *int
}

// CallDatabaseFunction will call the named function with output data placed in 'out'.   'out' is the address of a data
// type suitable to be passed to json.Unmarshal to decode the data.
func CallDatabaseFunction(c *gin.Context, out interface{}, fCall string, encPat string, data ...interface{}) (err error) {

	perReqLog := tf.GetLogFilePtr(c)
	var rv string
	rv, err = CallDatabaseJSONFunction(c, fCall, encPat, data...)
	if err != nil {
		return
	}

	var rvStatus RvCallErrorType

	err = json.Unmarshal([]byte(rv), out)
	if err != nil {
		dbgo.Fprintf(perReqLog, "Unable to unmarshal %s, ->%s<- %(LF)\n", err, rv)
		// dbgo.Fprintf(logFilePtr, "Unable to unmarshal %s, ->%s<- %(LF)\n", err, rv)

		rvStatus.LogUUID = GenUUID()
		if c != nil {
			c.JSON(http.StatusInternalServerError, LogJsonReturned(perReqLog, rvStatus.StdErrorReturn)) // 500
		}
		return ErrHttpStatusInternalServerError
	}

	return
}

// CallDatabaseJSONFunction will call the named fucntion with the set of parameters.
func CallDatabaseJSONFunction(c *gin.Context, fCall string, encPat string, data ...interface{}) (rv string, err error) {
	perReqLog := tf.GetLogFilePtr(c)
	var v2 []*SQLStringType
	stmt := "select " + fCall + " as \"x\""
	if conn == nil {
		dbgo.Fprintf(perReqLog, "!!!!! connection is nil at:%(LF)\n")
		os.Exit(1)
	}
	dbgo.Fprintf(perReqLog, "%(yellow)[    Database Call]:%(reset) ->%s<- data ->%s<- from/at:%s\n", stmt, dbgo.SVar(data), dbgo.LF(2))
	dbgo.Fprintf(perReqLog, "[    Database Call] ->%s<- data ->%s<- from/at:%s\n", stmt, dbgo.SVar(data), dbgo.LF(2))
	start := time.Now()
	err = pgxscan.Select(ctx, conn, &v2, stmt, data...)
	elapsed := time.Since(start) // elapsed time.Duration
	if err != nil {
		if elapsed > (1 * time.Millisecond) {
			dbgo.Fprintf(perReqLog, "    %(red)Error on select stmt ->%s<- data %s %(red)elapsed:%s%(reset) at:%s %s\n", stmt, dbgo.SVar(data), elapsed, dbgo.LF(-1), dbgo.LF(-2))
		} else {
			dbgo.Fprintf(perReqLog, "    %(red)Error on select stmt ->%s<- data %s elapsed:%s at:%s %s\n", stmt, dbgo.SVar(data), elapsed, dbgo.LF(-1), dbgo.LF(-2))
		}
		// dbgo.Fprintf(perReqLog, "    Error on select stmt ->%s<- data %s elapsed:%s at:%s\n", stmt, dbgo.SVar(data), elapsed, dbgo.LF(-1))
		log_enc.LogSQLError(c, stmt, err, encPat, data...)
		return "", ErrHttpStatusSqlError
	}
	if len(v2) > 0 {
		dbgo.Fprintf(perReqLog, "    %(yellow)Call Returns:%(reset) %s elapsed:%s at:%(LF)\n", v2[0].X, elapsed)
		// dbgo.Fprintf(perReqLog, "    Call Returns: %s elapsed:%s at:%(LF)\n", v2[0].X, elapsed)
		return v2[0].X, nil
	}
	dbgo.Fprintf(perReqLog, "    %(yellow)Call ---no rows returned--- Return%(reset) elapsed:%s at:%(LF)\n", elapsed)
	// dbgo.Fprintf(perReqLog, "    Call Empty ---no rows returned--- elapsed:%s at:%(LF)\n", elapsed)
	return "{}", nil
}

// SelectString will run/execute a SQL statement, returning a string.
func SelectString(c *gin.Context, stmt string, encPat string, data ...interface{}) (rv string, err error) {
	perReqLog := tf.GetLogFilePtr(c)
	var v2 []*SQLStringType
	if conn == nil {
		dbgo.Fprintf(perReqLog, "!!!!! connection is nil at:%(LF)\n")
		os.Exit(1)
	}
	dbgo.Fprintf(perReqLog, "%(yellow)[    Database Call]:%(reset) ->%s<- data ->%s<- from/at:%s\n", stmt, dbgo.SVar(data), dbgo.LF(2))
	// dbgo.Fprintf(perReqLog, "[    Database Call] ->%s<- data ->%s<- from/at:%s\n", stmt, dbgo.SVar(data), dbgo.LF(2))
	start := time.Now()
	err = pgxscan.Select(ctx, conn, &v2, stmt, data...)
	elapsed := time.Since(start) // elapsed time.Duration
	if err != nil {
		if elapsed > (1 * time.Millisecond) {
			dbgo.Fprintf(perReqLog, "    %(red)Error on select stmt ->%s<- data %s %(red)elapsed:%s%(reset) at:%s\n", stmt, dbgo.SVar(data), elapsed, dbgo.LF(-1))
		} else {
			dbgo.Fprintf(perReqLog, "    %(red)Error on select stmt ->%s<- data %s elapsed:%s at:%s\n", stmt, dbgo.SVar(data), elapsed, dbgo.LF(-1))
		}
		// dbgo.Fprintf(perReqLog, "    Error on select stmt ->%s<- data %s elapsed:%s at:%s\n", stmt, dbgo.SVar(data), elapsed, dbgo.LF(-1))
		//if c == nil {
		//	dbgo.Fprintf(perReqLog, "Error: %s stmt %s at %(LF)\n", stmt, err)
		//} else {
		log_enc.LogSQLError(c, stmt, err, encPat, data...)
		//}
		return "", ErrHttpStatusSqlError
	}
	if len(v2) > 0 {
		dbgo.Fprintf(perReqLog, "    %(yellow)Call Returns:%(reset) %s elapsed:%s at:%(LF)\n", v2[0].X, elapsed)
		// dbgo.Fprintf(perReqLog, "    Call Returns: %s elapsed:%s at:%(LF)\n", v2[0].X, elapsed)
		return v2[0].X, nil
	}
	dbgo.Fprintf(perReqLog, "    %(yellow)Call ---no rows returned--- Return%(reset) elapsed:%s at:%(LF)\n", elapsed)
	// dbgo.Fprintf(perReqLog, "    Call Empty ---no rows returned--- elapsed:%s at:%(LF)\n", elapsed)
	return "{}", nil
}

func CallDatabaseJSONFunctionNoErr(c *gin.Context, fCall string, encPat string, data ...interface{}) (rv string, err error) {
	perReqLog := tf.GetLogFilePtr(c)
	var v2 []*SQLStringType
	stmt := "select " + fCall + " as \"x\""
	if conn == nil {
		dbgo.Fprintf(perReqLog, "!!!!! connection is nil at:%(LF)\n")
		os.Exit(1)
	}
	dbgo.Fprintf(perReqLog, "%(yellow)[    Database Call]:%(reset) ->%s<- data ->%s<- from/at:%s\n", stmt, dbgo.SVar(data), dbgo.LF(2))
	// dbgo.Fprintf(perReqLog, "[    Database Call] ->%s<- data ->%s<- from/at:%s\n", stmt, dbgo.SVar(data), dbgo.LF(2))
	start := time.Now()
	err = pgxscan.Select(ctx, conn, &v2, stmt, data...)
	elapsed := time.Since(start) // elapsed time.Duration
	if err != nil {
		if elapsed > (1 * time.Millisecond) {
			dbgo.Fprintf(perReqLog, "    %(red)Error on select stmt ->%s<- data %s %(red)elapsed:%s%(reset) at:%s\n", stmt, dbgo.SVar(data), elapsed, dbgo.LF(-1))
		} else {
			dbgo.Fprintf(perReqLog, "    %(red)Error on select stmt ->%s<- data %s elapsed:%s at:%s\n", stmt, dbgo.SVar(data), elapsed, dbgo.LF(-1))
		}
		// dbgo.Fprintf(perReqLog, "    Error on select stmt ->%s<- data %s elapsed:%s at:%s\n", stmt, dbgo.SVar(data), elapsed, dbgo.LF(-1))
		log_enc.LogSQLErrorNoErr(c, stmt, err, encPat, data...)
		return "", ErrHttpStatusSqlError
	}
	if len(v2) > 0 {
		dbgo.Fprintf(perReqLog, "    %(yellow)Call Returns:%(reset) %s elapsed:%s at:%(LF)\n", v2[0].X, elapsed)
		// dbgo.Fprintf(perReqLog, "    Call Returns: %s elapsed:%s at:%(LF)\n", v2[0].X, elapsed)
		return v2[0].X, nil
	}
	dbgo.Fprintf(perReqLog, "    %(yellow)Call ---no rows returned--- Return%(reset) elapsed:%s at:%(LF)\n", elapsed)
	// dbgo.Fprintf(perReqLog, "    Call Empty ---no rows returned--- elapsed:%s at:%(LF)\n", elapsed)
	return "{}", nil
}

// -------------------------------------------------------------------------------------------------------------------------
func SqlRunStmt(c *gin.Context, stmt string, encPat string, data ...interface{}) (rv []map[string]interface{}, err error) {
	perReqLog := tf.GetLogFilePtr(c)
	// var v2 []*SQLStringType
	if conn == nil {
		dbgo.Fprintf(perReqLog, "!!!!! connection is nil at:%(LF)\n")
		os.Exit(1)
	}
	// fmt.Fprintf(perReqLog, "Database Stmt ->%s<- data ->%s<-\n", stmt, dbgo.SVar(data))
	fmt.Fprintf(perReqLog, "Database Stmt ->%s<- data ->%s<-\n", stmt, dbgo.SVar(data))

	// res, err := conn.Exec(ctx, stmt, data...)
	err = pgxscan.Select(ctx, conn, &rv, stmt, data...)
	if err != nil {
		log_enc.LogSQLError(c, stmt, err, encPat, data...)
		return nil, ErrHttpStatusSqlError
	}

	return nil, nil
}

/* vim: set noai ts=4 sw=4: */
