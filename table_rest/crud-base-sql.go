package table_rest

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

// 1. Convert all to pgx
// 2. Add in all GoFTL*/ []interface{} to data stuff
// 3. Use global as a defauilt - pass to underlying code.

// Notes: https://stackoverflow.com/questions/64357313/postgres-table-batch-updates-using-golang-pgxpool-not-reflected-in-database

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgproto3/v2"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pschlump/MiscLib"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/gintools/log_enc"
	"github.com/pschlump/uuid"
)

var logFilePtr *os.File = os.Stdout

var DbType = "Postgres" // var DbType = "SQLite"

func SetupSQL(f *os.File) {
	logFilePtr = f
	SetupProcCheck()
}

func LogIt(s string, x ...interface{}) {
	fmt.Fprintf(os.Stderr, "{ \"type\":%q", s)
	fmt.Fprintf(logFilePtr, "{ \"type\":%q", s)
	for i := 0; i < len(x); i += 2 {
		if i+1 < len(x) {
			fmt.Fprintf(os.Stderr, ", %q: %q", x[i], x[i+1])
			fmt.Fprintf(logFilePtr, ", %q: %q", x[i], x[i+1])
		}
	}
	fmt.Fprintf(os.Stderr, "}\n")
	fmt.Fprintf(logFilePtr, "}\n")
}

// LogQueries is called with all statments to log them to a file.
func logQueries(stmt string, err error, data []interface{}, elapsed time.Duration) {
	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	e := "SQLStmtRun"
	if err != nil {
		e = "SQLError"
	}
	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	log_enc.LogIt(e,
		"stmt", stmt,
		"error", fmt.Sprintf("%s", err),
		"data", dbgo.SVar(data), // "data", dbgo.SVar(data),
		"elapsed", elapsed,
		"AT", dbgo.LF(3),
	)
	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	if logFilePtr != nil {
		// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
		if err != nil {
			// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
			fmt.Fprintf(logFilePtr, "Error: %s stmt: %s data: %v elapsed: %s called from: %s\n", err, stmt, dbgo.SVar(data), elapsed, dbgo.LF(3))
		} else {
			// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
			fmt.Fprintf(logFilePtr, "stmt: %s data: %v elapsed: %s\n", stmt, dbgo.SVar(data), elapsed)
		}
	}
	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
}

func logQueriesW(c *gin.Context, stmt string, err error, data []interface{}, elapsed time.Duration) {
	e := "SQLStmtRun"
	if err != nil {
		e = "SQLError"
	}
	log_enc.LogIt(e,
		"url", c.Request.RequestURI,
		"method", c.Request.Method,
		"stmt", stmt,
		"error", fmt.Sprintf("%s", err),
		"data", dbgo.SVar(data), // "data", dbgo.SVar(data),
		"elapsed", elapsed,
		"AT", dbgo.LF(3),
	)
	if logFilePtr != nil {
		if err != nil {
			fmt.Fprintf(logFilePtr, "Error: %s stmt: %s data: %v elapsed: %s called from: %s\n", err, stmt, dbgo.SVar(data), elapsed, dbgo.LF(3))
		} else {
			fmt.Fprintf(logFilePtr, "stmt: %s data: %v elapsed: %s\n", stmt, dbgo.SVar(data), elapsed)
		}
	}
}

// SQLQueryRow queries a single row and returns that data.
// func SQLQueryRow(stmt string, data ...interface{}) (aRow *sql.Row) {
func SQLQueryRow(stmt string, data ...interface{}) (aRow pgx.Row) {
	start := time.Now()
	stmt, data, _ = BindFixer(stmt, data)
	// xyzzy
	aRow = conn.QueryRow(ctx, stmt, data...)
	//	aRow = DB.QueryRow(stmt, data...)
	elapsed := time.Since(start)
	logQueries(stmt, nil, data, elapsed)
	return
}

func SQLQueryRowW(c *gin.Context, stmt string, data ...interface{}) (aRow pgx.Row) {
	start := time.Now()
	stmt, data, _ = BindFixer(stmt, data)
	// xyzzy
	aRow = conn.QueryRow(ctx, stmt, data...)
	//	aRow = DB.QueryRow(stmt, data...)
	elapsed := time.Since(start)
	logQueriesW(c, stmt, nil, data, elapsed)
	return
}

// SQLSelectRow is SQLQueryRow under a different name.
func SQLSelectRow(stmt string, data ...interface{}) (aRow pgx.Row) {
	return SQLQueryRow(stmt, data...)
}

// SQLQuery runs stmt and returns rows.
func SQLQuery(stmt string, data ...interface{}) (resultSet pgx.Rows, err error) {
	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	start := time.Now()
	stmt, data, _ = BindFixer(stmt, data)
	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	resultSet, err = conn.Query(ctx, stmt, data...)
	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	elapsed := time.Since(start)
	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	logQueries(stmt, err, data, elapsed)
	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	return
}

// SQLQuery runs stmt and returns rows.
func SQLQueryW(c *gin.Context, stmt string, data ...interface{}) (resultSet pgx.Rows, err error) {
	start := time.Now()
	stmt, data, _ = BindFixer(stmt, data)
	resultSet, err = conn.Query(ctx, stmt, data...)
	elapsed := time.Since(start)
	logQueriesW(c, stmt, err, data, elapsed)
	return
}

// SQLSelect is SQLQuery under a different name.
func SQLSelect(stmt string, data ...interface{}) (resultSet pgx.Rows, err error) {
	return SQLQuery(stmt, data...)
}

// SQLUpdate can run update statements that do not return data.
func SQLUpdate(stmt string, data ...interface{}) (nr int, err error) {
	start := time.Now()
	dbgo.DbPrintf("crud-base-sql", "SQLUpdate: AT: %s\n", dbgo.LF())

	sstmt, ddata, _ := BindFixer(stmt, data)
	dbgo.DbPrintf("crud-base-sql", "SQLUpdate: AT: %s\n", dbgo.LF())
	res, e0 := conn.Exec(ctx, stmt, ddata...)
	if e0 != nil {
		err = e0
		return
	}
	nrT := res.RowsAffected()
	nr = int(nrT)
	// statement.Close()
	//	}
	dbgo.DbPrintf("crud-base-sql", "SQLUpdate: AT: %s\n", dbgo.LF())
	elapsed := time.Since(start)
	dbgo.DbPrintf("crud-base-sql", "SQLUpdate: AT: %s\n", dbgo.LF())
	logQueries(sstmt, err, ddata, elapsed)
	return
}

func SQLUpdateW(c *gin.Context, stmt string, data ...interface{}) (nr int, err error) {
	start := time.Now()
	dbgo.DbPrintf("crud-base-sql", "SQLUpdate: AT: %s\n", dbgo.LF())

	sstmt, ddata, _ := BindFixer(stmt, data)
	dbgo.DbPrintf("crud-base-sql", "SQLUpdate: AT: %s\n", dbgo.LF())
	res, e0 := conn.Exec(ctx, stmt, ddata...)
	if e0 != nil {
		err = e0
		return
	}
	nrT := res.RowsAffected()
	nr = int(nrT)
	// statement.Close()
	//	}
	dbgo.DbPrintf("crud-base-sql", "SQLUpdate: AT: %s\n", dbgo.LF())
	elapsed := time.Since(start)
	dbgo.DbPrintf("crud-base-sql", "SQLUpdate: AT: %s\n", dbgo.LF())
	logQueriesW(c, sstmt, err, ddata, elapsed)
	return
}

// SQLInsert can run insert statements that do not return data.
func SQLInsert(stmt string, data ...interface{}) (err error) {
	start := time.Now()
	sstmt, ddata, _ := BindFixer(stmt, data)
	dbgo.DbPrintf("crud-base-sql",
		"%sSQLInsert: AT: %s stmtNew[%s] data %s%s\n", dbgo.ColorCyan, dbgo.LF(), sstmt, dbgo.SVar(ddata), dbgo.ColorReset)
	res, e0 := conn.Exec(ctx, stmt, ddata...)
	err = e0
	if err == nil {
		elapsed := time.Since(start)
		logQueries(sstmt, err, ddata, elapsed)
		return err
	}
	_ = res
	elapsed := time.Since(start)
	logQueries(sstmt, err, ddata, elapsed)
	return
}

// SQLInsert can run insert statements that do not return data.
func SQLInsertW(c *gin.Context, stmt string, data ...interface{}) (err error) {
	start := time.Now()
	sstmt, ddata, _ := BindFixer(stmt, data)
	dbgo.DbPrintf("crud-base-sql",
		"%sSQLInsert: AT: %s stmtNew[%s] data %s%s\n", dbgo.ColorCyan, dbgo.LF(), sstmt, dbgo.SVar(ddata), dbgo.ColorReset)
	res, e0 := conn.Exec(ctx, stmt, ddata...)
	err = e0
	if err == nil {
		elapsed := time.Since(start)
		logQueries(sstmt, err, ddata, elapsed)
		return err
	}
	_ = res
	elapsed := time.Since(start)
	logQueriesW(c, sstmt, err, ddata, elapsed)
	return
}

// SQLInsertId can run insert statements , returns database generated id.
func SQLInsertId(stmt string, data ...interface{}) (id int64, err error) {
	start := time.Now()
	sstmt, ddata, _ := BindFixer(stmt, data)
	dbgo.DbPrintf("crud-base-sql", "%sSQLInsert: AT: %s stmtNew[%s] data %s%s\n", dbgo.ColorCyan, dbgo.LF(), sstmt, dbgo.SVar(ddata), dbgo.ColorReset)
	e0 := conn.QueryRow(ctx, stmt, ddata...).Scan(&id)
	if e0 != nil {
		err = e0
	}
	elapsed := time.Since(start)
	logQueries(sstmt, err, ddata, elapsed)
	return
}

// SQLInsertId can run insert statements , returns database generated id.
func SQLInsertIdW(c *gin.Context, stmt string, data ...interface{}) (id int64, err error) {
	start := time.Now()
	sstmt, ddata, _ := BindFixer(stmt, data)
	dbgo.DbPrintf("crud-base-sql", "%sSQLInsert: AT: %s stmtNew[%s] data %s%s\n", dbgo.ColorCyan, dbgo.LF(), sstmt, dbgo.SVar(ddata), dbgo.ColorReset)
	e0 := conn.QueryRow(ctx, stmt, ddata...).Scan(&id)
	if e0 != nil {
		err = e0
	}
	elapsed := time.Since(start)
	logQueriesW(c, sstmt, err, ddata, elapsed)
	return
}

// SQLDelete can run delete statements.
func SQLDelete(stmt string, data ...interface{}) (err error) {
	start := time.Now()
	sstmt, ddata, _ := BindFixer(stmt, data)
	dbgo.DbPrintf("crud-base-sql", "%sSQLDelete: AT: %s stmtNew[%s] data %s%s\n", dbgo.ColorCyan, dbgo.LF(), sstmt, dbgo.SVar(ddata), dbgo.ColorReset)
	_, err = conn.Exec(ctx, stmt, ddata...)
	elapsed := time.Since(start)
	logQueries(sstmt, err, ddata, elapsed)
	return
}

func SQLDeleteW(c *gin.Context, stmt string, data ...interface{}) (err error) {
	start := time.Now()
	sstmt, ddata, _ := BindFixer(stmt, data)
	dbgo.DbPrintf("crud-base-sql", "%sSQLDelete: AT: %s stmtNew[%s] data %s%s\n", dbgo.ColorCyan, dbgo.LF(), sstmt, dbgo.SVar(ddata), dbgo.ColorReset)
	_, err = conn.Exec(ctx, stmt, ddata...)
	elapsed := time.Since(start)
	logQueriesW(c, sstmt, err, ddata, elapsed)
	return
}

// RunStmt ( filelib.QtR( `drop table if exists get_columns_%{table_no%}`, mdata ) )
func RunStmt(stmt string, data ...interface{}) (err error) {
	return SQLInsert(stmt, data...)
}

// n := SelectInt ( `SELECT nextval('"table_id_seq"') as "x"` )
func SelectInt(stmt string, data ...interface{}) (n int) {
	err := SQLQueryRow(stmt, data...).Scan(&n)
	if err != nil {
		return 0
	}
	return
}

// --------------------------------------------------------------------------------------------------------------------------------------------
func GetColumns(rows pgx.Rows) (columns []string, err error) {
	// OLD2: var fd []pgx.FieldDescription
	var fd []pgproto3.FieldDescription
	fd = rows.FieldDescriptions()
	columns = make([]string, 0, len(fd))
	for _, vv := range fd {
		columns = append(columns, string(vv.Name))
	}
	return
}

func RowsToInterface(rows pgx.Rows) ([]map[string]interface{}, string, int) {
	// OLD: func RowsToInterface(rows *sql.Rows) ([]map[string]interface{}, string, int) {

	var finalResult []map[string]interface{}
	var oneRow map[string]interface{}
	var id string

	id = ""

	if rows == nil {
		return nil, "", 0
	}

	// Get column names
	// OLD: columns, err := rows.Columns()
	columns, err := GetColumns(rows)
	if err != nil {
		panic(err.Error())
	}
	length := len(columns)
	// dbgo.Printf("%(yellow)Columns from select are ->%s<- len %d\n", columns, len(columns))

	// Make a slice for the values
	values := make([]interface{}, length)

	// rows.Scan wants '[]interface{}' as an argument, so we must copy the
	// references into such a slice
	// See http://code.google.com/p/go-wiki/wiki/InterfaceSlice for details
	scanArgs := make([]interface{}, length)
	for i := range values {
		scanArgs[i] = &values[i]
	}

	// Fetch rows
	j := 0
	for rows.Next() {
		oneRow = make(map[string]interface{}, length)
		err = rows.Scan(scanArgs...)
		if err != nil {
			panic(err.Error())
		}

		// Print data
		for i, value := range values {
			// dbgo.Printf("%(cyan)RowsToInterface... At %(LF)  top i=%d %T\n", i, value)
			switch value.(type) {
			case nil:
				// fmt.Println("n, %s", columns[i], ": NULL", dbgo.LF())
				oneRow[columns[i]] = nil

			case [16]uint8:
				// fmt.Printf("%s--- In [16]uint8 Case [%s] - %T %s\n", MiscLib.ColorRed, dbgo.LF(), value, MiscLib.ColorReset)
				var uu uuid.UUID
				uu = (uuid.UUID)(value.([16]uint8))

				// dbgo.Fprintf(os.Stderr, "%(cyan)\n--- In [16]uint8 Case [%s] - %T uu=%s\n", value, value, uu)

				if strings.HasSuffix(columns[i], "_id") || columns[i] == "id" {
					id = fmt.Sprintf("%s", uu.String())
				}
				oneRow[columns[i]] = fmt.Sprintf("%s", uu.String())

			case []byte:
				// fmt.Printf("[]byte, len = %d, %s\n", len(value.([]byte)), dbgo.LF())
				if len(value.([]byte)) == 16 {
					if uuid.IsUUID(fmt.Sprintf("%s", value.([]byte))) {
						u, err := uuid.Parse(value.([]byte))
						if err != nil {
							// fmt.Printf("Error: Invalid UUID parse, %s\n", dbgo.LF())
							oneRow[columns[i]] = string(value.([]byte))
							if columns[i] == "id" && j == 0 {
								id = fmt.Sprintf("%s", value)
							}
						} else {
							if columns[i] == "id" && j == 0 {
								id = u.String()
							}
							oneRow[columns[i]] = u.String()
							// fmt.Printf(">>>>>>>>>>>>>>>>>> %s, %s\n", value, dbgo.LF())
						}
					} else {
						if columns[i] == "id" && j == 0 {
							id = fmt.Sprintf("%s", value)
						}
						oneRow[columns[i]] = string(value.([]byte))
						// fmt.Printf(">>>>> 2 >>>>>>>>>>>>> %s, %s\n", value, dbgo.LF())
					}
				} else {
					// Floats seem to end up at this point - xyzzy - instead of float64 -- so....  Need to check our column type info and see if 'f'  ---- xyzzy
					// fmt.Println("s", columns[i], ": ", string(value.([]byte)))
					if columns[i] == "id" && j == 0 {
						id = fmt.Sprintf("%s", value)
					}
					oneRow[columns[i]] = string(value.([]byte))
				}

			case int64:
				// fmt.Println("i, %s", columns[i], ": ", value, dbgo.LF())
				// oneRow[columns[i]] = fmt.Sprintf ( "%v", value )	// PJS-2014-03-06 - I suspect that this is a defect
				oneRow[columns[i]] = value

			case int32:
				// fmt.Println("i, %s", columns[i], ": ", value, dbgo.LF())
				// oneRow[columns[i]] = fmt.Sprintf ( "%v", value )	// PJS-2014-03-06 - I suspect that this is a defect
				oneRow[columns[i]] = int64(value.(int32))

			case float64:
				// fmt.Println("f, %s", columns[i], ": ", value, dbgo.LF())
				// oneRow[columns[i]] = fmt.Sprintf ( "%v", value )
				// fmt.Printf ( "yes it is a float\n" )
				oneRow[columns[i]] = value

			case bool:
				// fmt.Println("b, %s", columns[i], ": ", value, dbgo.LF())
				// oneRow[columns[i]] = fmt.Sprintf ( "%v", value )		// PJS-2014-03-06
				// oneRow[columns[i]] = fmt.Sprintf ( "%t", value )		"true" or "false" as a value
				oneRow[columns[i]] = value

			case string:
				// fmt.Printf("string, %s\n", dbgo.LF())
				if columns[i] == "id" && j == 0 {
					id = fmt.Sprintf("%s", value)
				}
				// fmt.Println("S", columns[i], ": ", value)
				oneRow[columns[i]] = fmt.Sprintf("%s", value)

			// Xyzzy - there is a timeNull structure in the driver - why is that not returned?  Maybee it is????
			// oneRow[columns[i]] = nil
			case time.Time:
				oneRow[columns[i]] = (value.(time.Time)).Format(ISO8601output)

			default:
				fmt.Printf("%s--- In default Case [%s] - %T %s\n", MiscLib.ColorRed, dbgo.LF(), value, MiscLib.ColorReset)
				fmt.Fprintf(os.Stderr, "%s--- In default Case [%s] - %T %s\n", MiscLib.ColorRed, dbgo.LF(), value, MiscLib.ColorReset)
				// fmt.Printf ( "default, yes it is a... , i=%d, %T\n", i, value, dbgo.LF() )
				// fmt.Println("r", columns[i], ": ", value)
				if columns[i] == "id" && j == 0 {
					id = fmt.Sprintf("%v", value)
				}
				oneRow[columns[i]] = fmt.Sprintf("%v", value)
			}
			//fmt.Printf("\nType: %s\n", reflect.TypeOf(value))
		}
		// fmt.Println("-----------------------------------")
		finalResult = append(finalResult, oneRow)
		j++
	}
	return finalResult, id, j
}

// --------------------------------------------------------------------------------------------------------------------------------------------

var conn *pgxpool.Pool
var ctx context.Context

// ISO format for date
const ISO8601 = "2006-01-02T15:04:05.99999Z07:00"

// ISO format for date
const ISO8601output = "2006-01-02T15:04:05.99999-0700"

// ConnectToDb creates a global that is used to connect to the PG database.
// You have to have "DATABASE_URL" setup as an environment variable first. (See ../setupx.sh)

func ConnectToDb() {
	ctx = context.Background()
	constr := os.Getenv("DATABASE_URL")
	var err error
	// func Connect(ctx context.Context, connString string) (*Pool, error)
	conn, err = pgxpool.Connect(ctx, constr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v connetion string [%s]\n", err, constr)
		os.Exit(1)
	}
}

func SetupConnectToDb(xctx context.Context, xconn *pgxpool.Pool) {
	ctx = xctx
	conn = xconn
	if conn == nil {
		dbgo.Fprintf(os.Stderr, "!!!! %(red)in SetupConnectToDb -- conn is nil\n")
	} else {
		dbgo.Fprintf(os.Stderr, "!!!! %(green)in SetupConnectToDb -- conn is good !!!!!\n")
	}

}

// DisConnectToDb() closes connection to databse.
func DisConnectToDb() {
	conn.Close()
}

/* vim: set noai ts=4 sw=4: */
