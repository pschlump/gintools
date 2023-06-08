package table_rest

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"fmt"
	"os"
	"strings"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pschlump/dbgo"
)

type PGColumn struct {
	ColumnName string
}

type PGTable struct {
	TableName string
	Columns   []PGColumn
}

type PGProc struct {
	FunctionName string
	Columns      []PGColumn
}

func PGCheckTableColumns(tab PGTable) (err error) {
	// if DB == nil {
	if conn == nil {
		return
	}
	err = CheckTable("public", tab.TableName)
	if err != nil {
		return
	}
	cm, _ := GetColumnMap("public", tab.TableName)
	for _, cc := range tab.Columns {
		if !cm[cc.ColumnName] {
			return fmt.Errorf("Missing column [%s] in table [%s]\n", cc.ColumnName, tab.TableName)
		}
	}
	return
}

// func (hdlr *TabServer2Type) GetTableInformationSchema(conn *sizlib.MyDb, TableName string) (rv DbTableType, err error) {

func CheckTable(DbSchema, TableName string) (err error) {
	qry := `SELECT * FROM information_schema.tables WHERE table_schema = $1 and table_name = $2`
	// data := sizlib.SelData(conn, qry, DbSchema, TableName)
	data := SelData(conn, qry, DbSchema, TableName)
	if data == nil || len(data) == 0 {
		fmt.Fprintf(os.Stderr, "%sError(190532): Missing table:%s%s\n", dbgo.ColorRed, TableName, dbgo.ColorReset)
		err = fmt.Errorf("Error(190532): Missing table:%s", TableName)
		return
	}
	return
}

// ./crud-pg-check.go:52:18: cannot use conn (variable of type *pgxpool.Pool) as type *pgx.Conn in argument to SelData
func SelData(db *pgxpool.Pool, q string, data ...interface{}) []map[string]interface{} {
	// func SelData(db *sql.DB, q string, data ...interface{}) []map[string]interface{} {
	// 1 use "sel" to do the query
	// func sel ( res http.ResponseWriter, req *http.Request, db *pgx.Conn, q string, data ...interface{} ) ( Rows *sql.Rows, err error ) {
	// fmt.Printf("in SelData, %s\n", godebug.LF())

	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	// OLD: Rows, err := SelQ(db, q, data...)
	Rows, err := SQLSelect(q, data...)

	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	if err != nil {
		fmt.Printf("Params: %s\n", dbgo.SVar(data))
		return make([]map[string]interface{}, 0, 1)
	}

	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	rv, _, n := RowsToInterface(Rows)
	_ = n

	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	return rv
}

func GetColumnMap(DbSchema, TableName string) (cm map[string]bool, err error) {
	qry := `SELECT * FROM information_schema.columns WHERE table_schema = $1 and table_name = $2`
	// cols := sizlib.SelData(conn.Db, qry, g_schema, TableName)
	// OLD: cols := sizlib.SelData(DB, qry, DbSchema, TableName)
	// cols := SelData(DB, qry, DbSchema, TableName)
	cols := SelData(conn, qry, DbSchema, TableName)

	// fmt.Printf("data=%s\n", dbgo.SVarI(data))
	// fmt.Printf("cols=%s\n", dbgo.SVarI(cols))
	cm = make(map[string]bool)
	for _, vv := range cols {
		cm[vv["column_name"].(string)] = true
		// rv.DbColumns = append(rv.DbColumns, DbColumnsType{
		// 	ColumnName: vv["column_name"].(string),
		// 	DBType:     vv["data_type"].(string),
		// 	TypeCode:   GetTypeCode(vv["data_type"].(string)),
		// })
	}
	// dbgo.Db2Printf(db83, "rv=%s\n", dbgo.SVarI(rv))
	return
}

func PGCheckStoredProcedureNameParams(fd PGProc) (err error) {
	// if DB == nil {
	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	if conn == nil {
		dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
		return
	}
	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	FunctionInfo, err := GetFunctionInformationSchema(fd.FunctionName, "public")
	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	if err != nil {
		dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
		return
	}
	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	//	ParameterList: []ParamListItem{
	//		{ReqVar: "user_id", ParamName: "p_user_id"},
	if len(fd.Columns) != len(FunctionInfo.DbColumns) {
		fmt.Fprintf(os.Stderr, "%sMessage (91442): Function:%s Has incorrect number of parameters.  Expected %d Has %d %s\n", dbgo.ColorRed, fd.FunctionName, len(fd.Columns), len(FunctionInfo.DbColumns), dbgo.ColorReset)
		fmt.Fprintf(os.Stderr, "   From DB=%s\n", dbgo.SVarI(FunctionInfo))
		fmt.Fprintf(os.Stderr, "   From Code=%s\n", dbgo.SVarI(fd))
		err = fmt.Errorf("Function %s incorrect number of parameters.  Want %d have %d", fd.FunctionName, len(fd.Columns), len(FunctionInfo.DbColumns))
		return
	}
	if db91 {
		dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF) compare of passed columns(%s) to Fetched from db (%s)\n", dbgo.SVarI(fd.Columns), dbgo.SVarI(FunctionInfo.DbColumns))
	}
	for _, param := range fd.Columns {
		// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
		ok := false
		for _, have := range FunctionInfo.DbColumns {
			if param.ColumnName == have.ColumnName {
				ok = true
				break
			}
		}
		// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
		if !ok {
			fmt.Fprintf(os.Stderr, "%sMessage (91443): Function:%s Missing Parameter [%s]%s\n", dbgo.ColorRed, fd.FunctionName, param, dbgo.ColorReset)
			err = fmt.Errorf("Function %s missing %s", fd.FunctionName, param)
			return
		}
	}
	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	return
}

var storedProcDefs = make(map[string]CrudStoredProcConfig)

func GetStoredProcDefinition(name string) (rv CrudStoredProcConfig, err error) {
	var ok bool
	if rv, ok = storedProcDefs[name]; !ok {
		err = fmt.Errorf("Missing %s stored procedure definition", name)
	}
	return
}

func GetAllStoredProcNames() (rv []string) {
	for key := range storedProcDefs {
		rv = append(rv, key)
	}
	return
}

func DumpStoredProcDefs() {
	fmt.Printf("%s\n", dbgo.SVarI(storedProcDefs))
}

func ValidateStoredProcs(sp []CrudStoredProcConfig) {

	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	for ii, vv := range sp {
		// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
		vv.FileWhereDefined = dbgo.LF(2) // save where this was called from, that is the source of the data.
		storedProcDefs[vv.StoredProcedureName] = vv

		Columns := make([]PGColumn, 0, len(vv.ParameterList))
		for _, ww := range vv.ParameterList {
			Columns = append(Columns, PGColumn{ColumnName: ww.ParamName})
		}
		fd := PGProc{
			FunctionName: vv.StoredProcedureName,
			Columns:      Columns,
		}
		// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
		err := PGCheckStoredProcedureNameParams(fd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "At %d in table - Name:%s AT:%s\n", ii, vv.StoredProcedureName, dbgo.LF())
		}
	}

	/*
		// dbgo.Db2Printf(db84, "Top Loop Function [%s], params %s %s\n", vv.G, vv.P, dbgo.LF())
		fmt.Printf("\n-----------------------------------------------------------------------\n")
		fmt.Printf("Checking Function/Procedure [%s] for endpoint: %s, params %s\n", vv.G, endPointName, vv.P)
		/ *
			SELECT routines.routine_name, parameters.data_type, parameters.ordinal_position
			FROM information_schema.routines
				JOIN information_schema.parameters ON routines.specific_name=parameters.specific_name
			WHERE routines.specific_schema='public'
			ORDER BY routines.routine_name, parameters.ordinal_position;
		* /
		var FunctionName = vv.G
		var EndPoint = endPointName
		var TheParams = vv.P
		var Valid = vv.Valid
		cfg.PostDbConnectChecks = append(cfg.PostDbConnectChecks, cfg.PostDbType{RunCheck: func(conn *sizlib.MyDb) bool {
			FunctionInfo, err := hdlr.GetFunctionInformationSchema(conn, FunctionName, TheParams)
			if err != nil {
				return false
			}
			fmt.Printf("Doing Check for %s %s : %s\n", FunctionName, TheParams, EndPoint)
			chkExtra := make(map[string]bool)
			for name := range Valid {
				chkExtra[name] = false
			}
			for ii, pp := range TheParams {
				ok := false
				chkExtra[pp] = true
				for name := range Valid {
					if name == pp {
						ok = true
						break
					}
				}
				if !ok {
					dbgo.Db2Printf(db84, "%sAt: %s Valid is wrong - endpoint[%s] missing[%s] at pos=%d in .P[], %s\n", dbgo.ColorRed, dbgo.LF(),
						EndPoint, pp, ii, dbgo.ColorReset)
					fmt.Fprintf(os.Stderr, "%sMessage (41990): Valid is wrong - endpoint[%s] missing[%s] at pos=%d in .P[], %s\n", dbgo.ColorRed,
						EndPoint, pp, ii, dbgo.ColorReset)
					return false
				}
			}
			for key, val := range chkExtra {
				if !val && key != "callback" { // callback is used by JSONp!
					fmt.Fprintf(os.Stderr, "%sNote (41991): Valid has extra, unused field - endpoint[%s] extra[%s], %s\n", dbgo.ColorCyan,
						EndPoint, key, dbgo.ColorReset)
				}
			}
			if len(TheParams) != len(FunctionInfo.DbColumns) {
				dbgo.Db2Printf(db84, "%sAt: %s Mismatch in number of params for function, expected %d(db) have %d, %s\n", dbgo.ColorRed, dbgo.LF(),
					len(TheParams), len(FunctionInfo.DbColumns), dbgo.ColorReset)
				fmt.Fprintf(os.Stderr, "%sMessage (81407): EndPoint [%s] Function [%s] number of columns mismatch config(JsonX) expected %d PostresSQL has %d\n%s", dbgo.ColorRed,
					EndPoint, FunctionName, len(TheParams), len(FunctionInfo.DbColumns), dbgo.ColorReset)
				return false
			}
			//	if !ValidateFunctionCols(FunctionInfo, TheParams) {
			//		return false
			//	}
			return true
		}})
	*/
	// const db84 = false
}

// validate functions

type DbColumnsType struct {
	ColumnName string
	DBType     string
	TypeCode   string
}

type DbTableType struct {
	TableName string
	DbColumns []DbColumnsType
}

func GetTypeCode(ty string) (rv string) {
	rv = "?"
	switch ty {
	case "character varying", "text":
		return "s"
	case "number", "iteger":
		return "i"
	}
	if strings.HasPrefix(ty, "timestamp") {
		return "d"
	}
	return
}

/*
	SELECT routines.routine_name, parameters.data_type, parameters.ordinal_position
	FROM information_schema.routines
		JOIN information_schema.parameters ON routines.specific_name=parameters.specific_name
	WHERE routines.specific_schema='public'
	ORDER BY routines.routine_name, parameters.ordinal_position;
*/
func GetFunctionInformationSchema(FunctionName string, DbSchema string) (rv DbTableType, err error) {
	// OLD: if DB == nil {
	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	if conn == nil {
		return
	}
	dbgo.DbPrintf("Validate-Func", "Validateing Function [%s], params %s %s\n", FunctionName, DbSchema, dbgo.LF())

	// check that the function exists

	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	qry := `SELECT routines.routine_name
			FROM information_schema.routines
			WHERE routines.specific_schema = $1
			  and ( routines.routine_name = lower($2)
			     or routines.routine_name = $2
				  )
	`
	// data := sizlib.SelData(DB, qry, DbSchema, FunctionName)
	// data := SelData(DB, qry, DbSchema, FunctionName)
	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	data := SelData(conn, qry, DbSchema, FunctionName)
	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	if data == nil || len(data) == 0 {
		fmt.Fprintf(os.Stderr, "%sMessage (91532): Missing function:%s%s\n", dbgo.ColorRed, FunctionName, dbgo.ColorReset)
		dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
		err = fmt.Errorf("Missing function %s", FunctionName)
		return
	}
	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	fmt.Fprintf(os.Stderr, "%sFound function: %s%s\n", dbgo.ColorGreen, FunctionName, dbgo.ColorReset)
	rv.TableName = FunctionName
	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")

	// get parametrs now
	qry = `SELECT routines.routine_name
				, parameters.data_type
				, parameters.parameter_name
				, parameters.ordinal_position
			FROM information_schema.routines
				JOIN information_schema.parameters ON routines.specific_name=parameters.specific_name
			WHERE routines.specific_schema = $1
			  and ( routines.routine_name = lower($2)
			     or routines.routine_name = $2
				  )
			ORDER BY routines.routine_name, parameters.ordinal_position;
	`
	// cols := sizlib.SelData(DB, qry, DbSchema, FunctionName)
	// OLD: cols := SelData(DB, qry, DbSchema, FunctionName)
	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	cols := SelData(conn, qry, DbSchema, FunctionName)
	if db90 {
		fmt.Fprintf(logFilePtr, "FunctionName %s - at:%s - database list of params: %s\n", FunctionName, dbgo.LF(), dbgo.SVarI(cols))
	}
	for _, vv := range cols {
		rv.DbColumns = append(rv.DbColumns, DbColumnsType{
			ColumnName: vv["parameter_name"].(string),
			DBType:     vv["data_type"].(string),
			TypeCode:   GetTypeCode(vv["data_type"].(string)),
		})
	}
	if db90 {
		dbgo.DbPrintf("Validate-Func", "rv=%s\n", dbgo.SVarI(rv))
	}
	// dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	return
}

var db90 = false
var db91 = false

// Load PG - setup schema - tables - functiosn - etc.
