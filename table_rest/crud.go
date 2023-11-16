package table_rest

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

// xyzzy00000 - error check

// xyzzy - for user_id = "__user_id__" - func FoundCol(c *gin.Context, WhereCols []string, UseRLS []RLSColumns) (cols []string, colsData []interface{}, found bool) {
// 		make change to this to pull back the "__user_id__" data?

// xyzzy - TODO - fix error messages written back to be in standard format --- xyzzy000

// mux:956: func (mux *ServeMux) Handle(pattern string, handler http.Handler) (rv *MuxAdditionalCriteria) {		// xyzzy424232 TODO - creation of the new endpoint.
// xyzzy5 - TODO - Must have error text returned. -- this is a general error - all error returns must have a message.

// ----------------------------------------------------------------------------------------------
// Should add a "PKColums" that is any legitimate set of primary key columns (or unique)
// Should add a "WhereColums" that is any legitimate set of queriable columns that are indexed
// 		for building a good index.
//
// Delete -> role -> id= or role_name= - both in PKColumns -- if PKColumns is not empty then
//		DELETE:/api/v1/role - requires a PKColumns match to work | a WhereColumns match to work.
//
// Change from current - make "DeleteCols [][]string so { { "id" } , { "role_name" } } and must mach one.
// ----------------------------------------------------------------------------------------------

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pschlump/dbgo"
	j5 "github.com/pschlump/json5"
)

type StatusType int

const (
	OkContinueSaveOutData StatusType = 1
	OkDiscard             StatusType = 2
	ErrorFail             StatusType = 3
)

type PrePostFlag int

const (
	PreFlag  PrePostFlag = 1
	PostFlag PrePostFlag = 2
)

type PrePostFx func(c *gin.Context, pp PrePostFlag, cfgData, inData string) (outData string, status StatusType, err error)

// ------------------------------------------------------------------------------------------------------------------------------------------
type CrudColTypeData struct {
	Name    string `json:"ColTypeName"`
	Type    string `json:"ColTypeType"`
	SeqName string `json:"ColTypeSeqName"`
}

type RLSColumns struct {
	ColumnName       string `json:"ColumnName"`
	ContextValueName string `json:"ContextValueName"`
}

type CrudConfig struct {
	CrudBaseConfig
	MethodsAllowed      []string          `json:"MethodsAllowed"`      // Set of methods that are allowed
	TableName           string            `json:"TableName"`           // table name
	InsertCols          []string          `json:"InsertCols"`          // Valid columns for insert
	ColsTypes           []CrudColTypeData `json:"ColsTypes"`           // Type of columns for thins like 'box'
	InsertPkCol         string            `json:"InsertPkCol"`         // PK during insert
	UpdateCols          []string          `json:"UpdateCols"`          // Valid columns for update
	UpdatePkCol         string            `json:"UpdatePkCol"`         // PK during update
	DeleteCols          []string          `json:"DeleteCols"`          // Valid columns for delete
	DeletePkCol         string            `json:"DeletePkCol"`         // PK during delete
	WhereCols           []string          `json:"WhereCols"`           // Set of columns that can be used in the "where" clause.
	SelectPkCol         string            `json:"SelectPkCol"`         // PK during select
	OrderByCols         []string          `json:"OrderByCols"`         // Set of columns that can be used in the "order by" clause.
	SelectRequiresWhere bool              `json:"SelectRequiresWhere"` // if true, then where must be specified -- can not return entire table.
	ProjectedCols       []string          `json:"ProjectedCols"`       // Set of columns that are projected in a select (GET).
	InsertAuthPrivs     []string          `json:"InsertAuthPrivs"`     // Prives that are requried to access this end point (requires login/auth_token/jwt)
	UpdateAuthPrivs     []string          `json:"UpdateAuthPrivs"`     // Prives that are requried to access this end point (requires login/auth_token/jwt)
	DeleteAuthPrivs     []string          `json:"DeleteAuthPrivs"`     // Prives that are requried to access this end point (requires login/auth_token/jwt)
	SelectAuthPrivs     []string          `json:"SelectAuthPrivs"`     // Prives that are requried to access this end point (requires login/auth_token/jwt)
	KeywordSearch       []string          `json:"KeywordSearch"`       // List of columns that will have tsvector data safedn from.
	KeywordKeyColumn    string            `json:"KewordKeyColumn"`     // tsvector colum where prioritiezed data is stored.
	UseRLS              []RLSColumns      `json:"UseRLS"`              // Use Row Level Secuirty basesed on colums specified. (user_id=$1)
}
type ParamListItem struct {
	ReqVar    string // variable for GetVar()
	ParamName string // Name of variable (Checked v.s. stored procedure name variable names)
	AutoGen   string // TODO Is automatically generated value (think UUID, Random or Sequence)
	Required  bool   // Verify that value is supplied (check if this is implemented)
}

type CrudBaseConfig struct {
	URIPath          string          // Path that will reach this end point
	JWTKey           bool            // Require a JWT token authentication header (logged in)
	APIKey           string          //
	TableNameList    []string        // table name update/used in call (Info Only)
	ParameterList    []ParamListItem // Pairs of values
	PreProc          []string        // Functions to call before the store procedure
	PreConfig        []string        //
	PostProc         []string        // Functions to call after the return from the S.P.
	PostConfig       []string        //
	NoDoc            bool            // Turn of documentation on this API
	DocTag           string          // Documentation tag for lookup and display of doc.
	AuthPrivs        []string        // Prives that are required to access this end point (requires login/auth_token/jwt)
	GET_InputList    []*MuxInput     // Validation of inputs for htis call, if len(0) then no validation takes place.
	PUT_InputList    []*MuxInput     // Validation of inputs for htis call, if len(0) then no validation takes place.
	POST_InputList   []*MuxInput     // Validation of inputs for htis call, if len(0) then no validation takes place.
	DELETE_InputList []*MuxInput     // Validation of inputs for htis call, if len(0) then no validation takes place.
	InputList        []*MuxInput     // Validation of inputs for htis call, if len(0) then no validation takes place. -- This is for "All" and excludes use of per-method stuff
	MuxName          string          // Name used for generation of code in desc.html
	NoValidate       bool            // Skip all validation - useful for items like files that do not have an active component.
	FileWhereDefined string          // debugging info on where the definition comes from
	Comment          string          //
	EncryptPat       string          // . - pass, e encrypt, ! ignore
}

// --------------------------------------------------------------------------------------------

type CrudStoredProcConfig struct {
	CrudBaseConfig             //
	StoredProcedureName string // Name of stored procedure to call.

	CallAuthPrivs []string `json:"CallAuthPrivs"` // Prives that are requried to access this end point (requires login/auth_token/jwt)
}

type CrudSubQueryConfig struct {
	BindValues []string // [ "id" ]
	To         string   // event_list - place to put the data result.
	QueryTmpl  string   // select * from "event" where "item_id" = $1 order by "seq"

	PrimayTableName string // MuxName
	HeaderInfo      []HeaderConfig
	BodyInfo        []BodyConfig
	SubQuery        []CrudSubQueryConfig // Recursive

	TableNameList []string // MuxName -- PJS New
	NamedOptional string   // New PJS - for __include__ optional data as sub-query 	__include__=notes when running primary query
	Cached        bool     // New PJS - for __include__ optional data as sub-query 	cache values so as to not re-run query

	SelectAuthPrivs []string `json:"SelectAuthPrivs"` // Prives that are requried to access this end point (requires login/auth_token/jwt)

}

type HeaderConfig struct {
	ColumnTitle string
	ColumnName  string
	ColumnPos   int
}
type BodyConfig struct {
	ColumnName string
	ColumnPos  int
}
type CrudQueryConfig struct {
	CrudBaseConfig
	QueryString     string // "select ... from tables where {{.where}} {{.order_by}}
	SubQuery        []CrudSubQueryConfig
	PrimayTableName string // MuxName
	HeaderInfo      []HeaderConfig
	BodyInfo        []BodyConfig
	IsUpdate        bool
	IsDelete        bool
	IsInsert        bool
	SelectAuthPrivs []string // Prives that are required to access this end point (requires login/auth_token/jwt)

}

// ------------------------------------------------------------------------------------------------------------------------------------------
type GetStatusType struct {
	Status         string
	HttpStatusCode int    `json:"status_code"`
	Msg            string `json:"msg"`
}

// ------------------------------------------------------------------------------------------------------------------------------------------
func RunPreFunctions(c *gin.Context, SPData CrudBaseConfig) (err error) {
	for ii, px := range SPData.PreProc {
		fx, found := PrePostTab[px]
		cfg := ""
		if SPData.PreConfig != nil && ii < len(SPData.PreConfig) {
			cfg = SPData.PreConfig[ii]
		}
		if !found {
			fmt.Fprintf(os.Stderr, "Missing [%s][%s] pre/func - no action taken - %s at %d\n", px, cfg, SPData.URIPath, ii)
			fmt.Fprintf(logFilePtr, "Missing [%s][%s] pre/func - no action taken - %s at %d\n", px, cfg, SPData.URIPath, ii)
		} else {
			_, status, e0 := fx(c, PreFlag, cfg, "")
			if status == ErrorFail {
				err = e0
				fmt.Fprintf(logFilePtr, "Error 406: %s %s\n", err, dbgo.LF())
				SetJSONHeaders(c)
				fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"error":%q,"location":%q}`, "Database Error", "Pre Processing call non-success status", dbgo.LF())
				c.Writer.WriteHeader(http.StatusNotAcceptable) // 406
				return
			}
		}
	}
	return
}

func RunPostFunctions(c *gin.Context, SPData CrudBaseConfig, inData string) (outData string, err error) {
	outData = inData
	for ii, px := range SPData.PostProc {
		fx, found := PrePostTab[px]
		cfg := ""
		if SPData.PostConfig != nil && ii < len(SPData.PostConfig) {
			cfg = SPData.PostConfig[ii]
		}
		if !found {
			fmt.Fprintf(os.Stderr, "Missing [%s][%s] post/func - no action taken - %s at %d\n", px, cfg, SPData.URIPath, ii)
			fmt.Fprintf(logFilePtr, "Missing [%s][%s] post/func - no action taken - %s at %d\n", px, cfg, SPData.URIPath, ii)
		} else {
			tmp, status, e1 := fx(c, PostFlag, cfg, outData)
			if status == OkDiscard {
				// Don't do anything
			} else if status == OkContinueSaveOutData {
				outData = tmp
			} else if status == ErrorFail {
				err = e1
				fmt.Fprintf(logFilePtr, "Error 406: %s %s\n", err, dbgo.LF())
				SetJSONHeaders(c)
				fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"error":%q,"location":%q}`, "Database Error", "Post Processing call non-success status", dbgo.LF())
				c.Writer.WriteHeader(http.StatusNotAcceptable) // 406
				return
			}
		}
	}
	return
}

// ------------------------------------------------------------------------------------------------------------------------------------------
func HandleStoredProcedureConfig(c *gin.Context, SPData *CrudStoredProcConfig) {

	method := MethodReplace(c)

	if err := RunPreFunctions(c, SPData.CrudBaseConfig); err != nil {
		return
	}

	dbgo.DbFprintf("HandleCRUD.SP", os.Stderr, "AT: %s%s%s \n", dbgo.ColorBlue, dbgo.LF(), dbgo.ColorReset)

	switch method {

	case "GET", "POST": // select
		// select <Name> ( $1 ... $n ) as "x"
		vals, inputData, err := GetStoredProcNames(c, SPData.ParameterList, SPData.StoredProcedureName, SPData.URIPath)
		dbgo.DbPrintf("HandleCRUD.SP", "AT: %s vals [%s] inputData %s err %s\n", dbgo.LF(), vals, dbgo.SVar(inputData), err)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error setting up call to %s error %s at %s\n", SPData.StoredProcedureName, err, dbgo.LF())
			return
		}
		stmt := fmt.Sprintf("select %s ( %s ) as \"x\"", SPData.StoredProcedureName, vals)
		stmt, inputData, _ = BindFixer(stmt, inputData)
		dbgo.DbPrintf("HandleCRUD.SP", "AT: %s stmt [%s] data=%s\n", dbgo.LF(), stmt, dbgo.SVar(inputData))
		var rawData string
		err = SQLQueryRowW(c, stmt, inputData...).Scan(&rawData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching return data from %s ->%s<- error %s at %s\n", SPData.StoredProcedureName, stmt, err, dbgo.LF())
			fmt.Fprintf(logFilePtr, "Error fetching return data from %s ->%s<- error %s at %s\n", SPData.StoredProcedureName, stmt, err, dbgo.LF())
			SetJSONHeaders(c)
			fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"error":%q,"location":%q}`, "Database Error", err, dbgo.LF())
			c.Writer.WriteHeader(http.StatusNotAcceptable) // 406
			e0 := fmt.Sprintf("Error fetching return data from %s ->%s<- error %s", SPData.StoredProcedureName, stmt, err)
			fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"location":%q}`, e0, dbgo.LF())
			return
		}
		var getStatus GetStatusType
		err = json.Unmarshal([]byte(rawData), &getStatus)
		if err != nil {
			fmt.Fprintf(logFilePtr, "Error 406: %s %s\n", err, dbgo.LF())
			SetJSONHeaders(c)
			fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"error":%q,"location":%q}`, "Database Error", err, dbgo.LF())
			c.Writer.WriteHeader(http.StatusNotAcceptable) // 406
			e0 := fmt.Sprintf("Error parsing return data ->%s<-form %s ->%s<- error %s", SPData.StoredProcedureName, stmt, rawData, err)
			fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"location":%q}`, e0, dbgo.LF())
			return
		}
		if getStatus.Status != "success" {
			if getStatus.HttpStatusCode != 0 {
				fmt.Fprintf(logFilePtr, "Error %v: %s\n", getStatus.HttpStatusCode, dbgo.LF())
				c.Writer.WriteHeader(getStatus.HttpStatusCode)
			} else {
				// xyzzy - TODO - shluld see if there is a "status_code" field - and if so use that for status code - else 406 status.
				fmt.Fprintf(logFilePtr, "Error 406: %s %s\n", err, dbgo.LF())
				c.Writer.WriteHeader(http.StatusNotAcceptable) // 406
			}
			if getStatus.Msg != "" {
				fmt.Fprintf(c.Writer, "%s", getStatus.Msg)
			}
			fmt.Fprintf(logFilePtr, "Error data ->%s<-form %s ->%s<- error %s at %s\n", SPData.StoredProcedureName, stmt, rawData, err, dbgo.LF())
			e0 := fmt.Sprintf("Error data ->%s<-form %s ->%s<- error %s", SPData.StoredProcedureName, stmt, rawData, err)
			SetJSONHeaders(c)
			fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"location":%q}`, e0, dbgo.LF())
			return
		}
		SetJSONHeaders(c)

		// rawData, err = RunPostFunctions(c, SPData.CrudBaseConfig, posInTable, rawData)
		rawData, err = RunPostFunctions(c, SPData.CrudBaseConfig, rawData)
		if err == nil {
			fmt.Fprintf(c.Writer, rawData)
		}
		return
	default:
		dbgo.DbPrintf("HandleCRUD.SP", "AT: %s method [%s]\n", dbgo.LF(), c.Request.Method)
		SetJSONHeaders(c)
		fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"location":%q}`, "Invalid Method", dbgo.LF())
		c.Writer.WriteHeader(http.StatusMethodNotAllowed) // 405
		return
	}

}

func HandleQueryConfig(c *gin.Context, QueryData *CrudQueryConfig) {

	method := MethodReplace(c)

	if err := RunPreFunctions(c, QueryData.CrudBaseConfig); err != nil {
		return
	}

	switch method {

	case "GET", "POST": // select
		inputData, err := GetQueryNames(c, QueryData.ParameterList, QueryData.QueryString, QueryData.URIPath)
		dbgo.DbPrintf("HandleCRUD.Query", "AT: %s inputData %s err %s\n", dbgo.LF(), dbgo.SVar(inputData), err)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error setting up call to %s error %s at %s\n", QueryData.QueryString, err, dbgo.LF())
			return
		}
		stmt := QueryData.QueryString
		stmt, inputData, _ = BindFixer(stmt, inputData)
		dbgo.DbPrintf("HandleCRUD.Query", "AT: %s stmt [%s] data=%s\n", dbgo.LF(), stmt, dbgo.SVar(inputData))

		if QueryData.IsUpdate {

			// func SQLUpdate(stmt string, data ...interface{}) (nr int, err error) {
			nr, err := SQLUpdateW(c, stmt, inputData...)

			if err != nil {
				fmt.Fprintf(os.Stderr, "Error updating data from %s ->%s<- error %s at %s\n", QueryData.QueryString, stmt, err, dbgo.LF())
				fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"error":%q,"location":%q}`, "Database Error", err, dbgo.LF())
				SetJSONHeaders(c)
				c.Writer.WriteHeader(http.StatusNotAcceptable) // 406
				return
			}

			dbgo.DbPrintf("HandleCRUD.Query", "%sAT: %s nr=%d%s\n", dbgo.ColorYellow, dbgo.LF(), nr, dbgo.ColorReset)
			SetJSONHeaders(c)

			rawData := fmt.Sprintf(`{"status":"success","n_rows":%d}`, nr)
			rawData, err = RunPostFunctions(c, QueryData.CrudBaseConfig, rawData)
			if err == nil {
				fmt.Fprintf(c.Writer, "%s", rawData)
			}
			return

		} else if QueryData.IsInsert || QueryData.IsDelete {

			err := SQLInsertW(c, stmt, inputData...)

			if err != nil {
				fmt.Fprintf(os.Stderr, "Error updating data from %s ->%s<- error %s at %s\n", QueryData.QueryString, stmt, err, dbgo.LF())
				SetJSONHeaders(c)
				fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"error":%q,"location":%q}`, "Database Error", err, dbgo.LF())
				c.Writer.WriteHeader(http.StatusNotAcceptable) // 406
				return
			}

			dbgo.DbPrintf("HandleCRUD.Query", "%sAT: %s %s\n", dbgo.ColorYellow, dbgo.LF(), dbgo.ColorReset)
			SetJSONHeaders(c)

			rawData := fmt.Sprintf(`{"status":"success"}`)
			rawData, err = RunPostFunctions(c, QueryData.CrudBaseConfig, rawData)
			if err == nil {
				fmt.Fprintf(c.Writer, "%s", rawData)
			}
			return

		} else { // select

			rows, err := SQLQueryW(c, stmt, inputData...)
			defer func() {
				if rows != nil && err == nil {
					rows.Close()
				}
			}()

			// ---------------------------------------------------------------------------------
			// CrudSubQueryConfig - Sub Queries
			// ---------------------------------------------------------------------------------
			//type CrudSubQueryConfig struct {
			//	BindValues []string // [ "id" ]
			//	To         string   // event_list - place to put the data result.
			//	QueryTmpl  string   // select * from "event" where "item_id" = $1 order by "seq"
			// }
			// ---------------------------------------------------------------------------------
			// OLD: data, _, _ := sizlib.RowsToInterface(rows)
			data, _, _ := RowsToInterface(rows)
			for ii, sq := range QueryData.SubQuery {
				for rn, row := range data {
					if theData, nonNull := NonNull(sq.BindValues, row); nonNull { // If al the bind values have values in the data.
						stmt1 := sq.QueryTmpl
						dbgo.DbPrintf("crud.520", "%s  - crud sub query - All Non Null at %d - run query ->%s<- data ->%s<-%s at:%s\n", dbgo.ColorYellow, ii, sq.QueryTmpl, theData, dbgo.LF(), dbgo.ColorReset)
						rows1, err1 := SQLQueryW(c, stmt1, theData...)
						if err1 != nil {
							fmt.Fprintf(os.Stderr, "Invaild Sub Query: %s data %s error %s\n", stmt1, theData, err1)
							continue
						}
						defer func() {
							if rows1 != nil && err1 == nil {
								rows1.Close()
							}
						}()
						// OLD: data1, _, _ := sizlib.RowsToInterface(rows1)
						data1, _, _ := RowsToInterface(rows1)
						row[sq.To] = data1
					} else {
						row[sq.To] = make([]map[string]interface{}, 0, 1)
					}
					data[rn] = row
				}
			}
			// ---------------------------------------------------------------------------------

			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching return data from %s ->%s<- error %s at %s\n", QueryData.QueryString, stmt, err, dbgo.LF())
				// xyzzy00000 - error check
				fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"error":%q,"location":%q}`, "Database Error", err, dbgo.LF())
				SetJSONHeaders(c)
				c.Writer.WriteHeader(http.StatusNotAcceptable) // 406
				return
			}

			dbgo.DbPrintf("HandleCRUD.Query", "%sAT: %s data ->%s<-%s\n", dbgo.ColorYellow, dbgo.LF(), dbgo.SVarI(data), dbgo.ColorReset)
			SetJSONHeaders(c)

			rawData := fmt.Sprintf(`{"status":"success","data":%s}`, dbgo.SVarI(data))
			rawData, err = RunPostFunctions(c, QueryData.CrudBaseConfig, rawData)
			if err == nil {
				fmt.Fprintf(c.Writer, "%s", rawData)
			}
			return
		}
		// return

	default:
		dbgo.DbPrintf("HandleCRUD.Query", "AT: %s method [%s]\n", dbgo.LF(), c.Request.Method)
		SetJSONHeaders(c)
		fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"location":%q}`, "Invalid Method", dbgo.LF())
		c.Writer.WriteHeader(http.StatusMethodNotAllowed) // 405
		return
	}

}

func NonNull(listCols []string, row map[string]interface{}) (rv []interface{}, nonNullFlag bool) { // If al the bind values have values in the data.
	for _, aCol := range listCols {
		dv, ok := row[aCol]
		if !ok { // not found
			return
		}
		fmt.Printf("%saCol[%s] data=[%v]%s\n", dbgo.ColorYellow, aCol, dv, dbgo.ColorReset)
		s := fmt.Sprintf("%v", dv)
		if len(s) == 0 {
			return
		}
		rv = append(rv, dv)
	}
	nonNullFlag = true
	return
}

func HandleCRUDPerTableRequests(c *gin.Context, CrudData *CrudConfig) {

	dbgo.DbPrintf("dump.gCfg", "%sAT %s gCfg=%s%s\n", dbgo.ColorCyan, dbgo.LF(), dbgo.SVarI(gCfg), dbgo.ColorReset)
	dbgo.DbPrintf("HandleCrudConfig", "Top of HandleCrudConfig: AT: %s\n", dbgo.LF())

	method := MethodReplace(c)

	dbgo.DbPrintf("HandleCrudConfig", "  AT: %s\n", dbgo.LF())
	if err := RunPreFunctions(c, CrudData.CrudBaseConfig); err != nil {
		return
	}

	if !InArray(method, CrudData.MethodsAllowed) {
		SetJSONHeaders(c)
		fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"location":%q}`, "Invalid Method", dbgo.LF())
		c.Writer.WriteHeader(http.StatusMethodNotAllowed) // 405
		return
	}

	dbgo.DbPrintf("HandleCrudConfig", "  AT: %s\n", dbgo.LF())
	// fmt.Printf("%sAT AT:%s%s\n", dbgo.ColorCyan, dbgo.LF(), dbgo.ColorReset)
	var nr int

	switch method {

	case "GET": // select
		dbgo.DbPrintf("HandleCrudConfig", "  %(yellow) -- From HandleCrudConfig Flag -- AT: %s\n", dbgo.LF())
		var data []map[string]interface{}
		// if "id" - then pull just id, else select all from...
		found_id, id := GetVar(IfEmpty(CrudData.SelectPkCol, "id"), c)
		dbgo.DbPrintf("HandleCRUD", "  %(red) -- From HandleCRUD -- AT: %s found_id %v id [%s]\n", dbgo.LF(), found_id, id)
		if found_id {
			stmt := fmt.Sprintf("select %s from %q where ( \"%s\" = $1 ) ", GenProjected(CrudData.ProjectedCols), CrudData.TableName, IfEmpty(CrudData.SelectPkCol, "id"))

			bindColData := []interface{}{id}
			if len(CrudData.UseRLS) > 0 {
				addStmt := AppendWhereUseRLS(2, CrudData.UseRLS)
				for _, col := range CrudData.UseRLS {
					xcol := col.ContextValueName
					ok, val := GetVar(xcol, c)
					dbgo.Printf("%(red)FoundCol/InlineCRUD: col/xcol [%s][%s] ok=%v val= ->%s<- AT: %(LF)\n", col, xcol, ok, val)
					if ok {
						fmt.Printf("           FoundCol: col [%s] AT: %s\n", col, dbgo.LF())
						bindColData = append(bindColData, val)
					}
				}
				stmt += addStmt
			}
			dbgo.DbPrintf("HandleCRUD", "AT: %s stmt(Where Generated) [%s] data=%s\n", dbgo.LF(), stmt, dbgo.SVar(bindColData))
			rows, err := SQLQueryW(c, stmt, bindColData)
			defer func() {
				if rows != nil && err == nil {
					rows.Close()
				}
			}()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching from %s ->%s<- error %s at %s\n", CrudData.TableName, stmt, err, dbgo.LF())
				SetJSONHeaders(c)
				fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"error":%q,"location":%q}`, "Database Error", err, dbgo.LF())
				c.Writer.WriteHeader(http.StatusNotAcceptable) // 406
				return
			}
			// data, _, _ = sizlib.RowsToInterface(rows)
			data, _, _ = RowsToInterface(rows)

		} else if cols, bindColData, found := FoundCol(c, CrudData.WhereCols, CrudData.UseRLS); found {
			// maybee - page-ing should occure at this point!!
			stmt := fmt.Sprintf("select %s from %q where %s", GenProjected(CrudData.ProjectedCols), CrudData.TableName, GenWhere(cols, CrudData.KeywordKeyColumn, CrudData.TableName, CrudData.UseRLS)) // xyzzy TODO - generate order by at end!
			if HasOrderByList(c) {                                                                                                                                                                      // xyzzy - TODO - should be a add-on to existing queries for order, not a different query -- this is an error
				// orderBy, err := GenOrderBy(c, CrudData, posInTable, gCfg)
				orderBy, err := GenOrderBy(c, CrudData)
				if err != nil {
					orderBy = ""
				} else {
					stmt += " order by " + orderBy
				}
			}
			dbgo.DbPrintf("HandleCRUD", "AT: %s stmt(Where Generated) [%s] data=%s\n", dbgo.LF(), stmt, dbgo.SVar(bindColData))
			rows, err := SQLQueryW(c, stmt, bindColData...)
			defer func() {
				if rows != nil && err == nil {
					rows.Close()
				}
			}()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching from %s ->%s<- error %s at %s\n", CrudData.TableName, stmt, err, dbgo.LF())
				fmt.Fprintf(logFilePtr, "Error fetching from %s ->%s<- error %s at %s\n", CrudData.TableName, stmt, err, dbgo.LF())
				fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"error":%q,"location":%q}`, "Database Error", err, dbgo.LF())
				c.Writer.WriteHeader(http.StatusNotAcceptable) // 406
				return
			}
			// fmt.Printf("%sAT: %s%s\n", dbgo.ColorYellow, dbgo.LF(), dbgo.ColorReset)
			// data, _, _ = sizlib.RowsToInterface(rows)
			data, _, _ = RowsToInterface(rows)

		} else if HasOrderByList(c) { // xyzzy - TODO - should be a add-on to existing queries for order, not a different query -- this is an error

			// bindColData := []interface{}{id}
			bindColData := []interface{}{}
			where := ""
			if len(CrudData.UseRLS) > 0 {
				addStmt := AppendWhereUseRLS(1, CrudData.UseRLS)
				for _, col := range CrudData.UseRLS {
					xcol := col.ContextValueName
					ok, val := GetVar(xcol, c)
					dbgo.Printf("%(red)FoundCol/InlineCRUD: col/xcol [%s][%s] ok=%v val= ->%s<- AT: %(LF)\n", col, xcol, ok, val)
					if ok {
						fmt.Printf("           FoundCol: col [%s] AT: %s\n", col, dbgo.LF())
						bindColData = append(bindColData, val)
					}
				}
				where = " where " + addStmt
			}
			orderBy, err := GenOrderBy(c, CrudData)
			if err != nil {
				return
			}
			stmt := fmt.Sprintf("select %s from %q %s order by %s", GenProjected(CrudData.ProjectedCols), CrudData.TableName, where, orderBy)
			dbgo.DbPrintf("HandleCRUD", "AT: %s stmt(Where Generated, With order by) [%s] data=%s\n", dbgo.LF(), stmt, dbgo.SVar(bindColData))
			if len(bindColData) > 0 {
				rows, err := SQLQueryW(c, stmt, bindColData)
				defer func() {
					if rows != nil && err == nil {
						rows.Close()
					}
				}()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error fetching from %s ->%s<- error %s at %s\n", CrudData.TableName, stmt, err, dbgo.LF())
					fmt.Fprintf(logFilePtr, "Error fetching from %s ->%s<- error %s at %s\n", CrudData.TableName, stmt, err, dbgo.LF())
					SetJSONHeaders(c)
					fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"error":%q,"location":%q}`, "Database Error", err, dbgo.LF())
					c.Writer.WriteHeader(http.StatusNotAcceptable) // 406
					return
				}
				data, _, _ = RowsToInterface(rows)
			} else {
				rows, err := SQLQueryW(c, stmt)
				defer func() {
					if rows != nil && err == nil {
						rows.Close()
					}
				}()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error fetching from %s ->%s<- error %s at %s\n", CrudData.TableName, stmt, err, dbgo.LF())
					fmt.Fprintf(logFilePtr, "Error fetching from %s ->%s<- error %s at %s\n", CrudData.TableName, stmt, err, dbgo.LF())
					SetJSONHeaders(c)
					fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"error":%q,"location":%q}`, "Database Error", err, dbgo.LF())
					c.Writer.WriteHeader(http.StatusNotAcceptable) // 406
					return
				}
				data, _, _ = RowsToInterface(rows)
			}

		} else if CrudData.SelectRequiresWhere { // If true, then were must be specified - can not do a full-table below.
			dbgo.DbPrintf("HandleCRUD", "AT: %s method [%s]\n", dbgo.LF(), c.Request.Method)
			SetJSONHeaders(c)
			fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"location":%q}`, "Select Requries a 'where' Clause", dbgo.LF())
			c.Writer.WriteHeader(http.StatusNotAcceptable) // 406
			return

		} else {

			bindColData := []interface{}{id}
			where := ""
			if len(CrudData.UseRLS) > 0 {
				addStmt := AppendWhereUseRLS(1, CrudData.UseRLS)
				for _, col := range CrudData.UseRLS {
					xcol := col.ContextValueName
					ok, val := GetVar(xcol, c)
					dbgo.Printf("%(red)FoundCol/InlineCRUD: col/xcol [%s][%s] ok=%v val= ->%s<- AT: %(LF)\n", col, xcol, ok, val)
					if ok {
						fmt.Printf("           FoundCol: col [%s] AT: %s\n", col, dbgo.LF())
						bindColData = append(bindColData, val)
					}
				}
				where = " where " + addStmt
			}

			// page-ing should occure at this point!!			___page__ and page-size will be needed
			stmt := fmt.Sprintf("select %s from %q %s", GenProjected(CrudData.ProjectedCols), CrudData.TableName, where)
			dbgo.DbPrintf("HandleCRUD", "AT: %s stmt(Where Generated, Original) [%s] data=%s\n", dbgo.LF(), stmt, dbgo.SVar(bindColData))

			//			if HasOrderByList(c) {
			//				orderBy, err := GenOrderBy(c, CrudData)
			//				if err != nil {
			//					return
			//				}
			//				stmt += fmt.Sprintf(" order by %ss", orderBy)
			//			}

			dbgo.DbPrintf("HandleCRUD", "AT: %s stmt(Where Generated, After Order By Added) [%s] data=%s\n", dbgo.LF(), stmt, dbgo.SVar(bindColData))
			if where == "" {
				rows, err := SQLQueryW(c, stmt)
				defer func() {
					if rows != nil && err == nil {
						rows.Close()
					}
				}()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error fetching from %s ->%s<- error %s at %s\n", CrudData.TableName, stmt, err, dbgo.LF())
					fmt.Fprintf(logFilePtr, "Error fetching from %s ->%s<- error %s at %s\n", CrudData.TableName, stmt, err, dbgo.LF())
					SetJSONHeaders(c)
					fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"error":%q,"location":%q}`, "Database Error", err, dbgo.LF())
					c.Writer.WriteHeader(http.StatusNotAcceptable) // 406
					return
				}
				data, _, _ = RowsToInterface(rows)
			} else {
				rows, err := SQLQueryW(c, stmt, bindColData)
				defer func() {
					if rows != nil && err == nil {
						rows.Close()
					}
				}()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error fetching from %s ->%s<- error %s at %s\n", CrudData.TableName, stmt, err, dbgo.LF())
					fmt.Fprintf(logFilePtr, "Error fetching from %s ->%s<- error %s at %s\n", CrudData.TableName, stmt, err, dbgo.LF())
					SetJSONHeaders(c)
					fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"error":%q,"location":%q}`, "Database Error", err, dbgo.LF())
					c.Writer.WriteHeader(http.StatusNotAcceptable) // 406
					return
				}
				// data, _, _ = sizlib.RowsToInterface(rows)
				data, _, _ = RowsToInterface(rows)
			}
		}
		dbgo.DbPrintf("HandleCRUD", "%sAT: %s data ->%s<-%s\n", dbgo.ColorYellow, dbgo.LF(), dbgo.SVarI(data), dbgo.ColorReset)

		// xyzzy21334 -- output format
		var err error
		ContentType := "application/json; charset=utf-8"
		var rawData string
		RDFmtFound, RDFmt := GetVar("__rdfmt__", c)
		if RDFmtFound {
			if IsTLS(c) {
				c.Writer.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}
			SetCORSHeaders(c)
			ss := strings.Split(RDFmt, ",")
			for _, aa := range ss {
				switch aa {
				case "":
					rawData = fmt.Sprintf(`{"status":"success","data":%s}`, dbgo.SVarI(data))
				case "array":
					rawData = fmt.Sprintf(`%s`, dbgo.SVarI(data))
				case "AsJS":
					ContentType = "text/javascript; charset=utf-8"
					Name_found, Name := GetVar("__rdata_name__", c)
					if !Name_found || Name == "" {
						Name = "Name"
					}
					rawData = fmt.Sprintf(`var %s = {"status":"success","data":%s};`, Name, dbgo.SVarI(data))
				case "AsJSWindow":
					ContentType = "text/javascript; charset=utf-8"
					Name_found, Name := GetVar("__rdata_name__", c)
					if !Name_found || Name == "" {
						Name = "Name"
					}
					rawData = fmt.Sprintf(`window.%s = {"status":"success","data":%s};`+"\n\n", Name, dbgo.SVarI(data))
				case "AsJSWindowData":
					ContentType = "text/javascript; charset=utf-8"
					Name_found, Name := GetVar("__rdata_name__", c)
					if !Name_found || Name == "" {
						Name = "Name"
					}
					rawData = fmt.Sprintf(`window.%s = %s;`+"\n\n", Name, dbgo.SVarI(data))
				case "AsTEXT":
					ContentType = "text/plain; charset=utf-8"
				case "PreFix", "PreFix2":
				default:
					err = fmt.Errorf("Invalid __rdfmt__ value of %s, shold be '', array, AsJS, AsTEXT", aa)
					rawData = fmt.Sprintf(`{"status":"error","msg":%q,"location":%q}`, err, dbgo.LF())
					break
				}
			}
			c.Writer.Header().Set("Content-Type", ContentType)
		} else {
			SetJSONHeaders(c)
			rawData = fmt.Sprintf(`{"status":"success","data":%s}`, dbgo.SVarI(data))
		}

		if err != nil {
			rawData, err = RunPostFunctions(c, CrudData.CrudBaseConfig, rawData) // xyzzy - should have extra params fro RDFmt, RDFmtFound
		}

		if RDFmtFound {
			ss := strings.Split(RDFmt, ",")
			for _, aa := range ss {
				switch aa {
				case "PreFix":
					rawData = "while(1);" + rawData
				case "PreFix2":
					rawData = "for(;;);" + rawData
				case "AsTEXT":
					ContentType = "text/plain; charset=utf-8"
					//default:
					//	err = fmt.Errorf("Invalid __rdfmt__ value of %s, shold be '', array, AsJS, AsTEXT", aa)
					//	rawData = fmt.Sprintf(`{"status":"error","msg":%q}`, err)
					//	break
				}
			}
			c.Writer.Header().Set("Content-Type", ContentType)
		} else {
			SetJSONHeaders(c)
			rawData = fmt.Sprintf(`{"status":"success","data":%s}`, dbgo.SVarI(data))
		}

		if err != nil {
			rawData, err = RunPostFunctions(c, CrudData.CrudBaseConfig, rawData) // xyzzy - should have extra params fro RDFmt, RDFmtFound
		}

		if RDFmtFound {
			ss := strings.Split(RDFmt, ",")
			for _, aa := range ss {
				switch aa {
				case "PreFix":
					rawData = "while(1);" + rawData
				case "PreFix2":
					rawData = "for(;;);" + rawData
				}
			}
		}

		if err == nil {
			fmt.Fprintf(c.Writer, "%s", rawData)
		} else {
			err := fmt.Errorf("Error occured on %s error %s at %s\n", CrudData.TableName, err, dbgo.LF())
			fmt.Fprintf(logFilePtr, "%s", err)
			SetJSONHeaders(c)
			fmt.Fprintf(c.Writer, `{"status":"error":"msg":%q,"location":%q}`, err, dbgo.LF())
			c.Writer.WriteHeader(http.StatusNotAcceptable) // 406
		}
		return

	case "POST": // insert
		dbgo.DbPrintf("HandleCrudConfig", "  AT: %s\n", dbgo.LF())

		cols, vals, inputData, id, genIdOnInsert, idColName, err := GetInsertNames(c, CrudData.InsertCols, CrudData.InsertPkCol, CrudData.ColsTypes, CrudData.ParameterList)
		dbgo.DbPrintf("HandleCRUD", "%(yellow)AT: %s cols [%s] vals [%s] inputData %s id %s err %s\n", dbgo.LF(), cols, vals, dbgo.SVar(inputData), id, err)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error setting up insert %s error %s at %s\n", CrudData.TableName, err, dbgo.LF())
			return
		}
		stmt := fmt.Sprintf("insert into %q ( %s ) values ( %s )", CrudData.TableName, cols, vals)
		stmt2, inputData2, _ := BindFixer(stmt, inputData)
		dbgo.DbPrintf("HandleCRUD", "%(yellow)AT: %s stmt [%s] data=%s\n", dbgo.LF(), stmt2, dbgo.SVar(inputData2))
		var xid int64
		if genIdOnInsert {
			if DbType == "Postgres" {
				stmt2 = stmt2 + fmt.Sprintf(" returning %s ", idColName)
			}
			xid, err = SQLInsertIdW(c, stmt2, inputData2...)
		} else {
			err = SQLInsertW(c, stmt2, inputData2...)
		}
		dbgo.DbPrintf("HandleCRUD", "New %(yellow)After!!!! AT: %s stmt [%s] data=%s err=%s\n", dbgo.LF(), stmt2, dbgo.SVar(inputData2), err)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error inserting to %s ->%s<- error %s at %s\n", CrudData.TableName, stmt, err, dbgo.LF())
			fmt.Fprintf(logFilePtr, "Error inserting to %s ->%s<- error %s at %s\n", CrudData.TableName, stmt, err, dbgo.LF())
			// xyzzy5 - TODO - Must have error text returned. -- this is a general error - all error returns must have a message.
			SetJSONHeaders(c)
			fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"location":%q}`, "Error inserting data.", dbgo.LF())
			c.Writer.WriteHeader(http.StatusNotAcceptable) // 406
			return
		}
		SetJSONHeaders(c)
		var rawData string
		if genIdOnInsert {
			rawData = fmt.Sprintf(`{"status":"success","id":%d}`, xid)
		} else {
			rawData = fmt.Sprintf(`{"status":"success","id":%q}`, id)
		}
		// rawData, err = RunPostFunctions(c, CrudData.CrudBaseConfig, posInTable, rawData)
		rawData, err = RunPostFunctions(c, CrudData.CrudBaseConfig, rawData)
		if err == nil {
			fmt.Fprintf(c.Writer, "%s", rawData)
		}
		return

	case "PUT": // update / insert
		dbgo.DbPrintf("HandleCRUD", "AT: %s Config: %s\n", dbgo.LF(), dbgo.SVarI(CrudData))

		updCols, inputData, id, err := GetUpdateNames(c, CrudData.UpdateCols, CrudData.UpdatePkCol, CrudData.ColsTypes)
		dbgo.DbPrintf("HandleCRUD", "AT: %s updCols [%s] inputData %s id %s err %s\n", dbgo.LF(), updCols, dbgo.SVar(inputData), id, err)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error setting up update %s error %s at %s\n", CrudData.TableName, err, dbgo.LF()) // TODO - table-name
			return
		}
		// UpdatePkCol:    "role_id",
		stmt := fmt.Sprintf("update %q set %s where \"%s\" = $1", CrudData.TableName, updCols, IfEmpty(CrudData.UpdatePkCol, "id"))
		stmt, inputData, _ = BindFixer(stmt, inputData)
		dbgo.DbPrintf("HandleCRUD", "AT: %s stmt [%s] data=%s\n", dbgo.LF(), stmt, dbgo.SVar(inputData))
		nr, err = SQLUpdateW(c, stmt, inputData...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error updating %s ->%s<- error %s at %s\n", CrudData.TableName, stmt, err, dbgo.LF())
			fmt.Fprintf(logFilePtr, "Error updating %s ->%s<- error %s at %s\n", CrudData.TableName, stmt, err, dbgo.LF())
			SetJSONHeaders(c)
			fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"error":%q,"location":%q}`, "Database Error", err, dbgo.LF())
			c.Writer.WriteHeader(http.StatusNotAcceptable) // 406
			return
		}
		SetJSONHeaders(c)
		rawData := fmt.Sprintf(`{"status":"success","id":%q,"nr":%d}`, id, nr)
		rawData, err = RunPostFunctions(c, CrudData.CrudBaseConfig, rawData)
		if err == nil {
			fmt.Fprintf(c.Writer, "%s", rawData)
		}
		return

	case "DELETE": // delete
		dbgo.DbPrintf("HandleCrudConfig", "  AT: %s\n", dbgo.LF())
		fmt.Printf("%sAT AT:%s%s\n", dbgo.ColorCyan, dbgo.LF(), dbgo.ColorReset)
		var nr int
		var err error
		found_id, id := GetVar(IfEmpty(CrudData.SelectPkCol, "id"), c)
		fmt.Printf("%sAT AT:%s%s\n", dbgo.ColorCyan, dbgo.LF(), dbgo.ColorReset)
		if found_id {
			// UpdatePkCol:    "role_id",
			stmt := fmt.Sprintf("delete from %q where \"%s\" = $1", CrudData.TableName, IfEmpty(CrudData.DeletePkCol, "id"))
			dbgo.DbPrintf("HandleCRUD", "AT: %s stmt [%s] id=%s\n", dbgo.LF(), stmt, id)
			dbgo.DbFprintf("HandleCRUD", os.Stderr, "AT: %s stmt [%s] id=%s\n", dbgo.LF(), stmt, id)
			nr, err = SQLUpdateW(c, stmt, id)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error deleting from %s stmt ->%s<- id ->%s<- error %s at %s\n", CrudData.TableName, stmt, id, err, dbgo.LF())
				fmt.Fprintf(logFilePtr, "Error updating %s ->%s<- error %s at %s\n", CrudData.TableName, stmt, err, dbgo.LF())
				SetJSONHeaders(c)
				fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"error":%q,"location":%q}`, "Database Error", err, dbgo.LF())
				c.Writer.WriteHeader(http.StatusNotAcceptable) // 406
				return
			}
			fmt.Printf("%sAT AT:%s nr=%d%s\n", dbgo.ColorCyan, dbgo.LF(), nr, dbgo.ColorReset)
			fmt.Fprintf(logFilePtr, "%sAT AT:%s nr=%d%s\n", dbgo.ColorCyan, dbgo.LF(), nr, dbgo.ColorReset)
		} else {
			fmt.Fprintf(logFilePtr, "DELETE %s - missking primary key info (%s) at:%s\n", c.Request.RequestURI, "id", dbgo.LF())
			SetJSONHeaders(c)
			fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"location":%q}`, "Missing key field (probably primary key)", dbgo.LF())
			c.Writer.WriteHeader(http.StatusBadRequest) // 400
			return
		}
		SetJSONHeaders(c)
		rawData := fmt.Sprintf(`{"status":"success","nr":%d}`, nr)
		rawData, err = RunPostFunctions(c, CrudData.CrudBaseConfig, rawData)
		if err == nil {
			fmt.Fprintf(c.Writer, "%s", rawData)
		}
		return

	default:
		dbgo.DbPrintf("HandleCrudConfig", "  AT: %s\n", dbgo.LF())
		dbgo.DbPrintf("HandleCRUD", "AT: %s method [%s]\n", dbgo.LF(), c.Request.Method)
		SetJSONHeaders(c)
		fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"location":%q}`, "Invalid Method", dbgo.LF())
		c.Writer.WriteHeader(http.StatusMethodNotAllowed) // 405
		return
	}

}

func HasOrderByList(c *gin.Context) bool {
	found, val := GetVar("__order_by__", c)
	if found && val != "" {
		dbgo.DbPrintf("HandleCRUD.GenOrderBy", "%(Cyan)%(LF) found __order_by__ \n")
		return true
	}
	return false
}

// xyzzy5050 TODO - order by - change to Name, Name Desc, Name Asc
// xyzzy5050 - TODO - need document format for __order_by__
//
//	a, b
//	a, -b
//	1, -b etc.
//	1 asc, b desc etc.
//	1 asc, "b" desc etc.
//
// xyzzy5050 - TODO - add this to "view-query" pre defined??? - if so how
// xyzzy5050 - TODO - JSON format for this [c1,c2,...] - then just parse JSON strings
// xyzzy5050 - TODO - __where__=[{"col":"name","op":,"val":}] => ["col":"name","ord":"asc|desc"]
func GenOrderBy(c *gin.Context, CrudData *CrudConfig) (rv string, err error) {
	_, val := GetVar("__order_by__", c)
	ParsedCols, ColExpr := ParserOrderBy(val, c, CrudData)
	orderByStmt := ""
	com := ""
	for ii, col := range ParsedCols {
		if !InArray(col, CrudData.OrderByCols) {
			fmt.Fprintf(logFilePtr, "ORDER BY %s - invalid column (%s) must be one of (%s) at:%s\n", c.Request.RequestURI, col, CrudData.OrderByCols, dbgo.LF())
			SetJSONHeaders(c)
			fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"error":%q,"location":%q}`, "Database Error", err, dbgo.LF())
			c.Writer.WriteHeader(http.StatusBadRequest) // 400
			err = fmt.Errorf("Invalid Order By Column %s, must be one of %s", col, CrudData.OrderByCols)
			return
		}
		orderByStmt = orderByStmt + com + ColExpr[ii]
		com = ", "
	}
	dbgo.DbPrintf("HandleCRUD.GenOrderBy", "%(Cyan)%(LF) order by [%s]\n", orderByStmt)
	return orderByStmt, nil
}

func ParserOrderBy(val string, c *gin.Context, CrudData *CrudConfig) (p, e []string) {
	p = strings.Split(val, ",")
	e = p // temporary - to test, if col is 1 then should looup list of coluns and replace w/ appropariate.  also ASC v.s. DESC
	return
}

// cols, colsData, found := FoundCol ( c, CrudData.WhereCols )
// Used in  } else if cols, colsData, found := FoundCol(c, CrudData.WhereCols, CrudData.UseRLS); found {
func FoundCol(c *gin.Context, WhereCols []string, UseRLS []RLSColumns) (cols []string, colsData []interface{}, found bool) {
	if len(WhereCols) == 0 {
		return
	}
	for _, col := range WhereCols {
		ok, val := GetVar(col, c)
		dbgo.Printf("%(red)FoundCol: col [%s] ok=%v val= ->%s<- AT: %(LF)\n", col, ok, val)
		if ok {
			// fmt.Printf("FoundCol: col [%s] AT: %s\n", col, dbgo.LF())
			found = true
			cols = append(cols, col)
			colsData = append(colsData, val)
		}
	}
	if ok, val := GetVar("__keyword__", c); ok {
		found = true
		cols = append(cols, "__keyword__")
		colsData = append(colsData, val)
	}
	for _, col := range UseRLS {
		xcol := col.ContextValueName
		ok, val := GetVar(xcol, c)
		dbgo.Printf("%(red)FoundCol: col/xcol [%s][%s] ok=%v val= ->%s<- AT: %(LF)\n", col, xcol, ok, val)
		if ok {
			fmt.Printf("           FoundCol: col [%s] AT: %s\n", col, dbgo.LF())
			found = true
			// cols = append(cols, col)
			colsData = append(colsData, val)
		}
	}
	return
}

// GenWhere(cols) generates the WHERE clause for a table.   Used in `func HandleCRUDPerTableRequests(c *gin.Context, CrudData *CrudConfig) {`
// this also handles the case where we havve specifed a __keyword__ column for full text search and adds in the and user_id=$1 for RLS.
func GenWhere(cols []string, KeywordKeyColumn, TableName string, UseRLS []RLSColumns) string {
	if len(cols) == 0 {
		return ""
	}
	com := ""
	var b bytes.Buffer
	foo := bufio.NewWriter(&b)
	fmt.Fprintf(foo, " ( ")
	dd := 1
	for _, ss := range cols {
		if ss == "__keyword__" {
			///ss = "item_tokens"
			// KeywordSearch:    []string{"item"},
			// KeywordKeyColumn: "item_tokens",
			ss = KeywordKeyColumn
			if ss == "" {
				// report error
				fmt.Fprintf(logFilePtr, "table did not have a keyword search column setup - this is an automatic false.  table_name=%s", TableName)
				fmt.Fprintf(foo, "%s1 = 2", com) // always false
			} else {
				fmt.Fprintf(foo, "%s%q @@ $%d", com, ss, dd)
			}
		} else {
			fmt.Fprintf(foo, "%s%q = $%d", com, ss, dd)
		}
		com = " and "
		dd++
	}
	fmt.Fprintf(foo, " ) ")
	for _, ss := range UseRLS {
		fmt.Fprintf(foo, "%s%q = $%d", com, ss.ColumnName, dd)
		com = " and "
		dd++
	}
	foo.Flush()
	where := b.String()
	dbgo.DbPrintf("HandleCRUD.GenWhere", "%(Cyan)%(LF) where [%s]\n", where)
	return where

}

// addStmt := AppendWhereUseRLS ( CrudData.UseRLS )
func AppendWhereUseRLS(dd int, UseRLS []RLSColumns) string {
	if len(UseRLS) == 0 {
		return ""
	}
	com := " and "
	var b bytes.Buffer
	foo := bufio.NewWriter(&b)
	for _, ss := range UseRLS {
		fmt.Fprintf(foo, "%s%q = $%d", com, ss.ColumnName, dd)
		com = " and "
		dd++
	}
	foo.Flush()
	where := b.String()
	dbgo.DbPrintf("HandleCRUD.GenWhere", "%(Cyan)%(LF) where [%s]\n", where)
	return where
}

func GenProjected(ProjectedCols []string) (rv string) {
	if len(ProjectedCols) == 0 {
		return "*"
	}
	rv = ""
	com := ""
	var b bytes.Buffer
	foo := bufio.NewWriter(&b)
	for _, ss := range ProjectedCols {
		fmt.Fprintf(foo, "%s%q", com, ss)
		com = ", "
	}
	foo.Flush()
	return b.String()
}

func GetQueryNames(c *gin.Context, potentialCols []ParamListItem, StoredProcdureName, URIPath string) (inputData []interface{}, err error) {
	inputData = make([]interface{}, 0, len(potentialCols))
	for _, col := range potentialCols {
		colName := col.ReqVar
		found, colVal := GetVar(colName, c)
		if col.AutoGen == "uuid" && !found {
			colVal = GenUUID()
			/*
				newUUID, err1 := uuid.NewV4()
				err = err1
				if err != nil {
					err = fmt.Errorf("An error occurred generating a UUID: %s", err)
					fmt.Fprintf(os.Stderr, "Error %s", err)
					fmt.Fprintf(logFilePtr, "Error 500: %s %s\n", err, dbgo.LF())
					c.Writer.WriteHeader(http.StatusInternalServerError) // 500
					return
				}
				colVal = newUUID.String()
			*/
		} else if len(col.AutoGen) > 4 && col.AutoGen[0:4] == "ran:" && !found {
			// xyzzy - TODO - xyzzy401 - generate random (number after ran:)
		} else if len(col.AutoGen) > 4 && col.AutoGen[0:4] == "seq:" && !found {
			// xyzzy - TODO - xyzzy401 - fetch from seq in database. name after seq:
		} else if !found && col.Required {
			err = fmt.Errorf("Missing %s in call to %s - endpoint %s", colName, StoredProcdureName, URIPath)
			fmt.Fprintf(os.Stderr, "Error %s", err)
			fmt.Fprintf(logFilePtr, "Error 500: %s, %s\n", err, dbgo.LF())
			fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"location":%q}`, fmt.Sprintf("Database Error: required name(%s) in query is missing", col.Required), dbgo.LF())
			SetJSONHeaders(c)
			c.Writer.WriteHeader(http.StatusInternalServerError) // 500
			return
		}

		inputData = append(inputData, colVal)
	}
	return
}

/*
   type ParamListItem struct {
   	ReqVar    string // variable for GetVar()
   	ParamName string // Name of variable (Info Only)
   	AutoGen   bool
	Required  bool
   }
   type CrudStoredProcConfig struct {
   	URIPath             string          // Path that will reach this end point
   	AuthKey             bool            // Require an auth_key
   	JWTKey              bool            // Require a JWT token authentntication header
   	StoredProcedureName string          // Name of stored procedure to call.
   	TableNameList       []string        // table name update/used in call (Info Only)
   	ParameterList       []ParamListItem // Pairs of values
   }
*/
// vals, inputData, id, err := GetStoredProcNames(c, SPData.ParameterList, SPData.StoredProcedureName, SPData.URIPath)
func GetStoredProcNames(c *gin.Context, potentialCols []ParamListItem, StoredProcdureName, URIPath string) (vals string, inputData []interface{}, err error) {
	inputData = make([]interface{}, 0, len(potentialCols))
	nc := 1
	com := ""
	for _, col := range potentialCols {
		colName := col.ReqVar
		found, colVal := GetVar(colName, c)
		if col.AutoGen == "uuid" && !found {
			colVal = GenUUID()
			/*
				newUUID, err1 := uuid.NewV4()
				err = err1
				if err != nil {
					err = fmt.Errorf("An error occurred generating a UUID: %s", err)
					fmt.Fprintf(os.Stderr, "Error %s", err)
					fmt.Fprintf(logFilePtr, "Error 500: %s %s\n", err, dbgo.LF())
					c.Writer.WriteHeader(http.StatusInternalServerError) // 500
					return
				}
				colVal = newUUID.String()
			*/
		} else if len(col.AutoGen) > 4 && col.AutoGen[0:4] == "ran:" && !found {
			// xyzzy - TODO - xyzzy401 - generate random (number after ran:)
		} else if len(col.AutoGen) > 4 && col.AutoGen[0:4] == "seq:" && !found {
			// xyzzy - TODO - xyzzy401 - fetch from seq in database. name after seq:
		} else if !found && col.Required {
			err = fmt.Errorf("Missing %s in call to %s - endpoint %s", colName, StoredProcdureName, URIPath)
			fmt.Fprintf(os.Stderr, "Error %s", err)
			fmt.Fprintf(logFilePtr, "Error 500: %s %s\n", err, dbgo.LF())
			SetJSONHeaders(c)
			fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"error":%q,"location":%q}`, "Database Error", fmt.Sprintf("Missing reqired column (%s)", col.Required), dbgo.LF())
			c.Writer.WriteHeader(http.StatusInternalServerError) // 500
			return
		}

		inputData = append(inputData, colVal)
		vals += fmt.Sprintf("%s$%d", com, nc)
		nc++
		com = ", "
	}
	return
}

//	ColsTypes           []CrudColTypeData `json:"ColsTypes"`           // Type of columns for thins like 'box'
//			cols, vals, inputData, id, err := GetInsertNames(c, CrudData.InsertCols, CrudData.InsertPkCol, CruData.ColsTypes)

// GetInsertNames returns the list of columns for an insert, the list of placeholders for PG substitution of values,
// the list of values, the primary key or an error.
func GetInsertNames(c *gin.Context, potentialCols []string, pkCol string, colTypes []CrudColTypeData, parameterList []ParamListItem) (cols, vals string, inputData []interface{}, id string, genId bool, idColName string, err error) {
	inputData = make([]interface{}, 0, len(potentialCols))
	colsSlice := make([]string, 0, len(potentialCols))
	valsSlice := make([]string, 0, len(potentialCols))
	nc := 1
	iddt, _ /*idseq*/, idfound := FindDataType(pkCol, colTypes)
	if idfound && (iddt == "serial" || iddt == "bigserial") {
		idColName = pkCol
		genId = true
		dbgo.Printf("%(cyan)%(LF) serial/bigsearial %+v\n", pkCol)
	} else if idfound && iddt == "gen-uuid" {
		idColName = pkCol
		found_pk, pk := GetVar(pkCol, c)
		if !found_pk || pk == "" {
			pk = GenUUID()
		}
		id = pk
		inputData = append(inputData, pk)
		colsSlice = append(colsSlice, pkCol)
		valsSlice = append(valsSlice, fmt.Sprintf("$%d", nc))
		nc++
		dbgo.Printf("%(cyan)%(LF) gen-uuid %+v, generated/used id = %s\n", pkCol, id)
	} else {
		idColName = pkCol
		found_pk, pk := GetVar(pkCol, c)
		if !found_pk {
			pk = ""
		}
		id = pk
		inputData = append(inputData, pk)
		colsSlice = append(colsSlice, pkCol)
		valsSlice = append(valsSlice, fmt.Sprintf("$%d", nc))
		nc++
		dbgo.Printf("%(cyan)%(LF) other %+v\n", pkCol)
	}
	dbgo.Printf("%(red)%(LF) cols %+v\n", potentialCols)
	for kInOrd, colName := range potentialCols {
		_ = kInOrd
		if colName != pkCol {
			//			xcolName := colName
			//			for _, vv := range parameterList { // Search param list to see if an alternate name is to be used for the value lookup (__user_id__ instad of user_id)
			//				if colName == vv.ParamName {
			//					xcolName = vv.ReqVar
			//					break
			//				}
			//			}
			//			found, val := GetVar(xcolName, c)

			found, val := GetVar(colName, c)
			// xyzzy -- TODO xyzzy4800 -- data validation of inputs.  mux-validate.go
			// 		InputList: []*MuxInput{		// validation of inputs
			// func (mux *ServeMux) ValidateInputParameters(c *gin.Context, kInOrd int) (err error) {
			// func ValidateInputParametersForHandler(c *gin.Context, kInOrd int, foundIn bool) (found bool, err error) {
			//
			// we have 'mux' available.
			// we need to find kInOrd - for self to be able to call existing validaiton function.
			//
			// var err error
			// found, err = ValidateInputParametersForHandler(c, kInOrd , found )
			// if err != nil {
			//		return
			// }
			if found {
				if dt, seq, found := FindDataType(colName, colTypes); found {
					switch dt {
					case "box":
						valx := strings.Split(val, ",")
						inputData = append(inputData, valx[0], valx[1], valx[2], valx[3])
						colsSlice = append(colsSlice, colName)
						valsSlice = append(valsSlice, fmt.Sprintf("box(point($%d,$%d),point($%d,$%d))", nc, nc+1, nc+2, nc+3))
						nc += 4

					case "serial", "bigserial":
						fmt.Fprintf(os.Stderr, "%sFound Serial ->%s<-%s\n", dbgo.ColorRed, seq, dbgo.ColorReset)

					// xyzzy ---------------------------------------------------------------- if data type is "box" then... do somethign special at this point xyzzy200
					// xyzzy ---------------------------------------------------------------- Other data types?

					default:
						fmt.Fprintf(os.Stderr, "Data Type [%s] not defined, %s\n", dt, dbgo.LF())
						err = fmt.Errorf("Data Type [%s] not defined, %s\n", dt, dbgo.LF())
						return
					}
				} else {
					inputData = append(inputData, val)
					colsSlice = append(colsSlice, colName)
					valsSlice = append(valsSlice, fmt.Sprintf("$%d", nc))
					nc++
				}
			}
		}
	}
	com := ""
	for _, aCol := range colsSlice {
		cols += fmt.Sprintf("%s%q", com, aCol)
		com = ", "
	}
	com = ""
	for _, aVal := range valsSlice {
		vals += fmt.Sprintf("%s%s", com, aVal)
		com = ", "
	}
	return
}

// if dt, found := FindDataType(colName, colTypes); found {
func FindDataType(colName string, colTypes []CrudColTypeData) (dt string, seq string, found bool) {
	for _, xx := range colTypes {
		if xx.Name == colName {
			return xx.Type, xx.SeqName, true
		}
	}
	return
}

// GetUpdateNmaes returns the set of update columns and the data values for running an udpate.
func GetUpdateNames(c *gin.Context, potentialCols []string, pkCol string, colTypes []CrudColTypeData) (updCols string, inputData []interface{}, id string, err error) {
	inputData = make([]interface{}, 0, len(potentialCols))
	colsSlice := make([]string, 0, len(potentialCols))
	valsSlice := make([]string, 0, len(potentialCols))
	colNameSlice := make([]string, 0, len(potentialCols))
	nc := 1

	dbgo.DbPrintf("GetUpdateNames", "AT: %s pkCol=%s\n", dbgo.LF(), pkCol)

	//	iddt, _ /*idseq*/, idfound := FindDataType(pkCol, colTypes)
	//	if idfound && iddt == "serial" {
	//		// idColName = pkCol
	//		// genId = true
	//	} else {
	found_pk, pk := GetVar(pkCol, c)
	dbgo.DbPrintf("GetUpdateNames", "AT: %s results value=%s found=%v\n", dbgo.LF(), pk, found_pk)
	if !found_pk {
		err = fmt.Errorf("PK (%s) not included in udpate", pkCol)
		fmt.Fprintf(os.Stderr, "Error %s", err)
		fmt.Fprintf(logFilePtr, "Error %s", err)
		SetJSONHeaders(c)
		fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"error":%q,"location":%q}`, "Database Error", fmt.Sprintf("Missing reqired column (%s)", pkCol), dbgo.LF())
		c.Writer.WriteHeader(http.StatusNotAcceptable) // 406
		return
	}
	id = pk
	inputData = append(inputData, pk)
	colsSlice = append(colsSlice, pkCol)
	valsSlice = append(valsSlice, fmt.Sprintf("$%d", nc))
	colNameSlice = append(colNameSlice, pkCol)
	nc++
	//	}
	for _, colName := range potentialCols {
		if colName != pkCol {
			dbgo.DbPrintf("GetUpdateNames", "AT: %s getting colName=%s\n", dbgo.LF(), colName)
			found, val := GetVar(colName, c)
			dbgo.DbPrintf("GetUpdateNames", "AT: %s results value=%s found=%v\n", dbgo.LF(), val, found)
			if found {
				colNameSlice = append(colNameSlice, colName)
				inputData = append(inputData, val)
				colsSlice = append(colsSlice, colName)
				valsSlice = append(valsSlice, fmt.Sprintf("$%d", nc))
				nc++
			}
		}
	}
	// if only ID, then no update
	if nc == 1 {
		err = fmt.Errorf("No columns updated")
		fmt.Fprintf(os.Stderr, "Error %s", err)
		fmt.Fprintf(logFilePtr, "Error: %s %s\n", err, dbgo.LF())
		SetJSONHeaders(c)
		fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"error":%q,"location":%q}`, "Database Error", fmt.Sprintf("Invalid number of columns, should be 1, found %d", nc), dbgo.LF())
		c.Writer.WriteHeader(http.StatusNotAcceptable) // 406
		return
	}
	com := ""
	for ii, aCol := range colsSlice {
		colName := colNameSlice[ii]
		if colName != pkCol {
			aVal := valsSlice[ii]
			updCols += fmt.Sprintf("\n\t%s%q = %s ", com, aCol, aVal)
			com = ", "
		}
	}
	return
}

// GetUpdateNmaes returns the set of update columns and the data values for running an udpate.
// Creating Delete from Update!!!!!
// 3. Delete - xyzzy3421
// xyzzy -- TODO xyzzy4800 -- implement multi-delete, change name for function.  Document Test.
func GetDeleteNames(c *gin.Context, potentialCols []string, pkCol string, colTypes []CrudColTypeData) (inputData []interface{}, id string, err error) {
	inputData = make([]interface{}, 0, len(potentialCols))
	nc := 1
	dbgo.DbPrintf("GetDeleteNames", "AT: %s pkCol=%s\n", dbgo.LF(), pkCol)

	found_pk, pk := GetVar(pkCol, c)
	dbgo.DbPrintf("GetDeleteNames", "AT: %s results value=%s found=%v\n", dbgo.LF(), pk, found_pk)
	if !found_pk {
		err = fmt.Errorf("PK (%s) not included in delete", pkCol)
		fmt.Fprintf(os.Stderr, "Error %s", err)
		fmt.Fprintf(logFilePtr, "Error %s", err)
		SetJSONHeaders(c)
		fmt.Fprintf(c.Writer, `{"status":"error","msg":%q,"error":%q,"location":%q}`, "Database Error", fmt.Sprintf("Missing reqired column (%s)", pkCol), dbgo.LF())
		c.Writer.WriteHeader(http.StatusNotAcceptable) // 406
		return
	}
	id = pk
	inputData = append(inputData, pk)
	nc++
	return
}

// var DbType = "SQLite"
// var DbType = "Postgres"

// Convert from Postgres $1, ... $n to
//
//	SQLite 	- ?, ?, ? - with positional replacement
//	MySql 	- ?, ?, ? - with positional replacement
//	MariaDB 	- ?, ?, ? - with positional replacement
//	Oracle 	- :n0, :n1, :n2 - named and return names.
func BindFixer(stmt string, vars []interface{}) (modStmt string, modVars []interface{}, names []string) {
	if DbType == "Postgres" || DbType == "" {
		modStmt = stmt
		modVars = vars
		return
	}
	// fmt.Printf("%sInput Stmt[%s] callFrom[%s]%s\n", dbgo.ColorRed, stmt, dbgo.LF(2), dbgo.ColorReset)
	if DbType == "SQLite" || DbType == "MySQL" || DbType == "MariaDB" {

		modVars := make([]interface{}, 0, len(vars))
		var b bytes.Buffer
		foo := bufio.NewWriter(&b)

		st := 0
		for i := 0; i < len(stmt); i++ {
			c := stmt[i]
			if st == 0 && c == '?' { // Already Converted
				return stmt, vars, names
			} else if st == 0 && c == '\'' {
				st = 1
				foo.WriteByte(c)
			} else if st == 0 && c == '"' {
				st = 2
				foo.WriteByte(c)
			} else if st == 1 && c == '\'' {
				st = 0
				foo.WriteByte(c)
			} else if st == 2 && c == '"' {
				st = 0
				foo.WriteByte(c)
			} else if st == 0 && c == '$' {
				var j int
				for j = i + 1; j < len(stmt) && stmt[j] >= '0' && stmt[j] <= '9'; j++ {
				}
				nth, _ := strconv.Atoi(stmt[i+1 : j])
				foo.WriteByte('?')
				modVars = append(modVars, vars[nth-1])
				// fmt.Printf("nth=%d vars[%d]=%v modVars=%s\n", nth, nth-1, vars[nth-1], dbgo.SVar(modVars))
				i = j - 1
			} else {
				foo.WriteByte(c)
			}
		}
		foo.Flush()
		modStmt = b.String() // Fetch the data back from the buffer
		// fmt.Printf("%sAT: %s vars = %s, modVars2 = %s%s\n", dbgo.ColorYellow, dbgo.LF(), dbgo.SVar(vars), dbgo.SVar(modVars), dbgo.ColorReset)
		return modStmt, modVars, names
	}
	if DbType == "MsSQL" { // Microsoft SQL Server

		modVars = make([]interface{}, 0, len(vars))
		var b bytes.Buffer
		foo := bufio.NewWriter(&b)

		st := 0
		// assume Postgres $1, $2 ... $n, translate to ? in order
		for i := 0; i < len(stmt); i++ {
			c := stmt[i]
			if st == 0 && c == '?' { // Already Converted
				return stmt, vars, names
			} else if st == 0 && c == '\'' {
				st = 1
				foo.WriteByte(c)
			} else if st == 0 && c == '"' {
				st = 2
				foo.WriteByte('[') // Icky non-standard quotes.
			} else if st == 1 && c == '\'' {
				st = 0
				foo.WriteByte(c)
			} else if st == 2 && c == '"' {
				st = 0
				foo.WriteByte(']')
			} else if st == 0 && c == '$' {
				var j int
				for j = i + 1; j < len(stmt) && stmt[j] >= '0' && stmt[j] <= '9'; j++ {
				}
				nth, _ := strconv.Atoi(stmt[i+1 : j])
				foo.WriteByte('?')
				modVars = append(modVars, vars[nth-1])
				i = j - 1
			} else {
				foo.WriteByte(c)
			}
		}
		foo.Flush()
		modStmt = b.String() // Fetch the data back from the buffer
		return
	}

	panic("Not implemented.  Invalid database type:" + DbType)
}

var StoredProcConfig = []CrudStoredProcConfig{}

var TableConfig = []CrudConfig{} // Table based end points

var QueryConfig = []CrudQueryConfig{}

func ReadThenAppendConfig(jsonFile string) (err error) {
	buf, e0 := ioutil.ReadFile(jsonFile)
	if e0 != nil {
		return e0
	}

	var AllData struct {
		Procedures []CrudStoredProcConfig
		Query      []CrudQueryConfig
		Tables     []CrudConfig
	}

	e1 := j5.Unmarshal(buf, &AllData)
	if e1 != nil {
		return e1
	}

	AppendConfig(AllData.Procedures, AllData.Tables, AllData.Query)
	return
}

func SaveCrudConfig(file string, sp []CrudStoredProcConfig, tp []CrudConfig, qp []CrudQueryConfig) (err error) {
	var AllData struct {
		Procedures []CrudStoredProcConfig
		Query      []CrudQueryConfig
		Tables     []CrudConfig
	}
	AllData.Procedures = sp
	AllData.Query = qp
	AllData.Tables = tp
	if false {
		err = ioutil.WriteFile(file, []byte(dbgo.SVarI(AllData)), 0644)
	} else {
		buf, err := json.MarshalIndent(AllData, "", "\t")
		// buf, err := j5.MarshalIndent(AllData, "", "\t")
		// buf, err := j5.Marshal(AllData)
		_ = err
		err = ioutil.WriteFile(file, buf, 0644)
		return err
	}

	return
}

func AppendConfig(sp []CrudStoredProcConfig, tp []CrudConfig, qp []CrudQueryConfig) {

	for ii, ss := range sp {
		if ss.MuxName == "" {
			dbgo.DbPrintf("auth_check.EmptyMuxName", "Note: %s missing MuxName. AT: %s\n", ss.URIPath, dbgo.LF(-3))
			ss.MuxName = NameTransform(ss.URIPath)
			sp[ii] = ss
		}
	}
	for ii, ss := range tp {
		if ss.MuxName == "" {
			dbgo.DbPrintf("auth_check.EmptyMuxName", "Note: %s missing MuxName. AT: %s\n", ss.URIPath, dbgo.LF(-3))
			ss.MuxName = NameTransform(ss.URIPath)
			tp[ii] = ss
		}
	}
	for ii, ss := range qp {
		if ss.MuxName == "" {
			dbgo.DbPrintf("auth_check.EmptyMuxName", "Note: %s missing MuxName. AT: %s\n", ss.URIPath, dbgo.LF(-3))
			ss.MuxName = NameTransform(ss.URIPath)
			qp[ii] = ss
		}
	}

	StoredProcConfig = append(StoredProcConfig, sp...)
	TableConfig = append(TableConfig, tp...)
	QueryConfig = append(QueryConfig, qp...)
}

type GobType struct {
	StoredProcConfig []CrudStoredProcConfig `json:"StoredProcConfig"`
	TableConfig      []CrudConfig           `json:"TableConfig"`
	QueryConfig      []CrudQueryConfig      `json:"QueryConfig"`
}

func ReadCRUDConfiFile(fn string) error {
	data, err := ioutil.ReadFile(fn)
	if err != nil {
		return err
	}

	var gob GobType

	err = json.Unmarshal(data, &gob)
	if err != nil {
		return err
	}

	SaveCRUDConfigData(gob)

	return nil
}

func SaveCRUDConfigData(gob GobType) error {
	if len(gob.StoredProcConfig) > 0 {
		StoredProcConfig = append(StoredProcConfig, gob.StoredProcConfig...)
	}
	if len(gob.TableConfig) > 0 {
		TableConfig = append(TableConfig, gob.TableConfig...)
	}
	if len(gob.QueryConfig) > 0 {
		QueryConfig = append(QueryConfig, gob.QueryConfig...)
	}

	return nil

}

func PrependCRUDConfigData(gob GobType) error {
	if len(gob.StoredProcConfig) > 0 {
		StoredProcConfig = append(gob.StoredProcConfig, StoredProcConfig...)
	}
	if len(gob.TableConfig) > 0 {
		TableConfig = append(gob.TableConfig, TableConfig...)
	}
	if len(gob.QueryConfig) > 0 {
		QueryConfig = append(gob.QueryConfig, QueryConfig...)
	}

	return nil
}

func SetupProcCheck() {
	//	var usedStoredProcConfig = []CrudStoredProcConfig{
	//		{
	//			CrudBaseConfig: CrudBaseConfig{
	//				URIPath:       "n/a",
	//				TableNameList: []string{"q_qr_role", "q_qr_priv", "q_qr_role_priv", "q_qr_user", "q_qr_auth_token"},
	//				ParameterList: []ParamListItem{
	//					{ReqVar: "auth_token", ParamName: "p_auth_token"},
	//					{ReqVar: "user_id", ParamName: "p_user_id"},
	//					{ReqVar: "needs_priv", ParamName: "p_needs_priv"},
	//				},
	//			},
	//			StoredProcedureName: "s_check_priv",
	//		},
	//	}
	//
	// // dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
	//
	// ValidateStoredProcs(usedStoredProcConfig)
	//
	// // dbgo.Fprintf(os.Stderr, "%(yellow)At:%(LF)\n")
}

/* vim: set noai ts=4 sw=4: */
