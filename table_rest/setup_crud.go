package table_rest

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/gintools/jwt_auth"
	"github.com/pschlump/gintools/log_enc"
)

/*
type OneOfThree struct {
	Type             int
	StoredProcConfig *CrudStoredProcConfig
	TableConfig      *CrudConfig
	QueryConfig      *CrudQueryConfig
}
*/

func InjectGlobalValues(c *gin.Context) {
	// {ReqVar: "__email_hmac_password__", ParamName: "$1"},
	// {ReqVar: "__user_password__", ParamName: "$1"},
	if aCfg == nil {
		dbgo.Printf("%(blue)aCfg is null%(reset)\n")
	}
	c.Set("__email_hmac_password__", aCfg.EncryptionPassword)
	c.Set("__user_password__", aCfg.UserdataPassword)
}

func InitTableREST(router *gin.Engine) {

	// mux.IsCompiled = true
	var pname string

	for spI, sp := range TableConfig {
		for _, m := range sp.MethodsAllowed {
			fx := func(xsp CrudConfig) func(c *gin.Context) {
				var sp int // to force use of xsp
				_ = sp
				var SpI = spI
				_ = SpI
				return func(c *gin.Context) {

					_, err := ParseAllParams(c)
					if err != nil {
						dbgo.Printf("%(red)Parse Parameter Error: %s at:%(LF)\n", err)
						log_enc.LogParamError(c, pname, fmt.Sprintf("%s", err))
						return
					}
					method := MethodReplace(c)
					InjectGlobalValues(c)

					// Check Loigin Stuff
					if xsp.JWTKey {

						if !jwt_auth.IsLoggedIn(c) {
							dbgo.Printf("%(red)Authetication Failed: %s at:%(LF)\n", err)
							c.JSON(http.StatusUnauthorized, gin.H{ // 401
								"status": "error",
								"msg":    "401 not authorized",
							})
							return
						}

						DumpParamsToLog("before/auth", c)

						privs := xsp.AuthPrivs
						if method == "GET" && len(xsp.SelectAuthPrivs) > 0 {
							privs = xsp.SelectAuthPrivs
						} else if method == "POST" && len(xsp.InsertAuthPrivs) > 0 {
							privs = xsp.InsertAuthPrivs
						} else if method == "PUT" && len(xsp.UpdateAuthPrivs) > 0 {
							privs = xsp.UpdateAuthPrivs
						} else if method == "DELETE" && len(xsp.DeleteAuthPrivs) > 0 {
							privs = xsp.DeleteAuthPrivs
						}
						dbgo.Fprintf(os.Stderr, "%(magenta)%(LF) privs=%+v\n", xsp.AuthPrivs)
						if len(privs) > 0 {
							// err = ValidatePrivs(c, privs, &(xsp.CrudBaseConfig))
							err = ValidatePrivs2(c, privs)
							if err != nil {
								return
							}
						} else {
							dbgo.Printf("%(yellow)No privs to check - skipped: at:%(LF)\n")
						}

						dbgo.Printf("%(green)Privilege Check Passed: %s at:%(LF)\n", err)

					} else if xsp.APIKey != "" {

						authHdr := c.Request.Header.Get("X-Authentication")
						if xsp.APIKey != authHdr {
							dbgo.Printf("%(red)Authetication Failed/APIKey: %s at:%(LF)\n", err)
							c.JSON(http.StatusUnauthorized, gin.H{ // 401
								"status": "error",
								"msg":    "401 not authorized",
							})
							return
						}
						dbgo.Printf("%(green)Is Authenticated via key: %s at:%(LF)\n", err)

					} else {
						dbgo.Printf("%(green)No login requried jwt_auth false: %s at:%(LF)\n", err)
						DumpParamsToLog("before/not-authenticated request", c)
					}

					if method == "GET" && len(xsp.GET_InputList) > 0 {
						pname, err = ValidateInputParameters(c, xsp.GET_InputList)
					} else if method == "POST" && len(xsp.POST_InputList) > 0 {
						pname, err = ValidateInputParameters(c, xsp.POST_InputList)
					} else if method == "PUT" && len(xsp.PUT_InputList) > 0 {
						pname, err = ValidateInputParameters(c, xsp.PUT_InputList)
					} else if method == "DELETE" && len(xsp.DELETE_InputList) > 0 {
						pname, err = ValidateInputParameters(c, xsp.DELETE_InputList)
					} else if len(xsp.InputList) > 0 {
						pname, err = ValidateInputParameters(c, xsp.InputList)
					} else {
						dbgo.Printf("%(yellow)Validation of paramters skipped - no validaiton specified in handle.go: at:%(LF)\n")
					}

					if err != nil {
						dbgo.Printf("%(red)Parameter Validation Error: %s at:%(LF)\n", err)
						log_enc.LogParamError(c, pname, fmt.Sprintf("%s", err))
						return
					}

					dbgo.Printf("%(green)Parameter Validation Passed, Privs Passed: %s at:%(LF)\n", err)

					HandleCRUDPerTableRequests(c, &xsp)

					DumpParamsToLog("After", c)

				}
			}(sp)

			switch m {
			case "GET":
				router.GET(RmTrailingSlash(sp.URIPath), fx)
			case "PUT":
				router.PUT(RmTrailingSlash(sp.URIPath), fx)
			case "POST":
				router.POST(RmTrailingSlash(sp.URIPath), fx)
			case "DELETE":
				// point to add /api/table/path/:id - SelectPkCol:    "id",
				router.DELETE(RmTrailingSlash(sp.URIPath)+"/:"+sp.SelectPkCol, fx)
				router.DELETE(RmTrailingSlash(sp.URIPath), fx)
			}

		}
	}
	for _, sp := range StoredProcConfig {
		fx := func(xsp CrudStoredProcConfig) func(c *gin.Context) {
			var sp int // to force use of xsp
			_ = sp
			return func(c *gin.Context) {

				_, err := ParseAllParams(c)
				if err != nil {
					dbgo.Printf("%(red)Parameter Error: %s at:%(LF)\n", err)
					log_enc.LogParamError(c, pname, fmt.Sprintf("%s", err))
					return
				}
				method := MethodReplace(c)
				InjectGlobalValues(c)

				// xyzzy - Check Loigin Stuff
				if xsp.JWTKey {
					if !jwt_auth.IsLoggedIn(c) {
						dbgo.Printf("%(red)Authetication Failed: %s at:%(LF)\n", err)
						c.JSON(http.StatusUnauthorized, gin.H{ // 401
							"status": "error",
							"msg":    "401 not authorized",
						})
						return
					}

					DumpParamsToLog("before", c)

					privs := xsp.AuthPrivs
					if len(xsp.CallAuthPrivs) > 0 {
						privs = xsp.CallAuthPrivs
					}

					if len(privs) > 0 {
						// err = ValidatePrivs(c, privs, &(xsp.CrudBaseConfig))
						err = ValidatePrivs2(c, privs)
						if err != nil {
							return
						}
					} else {
						dbgo.Printf("%(yellow)No privs to check - skipped: at:%(LF)\n")
					}

				} else if xsp.APIKey != "" {

					authHdr := c.Request.Header.Get("X-Authentication")
					if xsp.APIKey != authHdr {
						dbgo.Printf("%(red)Authetication Failed/APIKey: %s at:%(LF)\n", err)
						c.JSON(http.StatusUnauthorized, gin.H{ // 401
							"status": "error",
							"msg":    "401 not authorized",
						})
						return
					}
					dbgo.Printf("%(green)Is Authenticated via key: %s at:%(LF)\n", err)

				} else {
					dbgo.Printf("%(green)No login requried jwt_auth false: %s at:%(LF)\n", err)
					DumpParamsToLog("before/not-authenticated request", c)
				}

				if method == "GET" && len(xsp.GET_InputList) > 0 {
					pname, err = ValidateInputParameters(c, xsp.GET_InputList)
				} else if method == "POST" && len(xsp.POST_InputList) > 0 {
					pname, err = ValidateInputParameters(c, xsp.POST_InputList)
				} else if len(xsp.InputList) > 0 {
					pname, err = ValidateInputParameters(c, xsp.InputList)
				} else {
					dbgo.Printf("%(yellow)Validation of paramters skipped - no validaiton specified in handle.go: at:%(LF)\n")
				}

				if err != nil {
					dbgo.Printf("%(red)Parameter Validation Error: %s at:%(LF)\n", err)
					log_enc.LogParamError(c, pname, fmt.Sprintf("%s", err))
					return
				}

				HandleStoredProcedureConfig(c, &xsp)

				DumpParamsToLog("After", c)
			}
		}(sp)
		router.POST(RmTrailingSlash(sp.URIPath), fx)
	}
	for _, sp := range QueryConfig {
		fx := func(xsp CrudQueryConfig) func(c *gin.Context) {
			var sp int // to force use of xsp
			_ = sp
			return func(c *gin.Context) {
				_, err := ParseAllParams(c)
				if err != nil {
					dbgo.Printf("%(red)Parameter Error: %s at:%(LF)\n", err)
					log_enc.LogParamError(c, pname, fmt.Sprintf("%s", err))
					return
				}
				method := MethodReplace(c)
				InjectGlobalValues(c)

				dbgo.Printf("AT:%(LF) -- %(cyan) dump params before auth check \n")
				DumpParamsToLog("before", c)

				// xyzzy - Check Loigin Stuff
				dbgo.Printf("AT:%(LF) -- %(cyan) just before check of JWTKey = %v\n", xsp.JWTKey)
				if xsp.JWTKey {
					dbgo.Printf("AT:%(LF) -- %(cyan) must be true - auth required\n")
					if !jwt_auth.IsLoggedIn(c) {
						dbgo.Printf("%(red)Authetication Failed: %s at:%(LF)\n", err)
						c.JSON(http.StatusUnauthorized, gin.H{ // 401
							"status": "error",
							"msg":    "401 not authorized",
						})
						return
					}
					dbgo.Printf("AT:%(LF) -- %(cyan) dump params after auth check \n")

					DumpParamsToLog("before", c)

					privs := xsp.AuthPrivs
					if method == "GET" && len(xsp.SelectAuthPrivs) > 0 {
						privs = xsp.SelectAuthPrivs
					}
					if len(privs) > 0 {
						// err = ValidatePrivs(c, privs, &(xsp.CrudBaseConfig))
						err = ValidatePrivs2(c, privs)
						if err != nil {
							return
						}
					} else {
						dbgo.Printf("%(yellow)No privs to check - skipped: at:%(LF)\n")
					}

					dbgo.Printf("%(green)Is Logged In: %s at:%(LF)\n", err)
					DumpParamsToLog("after login", c)

				} else if xsp.APIKey != "" {

					authHdr := c.Request.Header.Get("X-Authentication")
					if xsp.APIKey != authHdr {
						dbgo.Printf("%(red)Authetication Failed/APIKey: %s at:%(LF)\n", err)
						c.JSON(http.StatusUnauthorized, gin.H{ // 401
							"status": "error",
							"msg":    "401 not authorized",
						})
						return
					}
					dbgo.Printf("%(green)Is Authenticated via key: %s at:%(LF)\n", err)

				} else {

					dbgo.Printf("%(green)No login requried jwt_auth false: %s at:%(LF)\n", err)
					DumpParamsToLog("before/not-authenticated request", c)

				}

				if method == "GET" && len(xsp.GET_InputList) > 0 {
					pname, err = ValidateInputParameters(c, xsp.GET_InputList)
				} else if method == "POST" && len(xsp.POST_InputList) > 0 {
					pname, err = ValidateInputParameters(c, xsp.POST_InputList)
				} else {
					dbgo.Printf("%(yellow)Validation of paramters skipped - no validaiton specified in handle.go: at:%(LF)\n")
				}

				if err != nil {
					dbgo.Printf("%(red)Parameter Validation Error: %s at:%(LF)\n", err)
					log_enc.LogParamError(c, pname, fmt.Sprintf("%s", err))
					return
				}

				HandleQueryConfig(c, &xsp)

				DumpParamsToLog("After", c)
			}
		}(sp)
		router.GET(RmTrailingSlash(sp.URIPath), fx)
	}
}

// ValidatePrivs returns an error if the specified privilage in the slice `RequiredAuthPrivs` is not in the set of
// privilates that the user has.
//
// Similar to (in the DDL/PgSQL code): create or replace function q_qr_admin_HasPriv_user_id ( p_user_id uuid, p_priv_needed varchar )
//
// old//func ValidatePrivs(c *gin.Context, RequiredAuthPrivs []string, xsp *CrudBaseConfig) error {
// old//
// old//	if dbgo.IsDbOn("ignore-privs") {
// old//		// log that flag is on to discard privilege requests -- IN Red
// old//		dbgo.Printf("%(red) --ignore-privs-- is set in debug - ignoring all privilege checks - at:%(LF)\n")
// old//		return nil
// old//	}
// old//
// old//	hasPriv := GetMapStringBool(c, "__privs_map__")
// old//
// old//	for _, needPriv := range RequiredAuthPrivs {
// old//		// lookup privs in list - if user has theses then - if missing - return nil
// old//		if gotIt, ok := hasPriv[needPriv]; ok && gotIt {
// old//			dbgo.Printf("%(cyan) at:%(LF) - user has %s\n", needPriv)
// old//		} else {
// old//			err := fmt.Errorf("Missing Required Privilege ->%s<-", needPriv)
// old//			dbgo.Fprintf(os.Stderr, "\n\n%(red) at:%(LF) - user missing privilege ->%s<- -- early exit, returning Error:%s\n\n", needPriv, err)
// old//			dbgo.Fprintf(logFilePtr, "\n{\"msg\":\"at:%(LF) - user missing privilege ->%s<- -- early exit, returning Error:%s\"}\n\n", needPriv, err)
// old//			log_enc.LogPrivError(c, needPriv, fmt.Sprintf("%s", err))
// old//			return err
// old//		}
// old//	}
// old//
// old//	dbgo.Fprintf(os.Stderr, "%(cyan) at:%(LF) - login not required - privilege passed\n")
// old//	dbgo.Fprintf(logFilePtr, "{\"msg\":\"at:%(LF) - login not required - privilege passed\"}\n")
// old//	return nil // All privilege tests passed, return success
// old//}
func ValidatePrivs2(c *gin.Context, RequiredAuthPrivs []string) error {

	if dbgo.IsDbOn("ignore-privs") {
		// log that flag is on to discard privilege requests -- IN Red
		dbgo.Printf("%(red) --ignore-privs-- is set in debug - ignoring all privilege checks - at:%(LF)\n")
		return nil
	}

	hasPriv := GetMapStringBool(c, "__privs_map__")

	for _, needPriv := range RequiredAuthPrivs {
		// lookup privs in list - if user has theses then - if missing - return nil
		if gotIt, ok := hasPriv[needPriv]; ok && gotIt {
			dbgo.Printf("%(cyan) at:%(LF) - user has %s\n", needPriv)
		} else {
			err := fmt.Errorf("Missing Required Privilege ->%s<-", needPriv)
			dbgo.Fprintf(os.Stderr, "\n\n%(red) at:%(LF) - user missing privilege ->%s<- -- early exit, returning Error:%s\n\n", needPriv, err)
			dbgo.Fprintf(logFilePtr, "\n{\"msg\":\"at:%(LF) - user missing privilege ->%s<- -- early exit, returning Error:%s\"}\n\n", needPriv, err)
			log_enc.LogPrivError(c, needPriv, fmt.Sprintf("%s", err))
			return err
		}
	}

	dbgo.Fprintf(os.Stderr, "%(cyan) at:%(LF) - login not required - privilege passed\n")
	dbgo.Fprintf(logFilePtr, "{\"msg\":\"at:%(LF) - login not required - privilege passed\"}\n")
	return nil // All privilege tests passed, return success
}

func GetMapStringBool(c *gin.Context, key string) (s map[string]bool) {
	if val, ok := c.Get(key); ok && val != nil {
		s, _ = val.(map[string]bool)
	}
	return
}

func DumpParamsToLog(when string, c *gin.Context) {

	fmt.Fprintf(os.Stderr, "\n%s\n", when)

	fmt.Fprintf(os.Stderr, "c.Keys\n")
	fmt.Fprintf(os.Stderr, "%25s | %s\n", "Name", "Value")
	fmt.Fprintf(os.Stderr, "%25s | %s\n", "-------------------------", "-------------------------------------------------------------")
	for _, name := range jwt_auth.SortedMapKeys(c.Keys) {
		val := c.Keys[name]
		_, ok := val.(string)
		if ok {
			fmt.Fprintf(os.Stderr, "%25s | %s\n", name, strings.Replace(fmt.Sprintf("%s", val), "\n", "\n                            ", -1))
		} else {
			valJSON := dbgo.SVarI(val)
			fmt.Fprintf(os.Stderr, "%25s | %s\n", name, strings.Replace(fmt.Sprintf("%s", valJSON), "\n", "\n                            ", -1))
		}
	}
	fmt.Fprintf(os.Stderr, "\n")

	return
}

/* vim: set noai ts=4 sw=4: */
