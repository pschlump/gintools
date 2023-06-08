package jwt_auth

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/copier"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/gintools/log_enc"
	"github.com/pschlump/json"
)

// &email_note=jane@client.com h

func DumpParamsToLog(when string, c *gin.Context) {

	fmt.Fprintf(os.Stderr, "\n%s\n", when)

	fmt.Fprintf(os.Stderr, "c.Keys\n")
	fmt.Fprintf(os.Stderr, "%25s | %s\n", "Name", "Value")
	fmt.Fprintf(os.Stderr, "%25s | %s\n", "-------------------------", "-------------------------------------------------------------")
	for _, name := range SortedMapKeys(c.Keys) {
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

// {Method: "POST", Path: "/api/v1/auth/create-registration-token", Fx: authHandleCreateRegistrationToken, UseLogin: LoginRequired}, //
// create or replace function q_admin_create_token_registration ( p_description varchar, p_client_id varchar, p_role_name varchar, p_email_note varchar, p_user_id uuid, p_admin_email varchar, p_application_url varchar, p_hmac_password varchar, p_userdata_password varchar )

// -------------------------------------------------------------------------------------------------------------------------
// Input for login
type ApiCreateRegistrationToken struct {
	Description string `json:"description"    form:"description"       binding:"required"`
	AdminEmail  string `json:"admin_email"     form:"admin_email"      binding:"required"`
	ClientId    string `json:"client_id"      form:"client_id"`
	RoleName    string `json:"role_name"      form:"role_name"`
	EmailNote   string `json:"email_note"     form:"email_note"`
}

// Create a new Registration Token
type RvCreateRegistrationTokenType struct {
	StdErrorReturn
	ClientId          string `json:"client_id"      form:"client_id" db:"client_id"`
	RegistrationToken string `json:"registration_token" form:"registration_token" db:"registration_token"`
}

// Output returned
type CreateRegistrationStuccess struct {
	Status            string `json:"status"`
	ClientId          string `json:"client_id"      form:"client_id"`
	RegistrationToken string `json:"registration_token" form:"registration_token" db:"registration_token"`
}

// {Method: "POST", Path: "/api/v1/auth/get-user-config", Fx: authHandleGetUserConfig, UseLogin: LoginRequired},
//
// authHandleGetUserConfig godoc
// @Summary Return the current user configuration data.
// @Schemes
// @Description Return the per-user config in the same format as during login.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Produce json
// @Success 200 {object} jwt_auth.LoginSuccess
// @Failure 403 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/get-user-config [post]
func authHandleCreateRegistrationToken(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF)\n")
	var pp ApiCreateRegistrationToken
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	UserId, AuthToken := GetAuthToken(c)

	if AuthToken == "" { // if user is logged in then logout - else - just ignore.
		dbgo.Printf("%(red)at: %(LF) - failt to authenticate\n")
		out := StdErrorReturn{
			Status:   "error",
			Msg:      "401 not authorized",
			Location: dbgo.LF(),
		}
		c.JSON(http.StatusUnauthorized, LogJsonReturned(out))
		return
	}

	// func DumpParamsToLog(when string, c *gin.Context) {
	DumpParamsToLog("After Auth - Top", c)

	var DBGetUserDataResp RvCreateRegistrationTokenType

	UserId, err := GetUserId(c)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": "unrachable-code",
		})
		return
	}

	// ------------------------------ xyzzy ---------------------------------------------------------
	//
	// Check role for logged in user.
	//
	// May Create User With:<Role> must exist for this user to create a role of this type.
	//
	// ----------------------------------------------------------------------------------------------

	//                                              1                      2                    3                    4                     5               6                      7                        8
	// function q_admin_create_token_registration ( p_description varchar, p_client_id varchar, p_role_name varchar, p_email_note varchar, p_user_id uuid, p_admin_email varchar, p_application_url varchar, p_hmac_password varchar, p_userdata_password varchar )
	stmt := "q_admin_create_token_registration ( $1, $2, $3, $4, $5, $6, $7, $8, $9 )"
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF): %s\n", stmt)
	//                                                      1               2            3            4             5       6              7                   7                        8
	rv, err := CallDatabaseJSONFunction(c, stmt, "ee.ee..", pp.Description, pp.ClientId, pp.RoleName, pp.EmailNote, UserId, pp.AdminEmail, gCfg.BaseServerURL, aCfg.EncryptionPassword, aCfg.UserdataPassword)
	if err != nil {
		return
	}
	dbgo.Fprintf(logFilePtr, "%(yellow)%(LF): rv=%s\n", rv)
	err = json.Unmarshal([]byte(rv), &DBGetUserDataResp)
	if DBGetUserDataResp.Status != "success" {
		DBGetUserDataResp.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "e", SVar(DBGetUserDataResp), UserId, pp.AdminEmail, gCfg.BaseServerURL /*aCfg.EncryptionPassword,*/ /*, aCfg.UserdataPassword*/)
		c.JSON(http.StatusBadRequest, LogJsonReturned(DBGetUserDataResp.StdErrorReturn))
		return
	}

	var out CreateRegistrationStuccess
	copier.Copy(&out, &DBGetUserDataResp)
	c.JSON(http.StatusOK, LogJsonReturned(out))
}

// {Method: "POST", Path: "/api/v1/auth/create-client", Fx: authHandleCreateClient, UseLogin: LoginRequired}, //
// create or replace function q_admin_create_client ( p_client_name varchar, p_description varchar, p_role_name varchar, p_user_id uuid, p_hmac_password varchar, p_userdata_password varchar )

// -------------------------------------------------------------------------------------------------------------------------
// Create a new Client
type ApiCreateClient struct {
	ClientName  string `json:"client_name"      form:"client_name"       binding:"required"`
	Description string `json:"description"      form:"description"       binding:"required"`
	RoleName    string `json:"role_name"        form:"role_name"`
	Email       string `json:"email"            form:"email"`
}

type RvCreateClientType struct {
	StdErrorReturn
	RegistrationToken string `json:"token_registration,omitempty" db:"token_registration"`
	ClientId          string `json:"client_id"                    db:"client_id"`
}

// Output returned
type CreateClientSuccess2 struct {
	Status            string `json:"status"`
	RegistrationToken string `json:"token_registration,omitempty"`
	ClientId          string `json:"client_id,omitempty"`
}

// {Method: "POST", Path: "/api/v1/auth/get-user-config", Fx: authHandleGetUserConfig, UseLogin: LoginRequired},
//
// authHandleGetUserConfig godoc
// @Summary Return the current user configuration data.
// @Schemes
// @Description Return the per-user config in the same format as during login.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Produce json
// @Success 200 {object} jwt_auth.LoginSuccess
// @Failure 403 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/get-user-config [post]
func authHandleCreateClient(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF)\n")
	var pp ApiCreateClient
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	var DBGetUserDataResp RvCreateClientType

	UserId, AuthToken := GetAuthToken(c)

	if AuthToken == "" { // if user is logged in then logout - else - just ignore.
		dbgo.Printf("%(red)at: %(LF) - failt to authenticate\n")
		out := StdErrorReturn{
			Status:   "error",
			Msg:      "401 not authorized",
			Location: dbgo.LF(),
		}
		c.JSON(http.StatusUnauthorized, LogJsonReturned(out))
		return
	}

	DumpParamsToLog("After Auth - Top", c)

	//                                  1                      2                      3                    4                     5               6                        7
	// function q_admin_create_client ( p_client_name varchar, p_description varchar, p_role_name varchar, p_email_addr varchar, p_user_id uuid, p_hmac_password varchar, p_userdata_password varchar )
	stmt := "q_admin_create_client ( $1, $2, $3, $4, $5, $6, $7 )"
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF): %s\n", stmt)
	//                                                      1              2               3            4         5       6                        7
	rv, err := CallDatabaseJSONFunction(c, stmt, "ee.ee..", pp.ClientName, pp.Description, pp.RoleName, pp.Email, UserId, aCfg.EncryptionPassword, aCfg.UserdataPassword)
	if err != nil {
		return
	}
	dbgo.Fprintf(logFilePtr, "%(yellow)%(LF): rv=%s\n", rv)
	err = json.Unmarshal([]byte(rv), &DBGetUserDataResp)
	if DBGetUserDataResp.Status != "success" {
		DBGetUserDataResp.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "e", SVar(DBGetUserDataResp), UserId /*aCfg.EncryptionPassword,*/ /*, aCfg.UserdataPassword*/)
		c.JSON(http.StatusBadRequest, LogJsonReturned(DBGetUserDataResp.StdErrorReturn))
		return
	}

	var out CreateClientSuccess
	copier.Copy(&out, &DBGetUserDataResp)
	c.JSON(http.StatusOK, LogJsonReturned(out))
}

// -------------------------------------------------------------------------------------------------------------------------
// Create a new Client
type ApiGetRegistrationToken struct {
	UserName string `json:"user_name"      form:"user_name"`
}

// l_token_registration
type RvGetRegistrationTokenType struct {
	StdErrorReturn
	RegistrationToken string `json:"token_registration,omitempty" db:"token_registration"`
}

// Output returned
type CreateClientSuccess struct {
	Status            string `json:"status"`
	RegistrationToken string `json:"token_registration,omitempty"`
}

// {Method: "POST", Path: "/api/v1/auth/get-registration-token", Fx: authHandleGetRegistrationToken, UseLogin: LoginRequired}, //
//
// authHandleGetUserConfig godoc
// @Summary Return the current user configuration data.
// @Schemes
// @Description Return the per-user config in the same format as during login.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Produce json
// @Success 200 {object} jwt_auth.LoginSuccess
// @Failure 403 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/get-user-config [post]
func authHandleGetRegistrationToken(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF)\n")
	var pp ApiGetRegistrationToken
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	var DBData RvGetRegistrationTokenType

	UserId, AuthToken := GetAuthToken(c)

	if AuthToken == "" { // if user is logged in then logout - else - just ignore.
		dbgo.Printf("%(red)at: %(LF) - failt to authenticate\n")
		out := StdErrorReturn{
			Status:   "error",
			Msg:      "401 not authorized",
			Location: dbgo.LF(),
		}
		c.JSON(http.StatusUnauthorized, LogJsonReturned(out))
		return
	}

	DumpParamsToLog("After Auth - Top", c)

	//                                            1               2                        3
	// function q_admin_get_registration_token (  p_user_id uuid, p_hmac_password varchar, p_userdata_password varchar )
	stmt := "q_admin_get_registration_token ( $1, $2, $3 )"
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF): %s\n", stmt)
	//                                                      1       2                        3
	rv, err := CallDatabaseJSONFunction(c, stmt, "ee.ee..", UserId, aCfg.EncryptionPassword, aCfg.UserdataPassword)
	if err != nil {
		return
	}
	dbgo.Fprintf(logFilePtr, "%(yellow)%(LF): rv=%s\n", rv)
	err = json.Unmarshal([]byte(rv), &DBData)
	if DBData.Status != "success" {
		DBData.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "e", SVar(DBData), UserId /*aCfg.EncryptionPassword,*/ /*, aCfg.UserdataPassword*/)
		c.JSON(http.StatusBadRequest, LogJsonReturned(DBData.StdErrorReturn))
		return
	}

	var out CreateClientSuccess2
	copier.Copy(&out, &DBData)
	c.JSON(http.StatusOK, LogJsonReturned(out))
}

/* vim: set noai ts=4 sw=4: */
