package jwt_auth

// xyzzyPriv

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

// xyzzyLogoutForced - send message via websockt to log out all of this user.

// xyzzyRedisUsePubSub gCfg.RedisUsePubSub   string `json:"redis_use_pub_sub" default:"no"`

//	1. Change Name 			/api/v1/auth/change-name
//	2. Change Email Address	/api/v1/auth/change-email-addrss, .../can-chagne-email -> success/failed
// xyzzy770000 TODO --------------------------- change account info
// xyzzy770000 TODO --------------------------- change account info -- all info update by admin...
//		- stored proc needs to be implemented
//		- admin page
// xyzzy551 - Change Email NOT Tested

// =======================================================================================

// xyzzy99 - AuthEmailToken           string `json:"auth_email_token" default:"uuid"`                                          // "uuid"|"n6" - if n6 then a 6 digit numer is used.

// =======================================================================================

// TODO - should allso allow use of x2fa_pin as an alternative to "password" - xyzzy988098
// TODO -		em.SendEmail("email_address_changed_old_address",
// TODO -		em.SendEmail("email_address_changed_new_address",

// xyzzy201312 - TODO - get user_config /api/v1/get-user-config -> array
// xyzzy201312 - TODO - set/add/upd user_config /api/v1/set-user-config -> [ { id / name / value } , ..., { "name":"value" } ]
// xyzzy201312 - TODO - delete user_config /api/v1/del-user-config -> [ id, ... ]
// make this a stored proc call that performs a upsert! xyzzy444444444

// xyzzy100 - TODO -- Finish SaveState -- Convert to middleware so it works with all.

// Email Templates
// =======================================================================================
//
// 1. login_new_device
// 2. welcome_registration
// 3. password_changed
// 4. recover_password
// 5. password_updated
// 6. account_deleted
// 7. admin_password_changed
// 8. regenerate_one_time_passwords
// 9. un_pw_account_created -- todo
// 10. token_account_created -- todo

// Notes
// =======================================================================================

// xyzzy443 - send email about this -- all done except end points that are not yet used.
//		- get sendgrid account updated
//		- validate actual email
//		- put in each email
//		- pwa not installedj0
// 		xyzzy448 - test for un/pw and token registration of acocunt, test of login, test of parent account deleted.

// xyzzy-Expire
//		Return token expiration date/time to user so can do intelligent refresh.
// 		SetInsecureCookie("X-Is-Logged-In", "yes", c) // To let the JS code know that it is logged in.

/*
// router.GET("/Q/:a/:b",
// OR
// router.GET("/Q/:a",
func QrGroupRequestHandler(c *gin.Context) {
	t1 := c.Param("t1")
	t2 := c.Param("t2")
	dbgo.Printf("\n%(green)Test of Q ->%s<- GroupID ->%s<-\n", t1, t2)

	QrCommonHandler(c, t1, t2)

	// 308 Permanent Redirect - where method never changes.
}
*/

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jinzhu/copier"
	"github.com/pschlump/HashStrings"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/filelib"
	"github.com/pschlump/gintools/callme"
	"github.com/pschlump/gintools/log_enc"
	"github.com/pschlump/gintools/qr_svr2"
	"github.com/pschlump/gintools/run_template"
	"github.com/pschlump/gintools/tf"
	"github.com/pschlump/gintools/tools/jwt-cli/jwtlib"
	"github.com/pschlump/htotp"
	"github.com/pschlump/json"
	"github.com/pschlump/pluto/g_lib"
	"github.com/pschlump/scany/pgxscan"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type RvStatus struct {
	StdErrorReturn
	// Status string `json:"status" db:"status"`
}

type GinLoginType struct {
	Path     string
	Method   string
	Fx       func(c *gin.Context)
	UseLogin LoginType // 0 required - or not found in table, 1 not required, 2 optional
}

type LoginType int

const (
	LoginRequired LoginType = 1
	PublicApiCall LoginType = 0
	LoginOptional LoginType = 2
)

type NoCookieType int

const (
	CookieUsed NoCookieType = 1
	NoCookie   NoCookieType = 2
)

var GinSetupTable = []GinLoginType{

	// No Login UseLogin
	{Method: "POST", Path: "/api/v1/auth/login", Fx: authHandleLogin, UseLogin: PublicApiCall},
	{Method: "POST", Path: "/api/v1/auth/xlogin/:seid", Fx: authHandleLogin, UseLogin: PublicApiCall},                            // 301 Rediret Destination URL
	{Method: "POST", Path: "/api/v1/auth/register", Fx: authHandleRegister, UseLogin: PublicApiCall},                             // un + pw + first_name + last_name
	{Method: "POST", Path: "/api/v1/auth/register-client-admin", Fx: authHandleRegisterClientAdmin, UseLogin: PublicApiCall},     // un + pw + first_name + last_name + token to lead to client account
	{Method: "POST", Path: "/api/v1/auth/register-using-auth-token", Fx: authHandleRegisterClientAdmin, UseLogin: PublicApiCall}, // un + pw + first_name + last_name + token to lead to client account

	{Method: "POST", Path: "/api/v1/auth/create-user-admin", Fx: authHandleRegister, UseLogin: PublicApiCall},                                    // TODO
	{Method: "POST", Path: "/api/v1/auth/validate-2fa-token", Fx: authHandleValidate2faToken, UseLogin: PublicApiCall},                           // 2nd step 2fa - create auth-token / jwtToken Sent
	{Method: "GET", Path: "/api/v1/auth/email-confirm", Fx: authHandlerEmailConfirm, UseLogin: PublicApiCall},                                    // Validate email token via GET link in email
	{Method: "POST", Path: "/api/v1/auth/validate-email-confirm", Fx: authHandlerValidateEmailConfirm, UseLogin: PublicApiCall},                  // Validate email token via manual entered POST
	{Method: "POST", Path: "/api/v1/auth/recover-password-01-setup", Fx: authHandleRecoverPassword01Setup, UseLogin: PublicApiCall},              //
	{Method: "GET", Path: "/api/v1/auth/recover-password-01-setup", Fx: authHandleRecoverPassword01Setup, UseLogin: PublicApiCall},               //
	{Method: "POST", Path: "/api/v1/auth/recover-password-02-fetch-info", Fx: authHandleRecoverPassword02FetchInfo, UseLogin: PublicApiCall},     //
	{Method: "GET", Path: "/api/v1/auth/recover-password-02-fetch-info", Fx: authHandleRecoverPassword02FetchInfo, UseLogin: PublicApiCall},      //
	{Method: "POST", Path: "/api/v1/auth/recover-password-03-set-password", Fx: authHandleRecoverPassword03SetPassword, UseLogin: PublicApiCall}, //
	{Method: "GET", Path: "/api/v1/auth/no-login-status", Fx: authHandleNoLoginStatus, UseLogin: PublicApiCall},                                  //
	{Method: "POST", Path: "/api/v1/auth/no-login-status", Fx: authHandleNoLoginStatus, UseLogin: PublicApiCall},                                 //
	{Method: "GET", Path: "/api/v1/auth/2fa-has-been-setup", Fx: authHandle2faHasBeenSetup, UseLogin: PublicApiCall},                             //
	{Method: "GET", Path: "/api/v1/auth/email-has-been-validated", Fx: authHandleEmailHasBeenSetup, UseLogin: PublicApiCall},                     //
	{Method: "GET", Path: "/api/v1/auth/acct-status", Fx: authHandleAcctHasBeenSetup, UseLogin: PublicApiCall},                                   //
	{Method: "GET", Path: "/api/v1/id.json", Fx: loginTrackingJsonHandler, UseLogin: PublicApiCall},                                              //
	{Method: "GET", Path: "/api/v1/set-debug-flag", Fx: authHandlerSetDebugFlag, UseLogin: PublicApiCall},                                        //
	{Method: "POST", Path: "/api/v1/auth/resend-registration-email", Fx: authHandleResendRegistrationEmail, UseLogin: PublicApiCall},             // Must have password to send.
	{Method: "GET", Path: "/api/v1/auth/setup.js", Fx: authHandlerGetXsrfIdFile, UseLogin: PublicApiCall},                                        //
	{Method: "GET", Path: "/api/v1/auth/setup", Fx: authHandlerGetXsrfIdFileJSON, UseLogin: PublicApiCall},                                       //
	{Method: "POST", Path: "/api/v1/auth/generate-qr-for-secret", Fx: authHandleGenerateQRForSecret, UseLogin: PublicApiCall},                    //
	{Method: "GET", Path: "/api/v1/auth/requires-2fa", Fx: authHandlerRequires2fa, UseLogin: PublicApiCall},                                      // reutrn y/n if 2fa is used  for htis account
	{Method: "POST", Path: "/api/v1/auth/requires-2fa", Fx: authHandlerRequires2fa, UseLogin: PublicApiCall},                                     // reutrn y/n if 2fa is used  for htis account
	{Method: "POST", Path: "/api/v1/auth/set-email-remap", Fx: authHandlerSetEmailRedirect, UseLogin: PublicApiCall},                             //

	{Method: "GET", Path: "/api/v1/auth/logout", Fx: authHandleLogout, UseLogin: LoginOptional},  // just logout - destroy auth-token
	{Method: "POST", Path: "/api/v1/auth/logout", Fx: authHandleLogout, UseLogin: LoginOptional}, // just logout - destroy auth-token

	// Login UseLogin
	{Method: "POST", Path: "/api/v1/auth/login-status", Fx: authHandleLoginStatus, UseLogin: LoginRequired},                          //	Test of Login UseLogin Stuff
	{Method: "GET", Path: "/api/v1/auth/login-status", Fx: authHandleLoginStatus, UseLogin: LoginRequired},                           //	Test of Login UseLogin Stuff
	{Method: "POST", Path: "/api/v1/auth/change-password", Fx: authHandleChangePassword, UseLogin: LoginRequired},                    // change passwword
	{Method: "POST", Path: "/api/v1/auth/delete-acct", Fx: authHandleDeleteAccount, UseLogin: LoginRequired},                         // self-terminate account
	{Method: "POST", Path: "/api/v1/auth/regen-otp", Fx: authHandleRegenOTP, UseLogin: LoginRequired},                                // regenerate list of OTP list
	{Method: "POST", Path: "/api/v1/auth/register-un-pw", Fx: authHandleRegisterUnPw, UseLogin: LoginRequired},                       //
	{Method: "POST", Path: "/api/v1/auth/register-token", Fx: authHandleRegisterToken, UseLogin: LoginRequired},                      //
	{Method: "POST", Path: "/api/v1/auth/change-email-address", Fx: authHandleChangeEmailAddress, UseLogin: LoginRequired},           //
	{Method: "POST", Path: "/api/v1/auth/change-account-info", Fx: authHandleChangeAccountInfo, UseLogin: LoginRequired},             //
	{Method: "POST", Path: "/api/v1/auth/change-password-admin", Fx: authHandleChangePasswordAdmin, UseLogin: LoginRequired},         //
	{Method: "POST", Path: "/api/v1/auth/refresh-token", Fx: authHandleRefreshToken, UseLogin: LoginRequired},                        //
	{Method: "POST", Path: "/api/v1/auth/validate-token", Fx: authHandleValidateToken, UseLogin: LoginRequired},                      //  Checks that AuthToken + Fingerprint data is valid, if not display a Login
	{Method: "GET", Path: "/api/v1/auth/get-user-config", Fx: authHandleGetUserConfig, UseLogin: LoginRequired},                      //
	{Method: "POST", Path: "/api/v1/auth/get-user-config", Fx: authHandleGetUserConfig, UseLogin: LoginRequired},                     //
	{Method: "POST", Path: "/api/v1/auth/set-user-config", Fx: authHandleSetUserConfig, UseLogin: LoginRequired},                     //
	{Method: "POST", Path: "/api/v1/auth/create-client", Fx: authHandleCreateClient, UseLogin: LoginRequired},                        //
	{Method: "POST", Path: "/api/v1/auth/create-registration-token", Fx: authHandleCreateRegistrationToken, UseLogin: LoginRequired}, //
	{Method: "POST", Path: "/api/v1/auth/get-registration-token", Fx: authHandleGetRegistrationToken, UseLogin: LoginRequired},       //
	{Method: "POST", Path: "/api/v1/auth/auth-token-delete-admin", Fx: authHandleAuthTokenDeleteAdmin, UseLogin: LoginRequired},      //
	{Method: "POST", Path: "/api/v1/auth/get-acct-state", Fx: authHandlerGetAcctState, UseLogin: LoginRequired},                      //
	{Method: "POST", Path: "/api/v1/auth/update-acct-state", Fx: authHandlerUpdateAcctState, UseLogin: LoginRequired},                //
	{Method: "GET", Path: "/api/v1/auth/has-priv", Fx: authHandlerHasPriv, UseLogin: LoginRequired},                                  //
	{Method: "POST", Path: "/api/v1/auth/has-priv", Fx: authHandlerHasPriv, UseLogin: LoginRequired},                                 //
	{Method: "POST", Path: "/api/v1/auth/add-priv-to", Fx: authHandlerAddPrivTo, UseLogin: LoginRequired},                            //
	{Method: "POST", Path: "/api/v1/auth/rm-priv-from", Fx: authHandlerRmPrivFrom, UseLogin: LoginRequired},                          //
	{Method: "GET", Path: "/api/v1/auth/list-priv", Fx: authHandlerListPriv, UseLogin: LoginRequired},                                //
	{Method: "POST", Path: "/api/v1/auth/list-priv", Fx: authHandlerListPriv, UseLogin: LoginRequired},                               //

}

// -------------------------------------------------------------------------------------------------------------------------
// Account Flow
// -------------------------------------------------------------------------------------------------------------------------
// 1. Create a "root" admin@xyz.com account -with- priv's
// 2. Use admin@xyz.com ( login to it )
//    a. Login
//    b. Use Account to create cient
//    c. Use Account to create a "token" account (match with (b) -- With 'role:*' as the role.
//    d. Login to jane@client.com
// 	  e. Use jane@client.com to create 3 user accoutns, tim@, fred@, mac@
// -------------------------------------------------------------------------------------------------------------------------

// -------------------------------------------------------------------------------------------------------------------------
func GinInitAuthPaths(router *gin.Engine) {
	for ii, vv := range GinSetupTable {
		if vv.Fx != nil {
			switch vv.Method {
			case "POST":
				router.POST(vv.Path, vv.Fx)
			case "GET":
				router.GET(vv.Path, vv.Fx)
			case "PUT":
				router.PUT(vv.Path, vv.Fx)
			case "DELETE":
				router.DELETE(vv.Path, vv.Fx)
			default:
				// dbgo.Fprintf(os.Stderr, "Invalid %s [pos %d in table] method in setup at %(LF) -- fatal internal error\n", vv.Method, ii)
				dbgo.Fprintf(logFilePtr, "Invalid %s [pos %d in table] method in setup at %(LF) -- fatal internal error\n", vv.Method, ii)
				os.Exit(1)
			}
		}
	}
}

// -------------------------------------------------------------------------------------------------------------------------
/*
CREATE TABLE if not exists q_qr_users (
	user_id 				uuid default uuid_generate_v4() not null primary key,
	email_hmac 				bytea not null,
	email_enc 				bytea not null,										-- encrypted/decryptable email address
	password_hash 			text not null,
	validation_method		varchar(10) default 'un/pw' not null check ( validation_method in ( 'un/pw', 'sip', 'srp6a', 'hw-key', 'webauthn' ) ),
	validator				text, -- p, q, a, v? -- Store as JSON and decode as necessary? { "typ":"sip", "ver":"v0.0.1", "v":..., "p":... }
	e_value					text,
	x_value					text,
	y_value					text,
	pdf_enc_password		text,	-- Password used for encryption of .pdf files - per user.
	first_name_enc			bytea not null,
	first_name_hmac 		text not null,
	last_name_enc			bytea not null,
	last_name_hmac 			text not null,
	acct_state				varchar(40) default 'registered' not null check ( acct_state in ( 'registered', 'change-pw', 'change-2fa', 'change-email', 'other' ) ),
	email_validated			varchar(1) default 'n' not null,
	email_verify_token		uuid,
	email_verify_expire 	timestamp,
	password_reset_token	uuid,
	password_reset_time		timestamp,
	failed_login_timeout 	timestamp,
	login_failures 			int default 0 not null,
	login_success 			int default 0 not null,
	parent_user_id 			uuid,
	account_type			varchar(20) default 'login' not null check ( account_type in ( 'login', 'un/pw', 'token', 'other' ) ),
	require_2fa 			varchar(1) default 'y' not null,
	secret_2fa 				varchar(20),
	setup_complete_2fa 		varchar(1) default 'n' not null,					-- Must be 'y' to login / set by q_auth_v1_validate_2fa_token
	start_date				timestamp default current_timestamp not null,
	end_date				timestamp,
	privileges				text,
	updated 				timestamp, 									 		-- Project update timestamp (YYYYMMDDHHMMSS timestamp).
	created 				timestamp default current_timestamp not null 		-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);
*/

// @title jwt auth code

type JwtClaims struct {
	AuthToken string `json:"auth_token"`
	jwt.RegisteredClaims
}

type StdErrorReturn struct {
	Status   string `json:"status"`
	Msg      string `json:",omitempty"`
	Code     string `json:",omitempty"`
	Location string `json:",omitempty"`
	LogUUID  string `json:",omitempty"`
}

// -------------------------------------------------------------------------------------------------------------------------

// DB Reutrn Data
type RvLoginType struct {
	StdErrorReturn
	UserId           string            `json:"user_id,omitempty"`
	AuthToken        string            `json:"auth_token,omitempty"` // May be "" - meaning no auth.
	TmpToken         string            `json:"tmp_token,omitempty"`  // May be "" - used in 2fa part 1 / 2
	Token            string            `json:"token,omitempty"`      // the JWT Token???
	Require2fa       string            `json:"require_2fa,omitempty"`
	Secret2fa        string            `json:"secret_2fa,omitempty"`
	AccountType      string            `json:"account_type,omitempty"`
	Privileges       []string          `json:"privileges,omitempty"`
	FirstName        string            `json:"first_name,omitempty"`
	LastName         string            `json:"last_name,omitempty"`
	IsNewDeviceLogin string            `json:"is_new_device_login,omitempty"`
	ClientId         string            `json:"client_id,omitempty"`
	AcctState        string            `json:"acct_state,omitempty"`
	UserConfig       map[string]string `json:"user_config,omitempty"`
}

// Input for login
type ApiAuthLogin struct {
	Email    string `json:"email"      form:"email"       binding:"required,email"`
	Pw       string `json:"password"   form:"password"    binding:"required"`
	AmIKnown string `json:"am_i_known" form:"am_i_known"`
	XsrfId   string `json:"xsrf_id"    form:"xsrf_id"     binding:"required"`
	FPData   string `json:"fp_data"    form:"fp_data"` // fingerprint data
	ScID     string `json:"scid"       form:"scid"`    // y_id - local storage ID

	// You can set any value for the 'no_cookie' data field.   Normally if you want to skip cookies send 'nc' for the value.
	NoCookie string `json:"no_cookie"  form:"no_cookie"` // default is to NOT send cookie if cookies and headers (both ==> , "token_header_vs_cookie": "both") are defined,
}

//type UserConfigData struct {
//	ConfigId string `json:"config_id" form:"config_id"`
//	Name     string `json:"name"      form:"name"`
//	Value    string `json:"value"     form:"value"`
//}

// Output returned
type LoginSuccess struct {
	Status     string            `json:"status"`
	TmpToken   string            `json:"tmp_token,omitempty"` // May be "" - used in 2fa part 1 / 2
	Token      string            `json:"token,omitempty"`     // the JWT Token???
	Require2fa string            `json:"require_2fa,omitempty"`
	FirstName  string            `json:"first_name,omitempty"`
	LastName   string            `json:"last_name,omitempty"`
	AcctState  string            `json:"acct_state,omitempty"`
	UserConfig map[string]string `json:"user_config,omitempty"`
	Email      string            `json:"email,omitempty"`
}

type LoginError1 struct {
	StdErrorReturn
	TmpToken string `json:"tmp_token,omitempty"` // May be "" - used in 2fa part 1 / 2
	Email    string `json:"email,omitempty"`
}

// /api/register-user, send-data={"user":"alice","v":13136}
// router.POST("/api/v1/auth/login", authHandleLogin)

// authHandleLogin will validate a user's username and password using the stored procedure `q_auth_v1_login` - if the user is
// validated then create a JWT token and send it back to the client as a secure cookie.   Send a "is-logged-in" regular
// cookie.
// func authHandleLogin(c *gin.Context, config interface{}) (err error) {

// authHandleLogin godoc
// @Summary Login a user - Part 1 before 2FA
// @Schemes
// @Description Call checks a users email/password and returns informaiton on part 2 validation.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   email        formData    string     true        "Email Address"
// @Param   pw           formData    string     true        "Password"
// @Param   am_i_known   formData    string     false       "Id from id.json if available"
// @Param   fp_data      formData    string     false       "Fingerprint of device"
// @Param   scid         formData    string     false       "Local storage ID, y_id from setup."
// @Produce json
// @Success 200 {object} jwt_auth.LoginSuccess
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/login [post]
func authHandleLogin(c *gin.Context) {
	var err error
	var pp ApiAuthLogin
	if err := BindFormOrJSON(c, &pp); err != nil {
		md.AddCounter("jwt_auth_failed_login_attempts", 1)
		return
	}

	pp.Email = cleanupEmail(pp.Email)
	pp.Pw = cleanupPw(pp.Pw)

	if err := ValidateXsrfId(c, pp.XsrfId); err != nil {
		md.AddCounter("jwt_auth_failed_login_attempts", 1)
		return
	}

	hashOfHeaders := HeaderFingerprint(c)
	perReqLog := tf.GetLogFilePtr(c)

	// dbgo.DbFprintf("dump-qr-encode-string", perReqLog, "%(Yellow)Encoding  ->%s<- intooo QR.png at:%(LF)\n", InputString)
	// if dbgo.IsDbOn("dump-login-info") {
	dbgo.Fprintf(perReqLog, "\n%(red)--------------------------------------------------------------------------------------------------\n"+
		"%(cyan)AT: %(LF)\n\temail ->%(yellow)%s%(cyan)<- pw ->%(yellow)%s%(cyan)<-\n\tAmIKnown ->%(yellow)%s%(cyan)<-     XsrfId ->%(yellow)%s%(cyan)<-\n"+
		"%(red)\thashOfHeadrs ->%s<-\n"+
		"%(red)\tFPData ->%s<-\n"+
		"%(red)\tScID ->%s<-\n"+
		"%(red)--------------------------------------------------------------------------------------------------\n\n",
		pp.Email, log_enc.EncryptLogItem(pp.Pw), pp.AmIKnown, pp.XsrfId, hashOfHeaders, pp.FPData, pp.ScID)

	//dbgo.Fprintf(perReqLog, "\n--------------------------------------------------------------------------------------------------\n")
	//dbgo.Fprintf(perReqLog, "AT: %(LF)\n\temail ->%s<- pw ->%s<-\n\tAmIKnown ->%s<-     XsrfId ->%s<-\n", pp.Email, log_enc.EncryptLogItem(pp.Pw), pp.AmIKnown, pp.XsrfId)
	//dbgo.Fprintf(perReqLog, "\thashOfHeadrs ->%s<-\n", hashOfHeaders)
	//dbgo.Fprintf(perReqLog, "\tFPData ->%s<-\n", pp.FPData)
	//dbgo.Fprintf(perReqLog, "\tScID ->%s<-\n", pp.ScID)
	//dbgo.Fprintf(perReqLog, "--------------------------------------------------------------------------------------------------\n\n")

	//                            1                2             3                     4                        5                            6                      7                8                          9
	// FUNCTION q_auth_v1_login ( p_email varchar, p_pw varchar, p_am_i_known varchar, p_hmac_password varchar, p_userdata_password varchar, p_fingerprint varchar, p_sc_id varchar, p_hash_of_headers varchar, p_xsrf_id varchar ) RETURNS text
	stmt := "q_auth_v1_login ( $1, $2, $3, $4, $5, $6, $7, $8, $9 )"
	//                                                    1         2      3            4                        5                      6          7        8              9
	rv, err := CallDatabaseJSONFunction(c, stmt, "ee.!!", pp.Email, pp.Pw, pp.AmIKnown, aCfg.EncryptionPassword, aCfg.UserdataPassword, pp.FPData, pp.ScID, hashOfHeaders, pp.XsrfId)
	if err != nil {
		md.AddCounter("jwt_auth_failed_login_attempts", 1)
		return
	}
	dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)

	var rvStatus RvLoginType
	err = json.Unmarshal([]byte(rv), &rvStatus)
	if rvStatus.Status != "success" {
		// xyzzy TODO - add in logging of / reporting of ... reason for failure, XsrfID, FP, y_id, HeaderHash -- Add in md.AddCounter...
		md.AddCounter("jwt_auth_failed_login_attempts", 1)
		rvStatus.LogUUID = GenUUID()

		if logger != nil {
			fields := []zapcore.Field{
				zap.String("message", "Stored Procedure (q_auth_v1_login) error return"),
				zap.String("go_location", dbgo.LF()),
			}
			fields = AppendStructToZapLog(fields, rvStatus)
			logger.Error("failed-to-login", fields...)
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
		} else {
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
		}
		var out LoginError1
		copier.Copy(&out, &rvStatus)
		out.Email = pp.Email
		// c.JSON(http.StatusUnauthorized, LogJsonReturned(perReqLog, rvStatus.StdErrorReturn)) // 401
		c.JSON(http.StatusUnauthorized, LogJsonReturned(perReqLog, out)) // 401
		return
	}

	//  TokenHeaderVSCookie string `json:"token_header_vs_cookie" default:"cookie"`
	if rvStatus.AuthToken != "" {
		// xyzzy TODO - add in logging of / reporting of ... reason for failure, XsrfID, FP, y_id, HeaderHash -- Add in md.AddCounter...
		theJwtToken, err := CreateJWTSignedCookie(c, rvStatus.AuthToken, pp.Email, g_lib.IfTrue(pp.NoCookie == "nc", NoCookie, CookieUsed))
		if err != nil {
			return
		}
		// dbgo.Fprintf(perReqLog, "!! Creating COOKIE Token, Logged In !!  at:%(LF): AuthToken=%s jwtCookieToken=%s email=%s\n", rvStatus.AuthToken, theJwtToken, pp.Email)
		dbgo.Fprintf(perReqLog, "%(green)!! Creating COOKIE Token, Logged In !!  at:%(LF): AuthToken=%s jwtCookieToken=%s email=%s\n", rvStatus.AuthToken, theJwtToken, pp.Email)

		c.Set("__is_logged_in__", "y")
		c.Set("__user_id__", rvStatus.UserId)
		c.Set("__auth_token__", rvStatus.AuthToken)
		rv, mr := ConvPrivs2(perReqLog, rvStatus.Privileges)
		c.Set("__privs__", rv)
		c.Set("__privs_map__", mr)
		c.Set("__email_hmac_password__", aCfg.EncryptionPassword)
		c.Set("__user_password__", aCfg.UserdataPassword) // __userdata_password__
		c.Set("__client_id__", rvStatus.ClientId)

		md.AddCounter("jwt_auth_success_login", 1)

		if theJwtToken != "" {
			// "Progressive improvement beats delayed perfection" -- Mark Twain
			if aCfg.TokenHeaderVSCookie == "cookie" {
				rvStatus.Token = ""
				c.Set("__jwt_token__", "")
				c.Set("__jwt_cookie_only__", "yes")
			} else { // header or both
				rvStatus.Token = theJwtToken
				c.Set("__jwt_token__", theJwtToken)
			}
		}

		// xyzzyRedisUsePubSub gCfg.RedisUsePubSub   string `json:"redis_use_pub_sub" default:"no"`
		if gCfg.RedisUsePubSub == "yes" {
			RedisBrodcast(rvStatus.AuthToken, fmt.Sprintf(`{"cmd":"/auth/login","auth_token":%q,"user_id":%q}`, rvStatus.AuthToken, rvStatus.UserId))
		}
	}

	// {ReqVar: "__hash_of_headers__", ParamName: "p_hash_of_headers"},
	// hashOfHeaders := HeaderFingerprint(c)
	c.Set("__hash_of_headers__", hashOfHeaders)

	// send email if a login is from a new device. ??
	if rvStatus.IsNewDeviceLogin == "y" {
		dbgo.Fprintf(perReqLog, "at:%(LF) data=%s\n", XArgs(em, "login_new_device",
			"username", pp.Email,
			"email", pp.Email,
			"email_url_encoded", url.QueryEscape(pp.Email),
			"first_name", rvStatus.FirstName,
			"last_name", rvStatus.LastName,
			"real_name", rvStatus.FirstName+" "+rvStatus.LastName,
			"application_name", gCfg.AuthApplicationName,
			"realm", gCfg.AuthRealm,
			"server", gCfg.BaseServerURL,
			"reset_password_uri", gCfg.AuthPasswordRecoveryURI,
		))
		if false {
			em.SendEmail("login_new_device",
				"username", pp.Email,
				"email", pp.Email,
				"email_url_encoded", url.QueryEscape(pp.Email),
				"first_name", rvStatus.FirstName,
				"last_name", rvStatus.LastName,
				"real_name", rvStatus.FirstName+" "+rvStatus.LastName,
				"application_name", gCfg.AuthApplicationName,
				"realm", gCfg.AuthRealm,
				"server", gCfg.BaseServerURL,
				"reset_password_uri", gCfg.AuthPasswordRecoveryURI,
			)
		}
	}

	var out LoginSuccess
	copier.Copy(&out, &rvStatus)
	out.Email = pp.Email
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))
}

// -------------------------------------------------------------------------------------------------------------------------
// HeaderFingerprint takes a set of headers and hashes the set strings and returns it.
//
//  3. Add in server-side hash of headers on login to validate
//     For added security our server keeps track of the browser fingerprint. At the moment we use the following headers:
//     HTTP_ACCEPT_* headers
//     HTTP_USER_AGENT
//
//     There are a few HTTP headers which can be used to create a fingerprint about a user. Here are some of the main ones:
//
//     User-Agent provides information about the browser and its operating system (including its versions).
//     Accept tells the server what content types the browser can render and send, and Content-Encoding provides data about the content compression.
//     Content-Language and Accept-Language both indicate the user's (and browser's) preferred language.
func HeaderFingerprint(c *gin.Context) (hashOfHeaders string) {
	hashOfHeaders = "Xyzzy8"
	h := sha256.New()
	for key, hArr := range c.Request.Header {
		if len(hArr) > 0 {
			hdr := hArr[0]
			if strings.EqualFold(key, "User-Agent") {
				h.Write([]byte(hdr))
			} else if strings.EqualFold(key, "Content-Language") {
				h.Write([]byte(hdr))
			} else if strings.EqualFold(key, "Accept-Language") {
				h.Write([]byte(hdr))
			} else if strings.HasPrefix(strings.ToUpper(key), "ACCEPT_") {
				h.Write([]byte(hdr))
			}
		}
	}
	hashOfHeaders = fmt.Sprintf("%x", (h.Sum(nil)))
	return
}

// -------------------------------------------------------------------------------------------------------------------------
// fields = AppendStructToZapLog ( fields, rvStatus )
// fields := []zapcore.Field{
func AppendStructToZapLog(fields []zapcore.Field, input interface{}) []zapcore.Field {
	s := dbgo.SVar(input)
	md := make(map[string]interface{})
	json.Unmarshal([]byte(s), &md)
	for kk, vv := range md {
		fields = append(fields, zap.String(kk, fmt.Sprintf("%s", vv)))
	}
	return fields
}

// -------------------------------------------------------------------------------------------------------------------------

func ValidateXsrfId(c *gin.Context, XsrfId string) (err error) {
	perReqLog := tf.GetLogFilePtr(c)
	stmt := "q_auth_v1_validate_xsrf_id ( $1, $2, $3 )"
	rv, err := CallDatabaseJSONFunction(c, stmt, "e!!", XsrfId, aCfg.EncryptionPassword, aCfg.UserdataPassword)
	if err != nil {
		return fmt.Errorf("Invalid Xref ID - error in database call")
	}
	dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)

	var rvStatus RvLoginType
	err = json.Unmarshal([]byte(rv), &rvStatus)
	if rvStatus.Status != "success" {
		rvStatus.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
		c.JSON(http.StatusUnauthorized, LogJsonReturned(perReqLog, rvStatus.StdErrorReturn)) // 401
		return fmt.Errorf("Invalid Xref ID")
	}
	return
}

// -------------------------------------------------------------------------------------------------------------------------

// Returned form stored procedure
//
//	l_data = '{"status":"error","msg":"Account already exists.  Please login or recover password.","code":"0007","location":"m4___file__ m4___line__"}';
//		||', "user_id":' ||coalesce(to_json(l_user_id)::text,'""')
//
// DB Reutrn Data
type RvRegisterType struct {
	StdErrorReturn
	UserId           string            `json:"user_id,omitempty"`
	EmailVerifyToken string            `json:"email_verify_token,omitempty"`
	Require2fa       string            `json:"require_2fa,omitempty"`
	Secret2fa        string            `json:"secret_2,omitempty"`
	URLFor2faQR      string            `json:"url_for_2fa_qr"`
	TotpSecret       string            `json:"totp_secret"`
	UserConfig       map[string]string `json:"user_config,omitempty"`
	Otp              []string          `json:"otp,omitempty"`
	TmpToken         string            `json:"tmp_token,omitempty"`
	N6               string            `json:"n6"`
}

// Input for api endpoint
type ApiAuthRegister struct {
	Email     string `json:"email"      form:"email"       binding:"required,email"`
	FirstName string `json:"first_name" form:"first_name"  binding:"required"`
	LastName  string `json:"last_name"  form:"last_name"   binding:"required"`
	Pw        string `json:"password"   form:"password"    binding:"required"`
	AgreeTOS  string `json:"agree_tos"  form:"agree_tos"`
	AgreeEULA string `json:"agree_eula" form:"agree_eula"`
	Data      string `json:"data"       form:"data"`
}

// Output returned
type RegisterSuccess struct {
	Status      string            `json:"status"`
	URLFor2faQR string            `json:"url_for_2fa_qr,omitempty"`
	TotpSecret  string            `json:"totp_secret,omitempty"`
	UserConfig  map[string]string `json:"user_config,omitempty"`
	Otp         []string          `json:"otp,omitempty"`
	TmpToken    string            `json:"tmp_token,omitempty"` // May be "" - used in 2fa part 1 / 2
	Require2fa  string            `json:"require_2fa,omitempty"`
	Email       string            `json:"email,omitempty"`
}

// authHandleRegister godoc
// @Summary Register a new user - Part 1 before 2FA pin and email validation.  Part 2 and 3 are the email conformation and the use of the 6 digit 2fa pin.
// @Schemes
// @Description Call will create a new user.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   email       formData    string     true        "Email Address"
// @Param   pw          formData    string     true        "Password"
// @Param   first_name  formData    string     true        "First Name"
// @Param   last_name   formData    string     true        "Last Name"
// @Param   agree_tos   formData    string     false       "Aggree To Terms of Service"
// @Param   agree_eula  formData    string     false       "Aggree To Terms of EULA"
// @Produce json
// @Success 200 {object} jwt_auth.RegisterSuccess
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/register [post]
func authHandleRegister(c *gin.Context) {
	var err error
	perReqLog := tf.GetLogFilePtr(c)
	var pp ApiAuthRegister
	var RegisterResp RvRegisterType
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}
	if pp.AgreeTOS == "on" {
		pp.AgreeTOS = "y"
	} else {
		pp.AgreeTOS = "n"
	}
	if pp.AgreeEULA == "on" {
		pp.AgreeEULA = "y"
	} else {
		pp.AgreeEULA = "n"
	}

	pp.Email = cleanupEmail(pp.Email)
	pp.Pw = cleanupPw(pp.Pw)

	if IsXDBOn("authHandleRegister:error01") {
		RegisterResp.LogUUID = GenUUID()
		RegisterResp.Status = "error"
		RegisterResp.Msg = "Simulated Error"
		RegisterResp.Code = "0000"
		RegisterResp.Location = dbgo.LF()
		c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, RegisterResp.StdErrorReturn))
		return
	}

	secret := GenerateSecret()

	//                      1             2             3                        4                     5                    6                            7                    8                  9                     10
	// q_auth_v1_register ( p_email varchar, p_pw varchar, p_hmac_password varchar, p_first_name varchar, p_last_name varchar, p_userdata_password varchar, p_secret varchar, p_n6_flag varchar, p_agree_eula varchar, p_agree_tos varchar )
	stmt := "q_auth_v1_register ( $1, $2, $3, $4, $5, $6, $7, $8, $9, $10 )"
	//                                                       1         2      3                        4             5            6                      7       8                    9             10
	rv, err := CallDatabaseJSONFunction(c, stmt, "ee!ee!..", pp.Email, pp.Pw, aCfg.EncryptionPassword, pp.FirstName, pp.LastName, aCfg.UserdataPassword, secret, gCfg.AuthEmailToken, pp.AgreeEULA, pp.AgreeTOS)
	if err != nil {
		return
	}
	dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
	err = json.Unmarshal([]byte(rv), &RegisterResp)
	if RegisterResp.Status != "success" {
		time.Sleep(1500 * time.Millisecond)
		RegisterResp.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "ee!ee!..ee", SVar(RegisterResp), pp.Email, pp.Pw /*aCfg.EncryptionPassword,*/, pp.FirstName, pp.LastName /*, aCfg.UserdataPassword*/, secret, gCfg.AuthEmailToken, pp.AgreeEULA, pp.AgreeTOS)
		c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, RegisterResp.StdErrorReturn))
		return
	}

	if gCfg.AuthEmailToken == "n6" {
		RegisterResp.EmailVerifyToken = RegisterResp.N6
	}

	// set Cookie for SavedState -- Save into database
	cookieValue := GenUUID()
	SetCookie("X-Saved-State", cookieValue, c)
	err = SaveState(cookieValue, RegisterResp.UserId, c)
	if err != nil {
		return
	}

	dbgo.Printf("%(yellow)%(LF) post register: email=%s data=%s\n", pp.Email, pp.Data)
	if pp.Data != "" {
		// CREATE OR REPLACE FUNCTION a_apply_coupon_for_crdits ( p_email varchar, p_coupon varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
		// rv, err := callme.CallAuthPostRegister(c, pp.Email, pp.Data, aCfg.EncryptionPassword, aCfg.UserdataPassword)
		/*
			rv, err := callme.CallQQrAdminPostRegister(c, pp.Email, pp.Data)

			if err != nil {
				c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, gin.H{ // 400
					"status": "error",
					"msg":    fmt.Sprintf("Error: %s", err),
				}))
				return
			}
		*/
		dbgo.Printf("%(yellow)%(LF) post register: email=%s data=%s\n", pp.Email, pp.Data)
		rv, err := callme.CallAuthPostRegister(c, pp.Email, pp.Data)
		dbgo.Printf("%(yellow)%(LF) post register: %s %s\n", err, dbgo.SVarI(rv))
	}

	// ---------------------------------------------------------------------------------------------------------------------
	// send email with validation - using: RegisterResp.EmailVerifyToken
	// ---------------------------------------------------------------------------------------------------------------------
	em.SendEmail("welcome_registration", // Email Template
		"username", pp.Email,
		"email", pp.Email,
		"email_url_encoded", url.QueryEscape(pp.Email),
		"first_name", pp.FirstName,
		"last_name", pp.LastName,
		"real_name", pp.FirstName+" "+pp.LastName,
		"token", RegisterResp.EmailVerifyToken,
		"user_id", RegisterResp.UserId,
		"server", gCfg.BaseServerURL,
		"application_name", gCfg.AuthApplicationName,
		"realm", gCfg.AuthRealm,
	)

	// ---------------------------------------------------------------------------------------------------------------------
	// setup the QR code and link for 2fa tool
	// ---------------------------------------------------------------------------------------------------------------------
	if RegisterResp.Require2fa == "y" {
		RegisterResp.TotpSecret = secret     // 	if htotp.CheckRfc6238TOTPKeyWithSkew(username, pin2fa, RegisterResp.Secret2fa, 0, 1) {
		totp := htotp.NewDefaultTOTP(secret) // totp := htotp.NewDefaultTOTP(RegisterResp.Secret2fa)
		QRUrl := totp.ProvisioningUri(pp.Email /*username*/, gCfg.AuthRealm)
		RegisterResp.URLFor2faQR = MintQRPng(c, QRUrl)
	} else {
		RegisterResp.TotpSecret = ""
		RegisterResp.URLFor2faQR = ""
	}

	var out RegisterSuccess
	copier.Copy(&out, &RegisterResp)
	out.Email = pp.Email
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))
}

// -------------------------------------------------------------------------------------------------------------------------
// -------------------------------------------------------------------------------------------------------------------------
type QrForSecretSuccess struct {
	Status      string `json:"status"`
	Secret      string `json:"secret"`
	URLFor2faQR string `json:"url_for_2fa_qr"`
}

type ApiAuthQrForSecret struct {
	Email  string `json:"email"      form:"email"       binding:"required,email"`
	Secret string `json:"secret"     form:"secret"      binding:"required"`
}

func authHandleGenerateQRForSecret(c *gin.Context) {
	perReqLog := tf.GetLogFilePtr(c)
	var pp ApiAuthQrForSecret
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	pp.Email = cleanupEmail(pp.Email)

	totp := htotp.NewDefaultTOTP(pp.Secret) // totp := htotp.NewDefaultTOTP(RegisterResp.Secret2fa)
	QRUrl := totp.ProvisioningUri(pp.Email /*username*/, gCfg.AuthRealm)
	URLFor2faQR := MintQRPng(c, QRUrl)

	out := QrForSecretSuccess{
		Status:      "success",
		Secret:      pp.Secret,
		URLFor2faQR: URLFor2faQR,
	}
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))
}

// -------------------------------------------------------------------------------------------------------------------------
// register client user account.
//
//		{Method: "POST", Path: "/api/v1/auth/register-client-admin", Fx: authHandleRegisterClientAdmin, UseLogin: PublicApiCall}, // un + pw + first_name + last_name + token to lead to client account
//
//
//
//		{Method: "POST", Path: "/api/v1/auth/register-client-admin", Fx: authHandleRegisterClientAdmin, UseLogin: PublicApiCall}, // un + pw + first_name + last_name + token to lead to client account:w
//	 create or replace function q_auth_v1_register_client ( p_email varchar, p_pw varchar, p_hmac_password varchar, p_first_name varchar, p_last_name varchar, p_userdata_password varchar, p_secret varchar, p_registration_token uuid )
//
// -------------------------------------------------------------------------------------------------------------------------
type RvRegisterClientAdminType struct {
	StdErrorReturn
	UserId           string   `json:"user_id,omitempty"`
	EmailVerifyToken string   `json:"email_verify_token,omitempty"`
	Require2fa       string   `json:"require_2fa,omitempty"`
	Secret2fa        string   `json:"secret_2,omitempty"`
	URLFor2faQR      string   `json:"url_for_2fa_qr"`
	TotpSecret       string   `json:"totp_secret"`
	Otp              []string `json:"otp,omitempty"`
	TmpToken         string   `json:"tmp_token,omitempty"` // May be "" - used in 2fa part 1 / 2
	N6               string   `json:"n6"`
}

// Input for api endpoint
type ApiAuthRegisterClientAdmin struct {
	Email     string `json:"email"      form:"email"       binding:"required,email"`
	FirstName string `json:"first_name" form:"first_name"  binding:"required"`
	LastName  string `json:"last_name"  form:"last_name"   binding:"required"`
	Pw        string `json:"password"   form:"password"    binding:"required"`
	Token     string `json:"token"      form:"token"       binding:"required"`
}

// authHandleClientAdminRegister godoc
// @Summary Register a new user - Part 1 before 2FA pin and email validation.  Part 2 and 3 are the email conformation and the use of the 6 digit 2fa pin.  This registration will set the client_id
// @Schemes
// @Description Call will create a new user.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   email     formData    string     true        "Email Address"
// @Param   pw        formData    string     true        "Password"
// @Param   first_name  formData    string     true        "First Name"
// @Param   last_name   formData    string     true        "Last Name"
// @Produce json
// @Success 200 {object} jwt_auth.RegisterSuccess
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/register-client-admin [post]
func authHandleRegisterClientAdmin(c *gin.Context) {
	// -------------------------------------------------------------------------------------------------------------------------
	// TODO
	// -------------------------------------------------------------------------------------------------------------------------
	var err error
	var pp ApiAuthRegisterClientAdmin
	var RegisterResp RvRegisterClientAdminType
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	pp.Email = cleanupEmail(pp.Email)
	pp.Pw = cleanupPw(pp.Pw)

	perReqLog := tf.GetLogFilePtr(c)

	if IsXDBOn("authHandleRegister:error01") {
		RegisterResp.LogUUID = GenUUID()
		RegisterResp.Status = "error"
		RegisterResp.Msg = "Simulated Error"
		RegisterResp.Code = "0000"
		RegisterResp.Location = dbgo.LF()
		c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, RegisterResp.StdErrorReturn))
		return
	}

	secret := GenerateSecret()

	//                             1                2             3                        4                     5                    6                            7                 8                          9
	// q_auth_v1_register_client ( p_email varchar, p_pw varchar, p_hmac_password varchar, p_first_name varchar, p_last_name varchar, p_userdata_password varchar, p_secret varchar, p_registration_token uuid, p_n6_flag varchar ) RETURNS text
	stmt := "q_auth_v1_register_client ( $1, $2, $3, $4, $5, $6, $7, $8, $9 )"
	//                                                      1         2      3                        4             5            6                      7       8          9
	rv, err := CallDatabaseJSONFunction(c, stmt, "ee.ee..", pp.Email, pp.Pw, aCfg.EncryptionPassword, pp.FirstName, pp.LastName, aCfg.UserdataPassword, secret, pp.Token, gCfg.AuthEmailToken)
	if err != nil {
		return
	}
	dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
	err = json.Unmarshal([]byte(rv), &RegisterResp)
	if RegisterResp.Status != "success" {
		RegisterResp.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "ee!ee!!", SVar(RegisterResp), pp.Email, pp.Pw /*aCfg.EncryptionPassword,*/, pp.FirstName, pp.LastName /*, aCfg.UserdataPassword*/, secret, pp.Token)
		c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, RegisterResp.StdErrorReturn))
		return
	}

	if gCfg.AuthEmailToken == "n6" {
		RegisterResp.EmailVerifyToken = RegisterResp.N6
	}

	// set Cookie for SavedState -- Save into database
	cookieValue := GenUUID()
	SetCookie("X-Saved-State", cookieValue, c)
	err = SaveState(cookieValue, RegisterResp.UserId, c)
	if err != nil {
		return
	}

	// ---------------------------------------------------------------------------------------------------------------------
	// send email with validation - using: RegisterResp.EmailVerifyToken
	// ---------------------------------------------------------------------------------------------------------------------
	em.SendEmail("welcome_registration", // Email Template
		"username", pp.Email,
		"email", pp.Email,
		"email_url_encoded", url.QueryEscape(pp.Email),
		"first_name", pp.FirstName,
		"last_name", pp.LastName,
		"real_name", pp.FirstName+" "+pp.LastName,
		"token", RegisterResp.EmailVerifyToken,
		"user_id", RegisterResp.UserId,
		"server", gCfg.BaseServerURL,
		"application_name", gCfg.AuthApplicationName,
		"realm", gCfg.AuthRealm,
	)

	// ---------------------------------------------------------------------------------------------------------------------
	// setup the QR code and link for 2fa tool
	// ---------------------------------------------------------------------------------------------------------------------
	// Confirm2faSetupAccount(c, *RegisterResp.UserId)

	RegisterResp.TotpSecret = secret     // 	if htotp.CheckRfc6238TOTPKeyWithSkew(username, pin2fa, RegisterResp.Secret2fa, 0, 1) {
	totp := htotp.NewDefaultTOTP(secret) // totp := htotp.NewDefaultTOTP(RegisterResp.Secret2fa)
	QRUrl := totp.ProvisioningUri(pp.Email /*username*/, gCfg.AuthRealm)
	RegisterResp.URLFor2faQR = MintQRPng(c, QRUrl)

	var out RegisterSuccess
	copier.Copy(&out, &RegisterResp)
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))
}

// -------------------------------------------------------------------------------------------------------------------------
func MintQRPng(c *gin.Context, InputString string) (qrurl string) {

	perReqLog := tf.GetLogFilePtr(c)
	dbgo.Fprintf(perReqLog, "at:%(LF)\n")
	qrid := GenUUID() // generate ID
	qrid10 := qrid[0:8] + qrid[9:11]

	redundancy := qr_svr2.Highest

	baseurl := qCfg.QrBaseServerURL
	sin := ""
	if len(baseurl) == 0 {
		err := fmt.Errorf("Invalid Configuration")
		log_enc.LogMiscError(c, err, "Invalid QrBaseServerURL, length 0.  Set \"qr_base_server_url\": \"http://localhost:9080/\" in cfg.json")
		return
	} else if baseurl[len(baseurl)-1:] == "/" {
	} else {
		sin = "/"
	}

	ext := "png"
	mdata := map[string]string{
		"qrext":           ext,
		"baseurl":         baseurl,
		"qrid":            qrid,
		"qr2":             qrid[0:2],              // pull off first 2 chars of qrid
		"qrid10":          qrid[0:8] + qrid[9:11], // pull off first 8 chars of qrid
		"slash_if_needed": sin,
	}

	fn := filelib.Qt(qCfg.QrFilePath, mdata)
	mdata["fn"] = fn
	mdata["qrfn"] = fn
	pth := filepath.Dir(fn)
	mdata["pth"] = pth
	basefn := filepath.Base(fn)
	mdata["basefn"] = basefn
	qrurl = filelib.Qt("%{baseurl%}%{slash_if_needed%}qr/%{qr2%}/%{basefn%}", mdata)
	mdata["qrurl"] = filelib.Qt(qCfg.QrURLPath, mdata)

	dbgo.Fprintf(perReqLog, "%s - at:%(LF)\n", dbgo.SVarI(mdata))

	// create directory
	os.MkdirAll(pth, 0755)

	// open file
	fp, err := filelib.Fopen(fn, "w")
	if err != nil {
		log_enc.LogMiscError(c, err, "Unable to open file")
		return
	}
	defer fp.Close()

	dbgo.Fprintf(perReqLog, "at:%(LF)\n")

	// Generate the QR code in internal format
	var q *qr_svr2.QRCode
	dbgo.DbFprintf("dump-qr-encode-string", perReqLog, "%(Yellow)Encoding  ->%s<- intooo QR.png at:%(LF)\n", InputString)
	q, err = qr_svr2.New(InputString, redundancy)
	qr_svr2.CheckError(err)

	dbgo.Fprintf(perReqLog, "at:%(LF)\n")

	// Output QR Code as a PNG
	var png []byte
	png, err = q.PNG(256)
	qr_svr2.CheckError(err)

	stmt := "insert into q_qr_code ( qrid10, qr_type, body, encoding, img_size, redundancy, direct, file_name, url_name, invert ) values ( $1, $2, $3, $4, $5, $6, $7, $8, $9, $10 )"
	res, err := conn.Exec(ctx, stmt, qrid10, "direct", InputString, "text", 256, "H", "direct", fn, qrurl, "r")
	if err != nil {
		log_enc.LogSQLError(c, stmt, err, "..e.......", qrid10, "direct", InputString, "text", 256, "H", "direct", fn, qrurl, "r") // xyzzy - encrypt
		return
	}
	_ = res

	fp.Write(png)
	return
}

// -------------------------------------------------------------------------------------------------------------------------

// DB Reutrn Data
type RvEmailConfirm struct {
	StdErrorReturn
	Email     string `json:"email,omitempty"`
	TmpToken  string `json:"tmp_token,omitempty"` // May be "" - used in 2fa part 1 / 2
	AcctState string `json:"acct_state,omitempty"`
	AuthToken string `json:"auth_token,omitempty"`
	UserId    string `json:"user_id,omitempty"`
}

// Input for api endpoint
type ApiAuthEmailValidate struct {
	Email            string `json:"email"              form:"email"             `
	EmailVerifyToken string `json:"email_verify_token" form:"email_verify_token"   binding:"required"`
	RedirectTo       string `json:"redirect_to"        form:"redirect_to"`
}

// Output returned
type EmailConfirmSuccess struct {
	Status    string `json:"status"`
	TmpToken  string `json:"tmp_token"`
	AcctState string `json:"acct_state,omitempty"`
}

// authHandlerEmailConfirm uses the token to lookup a user and confirms that the email that received the token is real.
// if websockets are configured then a message will be send to the client:
// 		addHandler("/cient/v1/email-validated", function(pth, parsedMsg ) {
// containing the email, tmp_token and auth_token
//
// From: router.GET("/api/v1/auth/email-confirm", authHandlerEmailConfirm)

// authHandleEmailConfirm godoc
// @Summary Confirm the email from registration.
// @Schemes
// @Description Call uses the provided token to confirm the users email.
// @Tags auth
// @Param   email     formData    string     true        "Email Address"
// @Param   email_verify_token     formData    string     true        "Password Again"
// @Produce json
// @Success 200 {object} jwt_auth.EmailConfirmSuccess
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/email-confirm [get]
func authHandlerEmailConfirm(c *gin.Context) {
	var err error
	var pp ApiAuthEmailValidate
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	pp.Email = cleanupEmail(pp.Email)

	perReqLog := tf.GetLogFilePtr(c)

	rv, stmt, err := ConfirmEmailAccount(c, pp.EmailVerifyToken)
	if err != nil {
		return
	}

	dbgo.Fprintf(perReqLog, "%(LF): confirm-email  rv=%s\n", rv)
	var rvEmailConfirm RvEmailConfirm
	err = json.Unmarshal([]byte(rv), &rvEmailConfirm)
	if rvEmailConfirm.Status != "success" {
		rvEmailConfirm.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "e", SVar(rvEmailConfirm))
		// c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog,rvEmailConfirm.StdErrorReturn)) // 400
		c.Writer.WriteHeader(http.StatusSeeOther) // 303
		to := gCfg.BaseServerURL + gCfg.AuthConfirmEmailErrorURI + "/error-token.html?msg=" + url.QueryEscape(rvEmailConfirm.Msg)
		c.Writer.Header().Set("Location", to)
		// , { path: '/regPt2/:email/:tmp_token',                name: 'regPt2',             component: RegPt2                     }
		html := run_template.RunTemplate("./tmpl/location-error.html.tmpl", "location", map[string]interface{}{
			"destination":  to,
			"error_detail": dbgo.SVarI(LogJsonReturned(perReqLog, rvEmailConfirm.StdErrorReturn)),
			"msg":          rvEmailConfirm.Msg,
		}) // email, tmp_token
		dbgo.Printf("Redirect/location-error.html: ->%(yellow)%s%(reset)<-\n", html)
		fmt.Fprintf(c.Writer, html)

		// xyzzyRedisUsePubSub gCfg.RedisUsePubSub   string `json:"redis_use_pub_sub" default:"no"`
		if gCfg.RedisUsePubSub == "yes" {
			RedisBrodcast(rvEmailConfirm.AuthToken, fmt.Sprintf(`{"cmd":"/auth/email-confirm", "auth_token":%q, "user_id":%q, "email":%q, "tmp_token":%q}`, rvEmailConfirm.AuthToken, rvEmailConfirm.UserId, rvEmailConfirm.Email, rvEmailConfirm.TmpToken))
		}

		// Prevents redirect_to=yes from having any effect ============================================================================================================= <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
		return
	} else {
		if gCfg.RedisUsePubSub == "yes" {
			RedisBrodcast(rvEmailConfirm.AuthToken, fmt.Sprintf(`{"cmd":"/auth/email-confirm-error", "user_id":%q, "email":%q, "tmp_token":%q}`, rvEmailConfirm.UserId, rvEmailConfirm.Email, rvEmailConfirm.TmpToken))
		}
	}

	// handle redirect.
	if pp.RedirectTo == "yes" {
		c.Writer.WriteHeader(http.StatusSeeOther) // 303
		// JOIN is appropriate for RESTful positioal paramters but can be had with template.
		//
		// old...
		// var to string
		// if strings.HasPrefix(gCfg.AuthConfirmEmailURI, "http://") || strings.HasPrefix(gCfg.AuthConfirmEmailURI, "https://") {
		// to, err = url.JoinPath(gCfg.AuthConfirmEmailURI, UrlEscapePeriod(url.QueryEscape(rvEmailConfirm.Email)), url.QueryEscape(rvEmailConfirm.TmpToken))
		// } else {
		// 	to, err = url.JoinPath(gCfg.BaseServerURL, gCfg.AuthConfirmEmailURI, UrlEscapePeriod(url.QueryEscape(rvEmailConfirm.Email)), url.QueryEscape(rvEmailConfirm.TmpToken))
		// }
		// if err != nil {
		// 	dbgo.Fprintf(perReqLog, "Redirect To: ->%s<-\n An error occured in joining the path: %s at:%(LF)\n", to, err)
		// 	dbgo.Fprintf(os.Stderr, "%(red)Redirect To: ->%s<-\n An error occured in joining the path: %s at:%(LF)\n", to, err)
		// 	to = gCfg.BaseServerURL
		// }
		// new...
		to := filelib.Qt(gCfg.AuthConfirmEmailURI, map[string]string{
			"base_server_url": gCfg.BaseServerURL,
			"email_addr":      UrlEscapePeriod(url.QueryEscape(rvEmailConfirm.Email)),
			"tmp_token":       url.QueryEscape(rvEmailConfirm.TmpToken),
		})
		c.Writer.Header().Set("Location", to)
		dbgo.Fprintf(perReqLog, "\n\n------------------------------------------------------------------------------------------------------------\n| Redirect To: ->%s<-\n------------------------------------------------------------------------------------------------------------\n\n", to)
		dbgo.Fprintf(perReqLog, "\n\n%(cyan)------------------------------------------------------------------------------------------------------------\n%(magenta)| Redirect To: ->%s<-\n%(cyan)------------------------------------------------------------------------------------------------------------\n\n", to)
		// Generate the webpage incase Redirect is not followed.  This will attempt to do a client rediret
		// using window.location.  If EcmaScript is disabled then there will be a page with a link to click.
		html := run_template.RunTemplate("./tmpl/location.html.tmpl", "location", map[string]interface{}{
			"destination": to,
			"email":       rvEmailConfirm.Email,
			"tmp_token":   rvEmailConfirm.TmpToken,
		})
		// Dump page to Log File
		dbgo.Fprintf(perReqLog, "Redirect/location.html: ->%s<-\n", html)
		fmt.Fprintf(c.Writer, html)
		// Page should look like...
		//<html>
		//<script>
		//window.location = "%s";
		//</script>
		//<body>
		//	If the browser fails to redirect you then click on the link below:<br>
		//	<br>
		//	<a href="%s">%s</a><br>
		//	<br>
		//</body>
		//</html>
		//`, to, to, to)
		return
	}

	var out EmailConfirmSuccess
	copier.Copy(&out, &rvEmailConfirm)
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out)) // 200

}

// authHandlerValidateEmailConfirm uses the token to lookup a user and confirms that the email that received the token is real.
//
// From: router.GET("/api/v1/auth/email-confirm", authHandlerEmailConfirm)

// authHandleEmailConfirm godoc
// @Summary Confirm the email from registration.
// @Schemes
// @Description Call uses the provided token to confirm the users email.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   email                  formData    string     true        "Email Address"
// @Param   email_verify_token     formData    string     true        "Password Again"
// @Produce json
// @Success 200 {object} jwt_auth.EmailConfirmSuccess
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/email-confirm [post]
func authHandlerValidateEmailConfirm(c *gin.Context) {
	var err error
	var pp ApiAuthEmailValidate
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}
	perReqLog := tf.GetLogFilePtr(c)

	rv, stmt, err := ConfirmEmailAccount(c, pp.EmailVerifyToken)
	if err != nil {
		return
	}

	dbgo.Fprintf(perReqLog, "%(LF): confirm-email  rv=%s\n", rv)
	var rvEmailConfirm RvEmailConfirm
	err = json.Unmarshal([]byte(rv), &rvEmailConfirm)
	if rvEmailConfirm.Status != "success" {
		rvEmailConfirm.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "e", SVar(rvEmailConfirm))
		c.JSON(http.StatusNotAcceptable, LogJsonReturned(perReqLog, rvEmailConfirm.StdErrorReturn)) // 406
		return
	}

	var out EmailConfirmSuccess
	copier.Copy(&out, &rvEmailConfirm)
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out)) // 200

}

func UrlEscapePeriod(s string) (rv string) {
	rv = strings.Replace(s, ".", "%2e", -1)
	return
}

// -------------------------------------------------------------------------------------------------------------------------
// jwtConfig.authInternalHandlers["POST:/api/v1/auth/change-password"] = authHandleChangePassword                       // change passwword
// Input for api endpoint
type ApiAuthChangePassword struct {
	Email   string `json:"email"      form:"email"       binding:"required,email"`
	NewPw   string `json:"new_pw"     form:"new_pw"      binding:"required"`
	OldPw   string `json:"old_pw"     form:"old_pw"      binding:"required"`
	X2FaPin string `json:"x2fa_pin"   form:"x2fa_pin"`
}

// Output returned
type ReturnSuccess struct {
	Status string `json:"status"`
}

// DB Reutrn Data
type RvChangePasswordType struct {
	StdErrorReturn
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
}

// authHandleChangePassword godoc
// @Summary Change Users Password
// @Schemes
// @Description The user can change there own password.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   email     formData    string     true        "Email Address"
// @Param   newpw     formData    string     true        "New Password"
// @Param   oldpw     formData    string     true        "Old Password"
// @Produce json
// @Success 200 {object} jwt_auth.ReturnSuccess
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/change-password [post]
func authHandleChangePassword(c *gin.Context) {
	var pp ApiAuthChangePassword
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	pp.Email = cleanupEmail(pp.Email)
	pp.NewPw = cleanupPw(pp.NewPw)
	pp.OldPw = cleanupPw(pp.OldPw)

	perReqLog := tf.GetLogFilePtr(c)

	if pp.NewPw == pp.OldPw {
		// should be a log call - with a log_enc.LogInputValidationError... call...
		c.JSON(http.StatusNotAcceptable, LogJsonReturned(perReqLog, gin.H{ // 406
			"status": "error",
			"msg":    "Old and new password should be different",
		}))
		return
	}

	_, _, AuthToken := GetAuthToken(c)

	if AuthToken != "" { // if user is logged in then logout - else - just ignore.

		// Check x2faPin for validity for this account.
		stmt := "q_auth_v1_2fa_get_secret ( $1, $2 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, "e.", pp.Email, aCfg.EncryptionPassword)
		if e0 != nil {
			return
		}

		dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
		var rvSecret RvGetSecretType
		err := json.Unmarshal([]byte(rv), &rvSecret)
		if err != nil || rvSecret.Status != "success" {
			rvSecret.LogUUID = GenUUID()
			dbgo.Printf("%(red)%(LF) -- err:%s rvSecret=%s\n", err, dbgo.SVarI(rvSecret))
			log_enc.LogStoredProcError(c, stmt, "e.", SVar(rvSecret), fmt.Sprintf("%s", err))
			c.JSON(http.StatusNotAcceptable, LogJsonReturned(perReqLog, rvSecret.StdErrorReturn)) // 406
			return
		}

		if rvSecret.Require2fa == "y" && pp.X2FaPin == "" {
			rvSecret.LogUUID = GenUUID()
			dbgo.Printf("%(red)%(LF) -- err:%s rvSecret=%s\n", err, dbgo.SVarI(rvSecret))
			log_enc.LogStoredProcError(c, stmt, "e.", SVar(rvSecret), fmt.Sprintf("%s", err))
			c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, rvSecret.StdErrorReturn)) // 400
			return
		}

		// chkSecret allows for multiple secrets in a JSON list, otherwize it just uses the value.
		// So GS2RV3HVX2LTC2PZ is a good secret aw well as
		//    ["GS2RV3HVX2LTC2PZ","G6WAUNNFR6PXPWTL"]
		chkSecret := func(secret string) bool {
			if secret[0:1] == "[" {
				var secret_list []string
				err := json.Unmarshal([]byte(secret), &secret_list)
				if err != nil {
					rvStatus := StdErrorReturn{
						Status:   "error",
						Msg:      "Invalid  format for JSON data - user 2fa secret",
						Location: dbgo.LF(),
						LogUUID:  GenUUID(),
					}
					log_enc.LogAttentionError(c, fmt.Errorf("Internal Data Format Error: %s data %s", err, secret), SVar(rvStatus))
					return false
				}
				for ii, a_secret := range secret_list {
					dbgo.Fprintf(perReqLog, "		Secret[%d] = %s\n", ii, a_secret)
					rv := htotp.CheckRfc6238TOTPKeyWithSkew(pp.Email /*username*/, pp.X2FaPin /*pin2fa*/, a_secret, 1, 2)
					if rv {
						return true
					}
				}
				return false
			} else {
				return htotp.CheckRfc6238TOTPKeyWithSkew(pp.Email /*username*/, pp.X2FaPin /*pin2fa*/, secret, 1, 2)
			}
		}

		if rvSecret.Require2fa == "y" {

			if pp.X2FaPin == "" {
				c.JSON(http.StatusNotAcceptable, StdErrorReturn{ // 406
					Status:   "error",
					Msg:      "A 2fa Pin is Required",
					Code:     "9001",
					Location: dbgo.LF(),
					LogUUID:  GenUUID(),
				})
				// ------------------------------------------------------------------------------------------
				// Early Return if 2fa token is missing.
				// ------------------------------------------------------------------------------------------
				return
			}

			// If the 2fa token fails to validate - then we are done.
			// dbgo.Fprintf(perReqLog, "\n\n%(LF) Secret = %s\n", rvSecret.Secret2fa)
			dbgo.Fprintf(perReqLog, "\n\n%(LF)%(magenta) Secret = %(yellow)%s\n", rvSecret.Secret2fa)
			// if !htotp.CheckRfc6238TOTPKeyWithSkew(pp.Email /*username*/, pp.X2FaPin /*pin2fa*/, rvSecret.Secret2fa, 1, 2) {
			if !chkSecret(rvSecret.Secret2fa) {
				dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
				// xyzzy - log event - TODO
				c.JSON(http.StatusBadRequest, StdErrorReturn{ // 400
					Status:   "error",
					Msg:      "Invalid PIN - Please enter a new PIN",
					Code:     "9001",
					Location: dbgo.LF(),
					LogUUID:  GenUUID(),
				})
				// ------------------------------------------------------------------------------------------
				// Early Return if 2fa token is not valid.
				// ------------------------------------------------------------------------------------------
				return
			}
			dbgo.Fprintf(perReqLog, "%(LF) -- 2fa has been validated -- \n\n")
			dbgo.Fprintf(os.Stderr, "%(LF)%(magenta)  -- 2fa has been validated -- %(reset)\n\n")
		}

		// create or replace function q_auth_v1_change_password ( p_un varchar, p_pw varchar, p_new_pw varchar, p_hmac_password varchar, p_userdata_password varchar )
		stmt = "q_auth_v1_change_password ( $1, $2, $3, $4, $5 )"
		rv, e0 = CallDatabaseJSONFunction(c, stmt, "e....", pp.Email, pp.OldPw, pp.NewPw, aCfg.EncryptionPassword, aCfg.UserdataPassword)
		if e0 != nil {
			// err = e0
			return
		}

		dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
		// var rvStatus RvStatusType
		var rvStatus RvChangePasswordType
		err = json.Unmarshal([]byte(rv), &rvStatus)
		if err != nil || rvStatus.Status != "success" {
			rvStatus.LogUUID = GenUUID()
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
			c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, rvStatus)) // 400
			return
		}

		// xyzzyLogoutForced - send message via websockt to log out all of this user.
		// err = rdb.Del(ctx, fmt.Sprintf("auth_token:%s", pp.AuthToken)).Err()

		// send email about change
		em.SendEmail("password_changed",
			"username", pp.Email,
			"email", pp.Email,
			"email_url_encoded", url.QueryEscape(pp.Email),
			"first_name", rvStatus.FirstName,
			"last_name", rvStatus.LastName,
			"real_name", rvStatus.FirstName+" "+rvStatus.LastName,
			"application_name", gCfg.AuthApplicationName,
			"realm", gCfg.AuthRealm,
			"server", gCfg.BaseServerURL,
			"reset_password_uri", gCfg.AuthPasswordRecoveryURI,
		)

		// em.SendEmail("password_updated", "username", un, "email", emailaddr, "real_name", real_name, "token", recovery_token, "realm", gCfg.AuthRealm, "server", gCfg.AuthSelfURL)
		// "email_url_encoded", url.QueryEscape(pp.Email),
	} else {
		time.Sleep(1500 * time.Millisecond)
	}

	out := ReturnSuccess{Status: "success"}
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out)) // 200

}

// -------------------------------------------------------------------------------------------------------------------------
//	router.POST("/api/v1/auth/recover-password-01-setup", authHandleRecoverPassword01Setup)              //
//	router.GET("/api/v1/auth/recover-password-01-setup", authHandleRecoverPassword01Setup)               //

// DB Reutrn Data
type RvRecoverPassword01Setup struct {
	StdErrorReturn
	RecoveryToken   string `json:"recovery_token,omitempty"`
	RecoveryTokenN6 string `json:"recovery_token_n6,omitempty"`
	FirstName       string `json:"first_name,omitempty"`
	LastName        string `json:"last_name,omitempty"`
	N6Flag          string `json:"n6_flag,omitempty"`
}

// Input for api endpoint
type ApiEmail struct {
	Email string `json:"email"  form:"email"  binding:"required,email"`
}

// Input for api endpoint
type ApiEmailOptional struct {
	Email string `json:"email"  form:"email"`
}

// authHandleRecoverPassword01Setup godoc
// @Summary Start forgotten password process.
// @Schemes
// @Description Send an email to the specified address with a recovery token.  Success even if the email is not a valid email.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   email     formData    string     true        "Email Address"
// @Produce json
// @Success 200 {object} jwt_auth.ReturnSuccess
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/recover-password-01-setup [post]
func authHandleRecoverPassword01Setup(c *gin.Context) {
	var pp ApiEmail
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	pp.Email = cleanupEmail(pp.Email)

	perReqLog := tf.GetLogFilePtr(c)

	// create or replace function q_auth_v1_recover_password_01_setup ( p_un varchar, p_hmac_password varchar, p_userdata_password varchar )
	stmt := "q_auth_v1_recover_password_01_setup ( $1, $2, $3 )"
	rv, e0 := CallDatabaseJSONFunction(c, stmt, "e..", pp.Email, aCfg.EncryptionPassword, aCfg.UserdataPassword)
	if e0 != nil {
		return
	}

	dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
	var rvStatus RvRecoverPassword01Setup
	err := json.Unmarshal([]byte(rv), &rvStatus)
	if err != nil || rvStatus.Status != "success" {
		rvStatus.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
		c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, rvStatus.StdErrorReturn)) // 400
		return
	}

	// AuthPasswordRecoveryURI  string `json:"auth_password_recovery_uri" default:"forgotten-password/web-set-password"` // Path inside app to the form that changes a password
	// http://localhost:15080/popup.html?email=bob@park.com&token=123#PageForgotPassword02
	gCfg_BaseServerURL := gCfg.BaseServerURL
	gCfg_AuthPasswordRecoveryURI := gCfg.AuthPasswordRecoveryURI
	template_name := "recover_password"
	if strings.HasPrefix(gCfg.AuthPasswordRecoveryURI, "http://") || strings.HasPrefix(gCfg.AuthPasswordRecoveryURI, "https://") {
		template_name = "recover_password_tmpl"
		gCfg_BaseServerURL = ""
		dbgo.Fprintf(perReqLog, "%(LF)%(cyan)Has 'http' or 'https'\n")
	}

	// Apply Template : gCfg_AuthPasswordRecoveryURI := gCfg.AuthPasswordRecoveryURI
	// , "x_auth_password_recovery_uri":"http://localhost:15080/popup.html?email={{.email_addr}}&token={{.email_token}}#PageForgotPassword02"
	// {{.email_addr}} and {{.email_token}} may need to be substituted.
	mdata := map[string]string{
		"email_addr":  url.QueryEscape(pp.Email),
		"email_token": rvStatus.RecoveryToken,
	}
	// dbgo.Fprintf(os.Stderr, "%(LF)%(cyan)Before Template ->%s<-\n", gCfg_AuthPasswordRecoveryURI)
	gCfg_AuthPasswordRecoveryURI = filelib.Qt(gCfg.AuthPasswordRecoveryURI, mdata)
	// dbgo.Fprintf(os.Stderr, "%(LF)%(cyan)After  Template ->%s<-\n", gCfg_AuthPasswordRecoveryURI)

	em.SendEmail(template_name,
		"username", pp.Email,
		"email", pp.Email,
		"email_url_encoded", url.QueryEscape(pp.Email),
		"reset_password_uri_enc", gCfg_AuthPasswordRecoveryURI, // xyzzy - should change & to &and;
		"token", rvStatus.RecoveryToken,
		"token_n6", rvStatus.RecoveryTokenN6,
		"first_name", rvStatus.FirstName,
		"last_name", rvStatus.LastName,
		"real_name", rvStatus.FirstName+" "+rvStatus.LastName,
		"application_name", gCfg.AuthApplicationName,
		"realm", gCfg.AuthRealm,
		"server", gCfg_BaseServerURL,
		"reset_password_uri", gCfg_AuthPasswordRecoveryURI,
	)

	time.Sleep(500 * time.Millisecond)

	// Cookies Reset
	SetCookie("X-Authentication", "", c) // Will be a secure http cookie on TLS.
	if gCfg.ReleaseMode == "dev" {
		SetCookie("X-Authentication-User", "", c)
	}
	SetInsecureCookie("X-Is-Logged-In", "no", c) // To let the JS code know that it is logged in.

	out := ReturnSuccess{Status: "success"}
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out)) // 200

}

// -------------------------------------------------------------------------------------------------------------------------
// router.POST("/api/v1/auth/recover-password-02-fetch-info", authHandleRecoverPassword02FetchInfo)     //
// router.GET("/api/v1/auth/recover-password-02-fetch-info", authHandleRecoverPassword02FetchInfo)      //

// DB Reutrn Data
type RvRecoverPassword02FetchInfo struct {
	StdErrorReturn
	Email     string `json:"email,omitempty"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
}

// Input for api endpoint
type ApiAuthRecoveryPassword02FetchInfo struct {
	Email         string `json:"email"          form:"email"            binding:"required,email"`
	RecoveryToken string `json:"recovery_token" form:"recovery_token"   binding:"required"`
}

// Output returned
type RecoverPassword02Success struct {
	Status    string `json:"status"`
	Email     string `json:"email,omitempty"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
}

// authHandleEmailConfirm godoc
// @Summary Return information to recovery form.
// @Schemes
// @Description Information is returned based on an Email and a Token to a recovery form.  The inforaiton if the token is valid is the name of the user.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   email     formData    string     true        "Email Address"
// @Param   recovery_token        formData    string     true        "Recovery Token"
// @Produce json
// @Success 200 {object} jwt_auth.RecoverPassword02Success
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/recover-password-02-fetch-info [post]
func authHandleRecoverPassword02FetchInfo(c *gin.Context) {
	var pp ApiAuthRecoveryPassword02FetchInfo
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	pp.Email = cleanupEmail(pp.Email)

	perReqLog := tf.GetLogFilePtr(c)

	// create or replace function q_auth_v1_recover_password_02_fetch_info ( p_un varchar, p_recovery_token varchar, p_hmac_password varchar, p_userdata_password varchar )
	stmt := "q_auth_v1_recover_password_02_fetch_info ( $1, $2, $3, $4 )"
	rv, e0 := CallDatabaseJSONFunction(c, stmt, "e!..", pp.Email, pp.RecoveryToken, aCfg.EncryptionPassword, aCfg.UserdataPassword)
	if e0 != nil {
		return
	}

	dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
	var rvStatus RvRecoverPassword02FetchInfo
	err := json.Unmarshal([]byte(rv), &rvStatus)
	if err != nil || rvStatus.Status != "success" {
		rvStatus.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
		c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, rvStatus.StdErrorReturn)) // 400
		return
	}

	var out RecoverPassword02Success
	copier.Copy(&out, &rvStatus)
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out)) // 200

}

// -------------------------------------------------------------------------------------------------------------------------
// router.POST("/api/v1/auth/recover-password-03-set-password", authHandleRecoverPassword03SetPassword) //

// DB Reutrn Data
type RvRecoverPassword03SetPassword struct {
	StdErrorReturn
	RecoveryToken string `json:"recovery_token,omitempty"`
	FirstName     string `json:"first_name,omitempty"`
	LastName      string `json:"last_name,omitempty"`
}

// Input for api endpoint
type ApiAuthRecoverPassword03SetPassword struct {
	Email         string `json:"email"          form:"email"           binding:"required,email"`
	NewPw         string `json:"new_pw"         form:"new_pw"          binding:"required"`
	NewPwAgain    string `json:"new_pw_again"   form:"new_pw_again"`
	RecoveryToken string `json:"recovery_token" form:"recovery_token"  binding:"required"`
	X2FaPin       string `json:"x2fa_pin"       form:"x2fa_pin"        `
}

// Output returned
type RecoverPassword03SetPasswordSuccess struct {
	Status    string `json:"status"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
}

// authHandleRecoverPassword03SetPassword godoc
// @Summary Using the recovery token set the users password.
// @Schemes
// @Description Using email and recvoery token set the users password to a new value.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   email           formData    string     true        "Email Address"
// @Param   new_pw          formData    string     true        "Password"
// @Param   recovery_token  formData    string     true        "Recovery Token"
// @Produce json
// @Success 200 {object} jwt_auth.RecoverPassword03SetPasswordSuccess
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/recover-password-03-set-password [post]
func authHandleRecoverPassword03SetPassword(c *gin.Context) {
	var pp ApiAuthRecoverPassword03SetPassword
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	pp.Email = cleanupEmail(pp.Email)
	pp.NewPw = cleanupPw(pp.NewPw)
	pp.NewPwAgain = cleanupPw(pp.NewPwAgain)

	perReqLog := tf.GetLogFilePtr(c)

	// Check x2faPin for validity for this account.
	stmt := "q_auth_v1_2fa_get_secret ( $1, $2 )"
	rv, e0 := CallDatabaseJSONFunction(c, stmt, "e.", pp.Email, aCfg.EncryptionPassword)
	if e0 != nil {
		return
	}

	dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
	var rvSecret RvGetSecretType
	err := json.Unmarshal([]byte(rv), &rvSecret)
	if err != nil || rvSecret.Status != "success" {
		rvSecret.LogUUID = GenUUID()
		dbgo.Printf("%(red)%(LF) -- err:%s rvSecret=%s\n", err, dbgo.SVarI(rvSecret))
		log_enc.LogStoredProcError(c, stmt, "e.", SVar(rvSecret), fmt.Sprintf("%s", err))
		c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, rvSecret.StdErrorReturn)) // 400
		return
	}

	// If require_2fa == "y" - then if pp.x2fa_pin == "" -- error 406.
	if rvSecret.Require2fa == "y" && pp.X2FaPin == "" {
		rvSecret.LogUUID = GenUUID()
		dbgo.Printf("%(red)%(LF) -- err:%s rvSecret=%s\n", err, dbgo.SVarI(rvSecret))
		log_enc.LogStoredProcError(c, stmt, "e.", SVar(rvSecret), fmt.Sprintf("%s", err))
		c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, rvSecret.StdErrorReturn)) // 400
		return
	}

	// chkSecret allows for multiple secrets in a JSON list, otherwize it just uses the value.
	// So GS2RV3HVX2LTC2PZ is a good secret aw well as
	//    ["GS2RV3HVX2LTC2PZ","G6WAUNNFR6PXPWTL"]
	chkSecret := func(secret string) bool {
		if secret[0:1] == "[" {
			var secret_list []string
			err := json.Unmarshal([]byte(secret), &secret_list)
			if err != nil {
				rvStatus := StdErrorReturn{
					Status:   "error",
					Msg:      "Invalid  format for JSON data - user 2fa secret",
					Location: dbgo.LF(),
					LogUUID:  GenUUID(),
				}
				log_enc.LogAttentionError(c, fmt.Errorf("Internal Data Format Error: %s data %s", err, secret), SVar(rvStatus))
				return false
			}
			for ii, a_secret := range secret_list {
				dbgo.Fprintf(perReqLog, "		Secret[%d] = %s\n", ii, a_secret)
				rv := htotp.CheckRfc6238TOTPKeyWithSkew(pp.Email /*username*/, pp.X2FaPin /*pin2fa*/, a_secret, 1, 2)
				if rv {
					return true
				}
			}
			return false
		} else {
			return htotp.CheckRfc6238TOTPKeyWithSkew(pp.Email /*username*/, pp.X2FaPin /*pin2fa*/, secret, 1, 2)
		}
	}

	if rvSecret.Require2fa == "y" {

		if pp.X2FaPin == "" {
			c.JSON(http.StatusNotAcceptable, StdErrorReturn{ // 406
				Status:   "error",
				Msg:      "A 2fa Pin is Required",
				Code:     "9001",
				Location: dbgo.LF(),
				LogUUID:  GenUUID(),
			})
			// ------------------------------------------------------------------------------------------
			// Early Return if 2fa token is missing.
			// ------------------------------------------------------------------------------------------
			return
		}

		// If the 2fa token fails to validate - then we are done.
		// dbgo.Fprintf(perReqLog, "\n\n%(LF) Secret = %s\n", rvSecret.Secret2fa)
		dbgo.Fprintf(perReqLog, "\n\n%(LF)%(magenta) Secret = %(yellow)%s\n", rvSecret.Secret2fa)
		// if !htotp.CheckRfc6238TOTPKeyWithSkew(pp.Email /*username*/, pp.X2FaPin /*pin2fa*/, rvSecret.Secret2fa, 1, 2) {
		if !chkSecret(rvSecret.Secret2fa) {
			dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
			// xyzzy - log event - TODO
			c.JSON(http.StatusBadRequest, StdErrorReturn{ // 400
				Status:   "error",
				Msg:      "Invalid PIN - Please enter a new PIN",
				Code:     "9001",
				Location: dbgo.LF(),
				LogUUID:  GenUUID(),
			})
			// ------------------------------------------------------------------------------------------
			// Early Return if 2fa token is not valid.
			// ------------------------------------------------------------------------------------------
			return
		}
		//dbgo.Fprintf(perReqLog, "%(LF) -- 2fa has been validated -- \n\n")
		dbgo.Fprintf(perReqLog, "%(LF)%(magenta)  -- 2fa has been validated -- %(reset)\n\n")

	}

	// create or replace function q_auth_v1_recover_password_03_set_password ( p_un varchar, p_new_pw varchar, p_recovery_token varchar, p_hmac_password varchar, p_userdata_password varchar )
	stmt = "q_auth_v1_recover_password_03_set_password ( $1, $2, $3, $4, $5 )"
	rv, e0 = CallDatabaseJSONFunction(c, stmt, "ee!..", pp.Email, pp.NewPw, pp.RecoveryToken, aCfg.EncryptionPassword, aCfg.UserdataPassword)
	if e0 != nil {
		return
	}

	dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
	var rvStatus RvRecoverPassword03SetPassword
	err = json.Unmarshal([]byte(rv), &rvStatus)
	if err != nil || rvStatus.Status != "success" {
		rvStatus.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
		c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, rvStatus.StdErrorReturn)) // 400
		return
	}

	em.SendEmail("password_updated",
		"username", pp.Email,
		"email", pp.Email,
		"email_url_encoded", url.QueryEscape(pp.Email),
		"first_name", rvStatus.FirstName,
		"last_name", rvStatus.LastName,
		"real_name", rvStatus.FirstName+" "+rvStatus.LastName,
		"application_name", gCfg.AuthApplicationName,
		"token", rvStatus.RecoveryToken,
		"realm", gCfg.AuthRealm,
		"server", gCfg.BaseServerURL,
	)

	// Cookies Reset
	SetCookie("X-Authentication", "", c) // Will be a secure http cookie on TLS.
	if gCfg.ReleaseMode == "dev" {
		SetCookie("X-Authentication-User", "", c)
	}
	SetInsecureCookie("X-Is-Logged-In", "no", c) // To let the JS code know that it is logged in.

	var out RecoverPassword03SetPasswordSuccess
	copier.Copy(&out, &rvStatus)
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out)) // 200

}

// -------------------------------------------------------------------------------------------------------------------------
// authHandleLogout godoc
// @Summary Log the user out.
// @Schemes
// @Description If the user is currently logged in then delect the login auth-token.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   email     formData    string     true        "Email Address"
// @Produce json
// @Success 200 {object} jwt_auth.ReturnSuccess
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/logout [post]
func authHandleLogout(c *gin.Context) {
	perReqLog := tf.GetLogFilePtr(c)
	var UserId, AuthToken string
	var pp ApiEmailOptional
	if err := BindFormOrJSONOptional(c, &pp); err != nil {
		goto done
	}
	if pp.Email == "" {
		goto done
	}
	UserId, _, AuthToken = GetAuthToken(c)
	if AuthToken == "" {
		time.Sleep(1500 * time.Millisecond)
		goto done
	}

	if AuthToken != "" { // if user is logged in then logout - else - just ignore.
		DumpParamsToLog("After Auth - Top", c)

		// create or replace function q_auth_v1_logout ( p_un varchar, p_auth_token varchar, p_hmac_password varchar )
		stmt := "q_auth_v1_logout ( $1, $2, $3 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, "e!.", pp.Email, AuthToken, aCfg.EncryptionPassword)
		if e0 != nil {
			return
		}

		dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
		// var rvStatus RvStatusType
		var rvStatus StdErrorReturn
		err := json.Unmarshal([]byte(rv), &rvStatus)
		if err != nil || rvStatus.Status != "success" {
			rvStatus.LogUUID = GenUUID()
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
			c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, rvStatus)) // 400
			return
		}

		// xyzzyRedisUsePubSub gCfg.RedisUsePubSub   string `json:"redis_use_pub_sub" default:"no"`
		if gCfg.RedisUsePubSub == "yes" {
			RedisBrodcast(AuthToken, fmt.Sprintf(`{"cmd":"/auth/logout","auth_token":%q,"user_id":%q}`, AuthToken, UserId))
		}

	}

done:

	dbgo.Fprintf(perReqLog, "# In Handler at %(LF) - Logout / not authenticated on server side\n")

	// Cookies Reset
	SetCookie("X-Authentication", "", c) // Will be a secure http cookie on TLS.
	if gCfg.ReleaseMode == "dev" {
		SetCookie("X-Authentication-User", "", c)
	}
	SetInsecureCookie("X-Is-Logged-In", "no", c) // To let the JS code know that it is logged in.

	out := ReturnSuccess{Status: "success"}
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out)) // 200

}

// -------------------------------------------------------------------------------------------------------------------------
// jwtConfig.authInternalHandlers["GET:/api/v1/auth/2fa-has-been-setup"] = authHandle2faHasBeenSetup

// Output returned
type X2faSetupSuccess struct {
	Status        string `json:"status"`
	Msg           string `json:"msg"`
	X2faValidated string `json:"x2fa_validated,omitempty"`
}

// authHandle2faHasBeenSetup godoc
// @Summary Search user to see if 2fa setup is complete.
// @Schemes
// @Description Return status information on the user to show if 2fa setup has been completed at the end of registration.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   email     formData    string     true        "Email Address"
// @Produce json
// @Success 200 {object} jwt_auth.X2faSetupSuccess
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/2fa-has-been-setup [get]
func authHandle2faHasBeenSetup(c *gin.Context) {
	perReqLog := tf.GetLogFilePtr(c)
	var err error
	var pp ApiEmail
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	time.Sleep(500 * time.Millisecond)

	var v2 []*SQLStringType
	stmt := `
		select 'found' as "x" 
			from q_qr_users  as t1
			where t1.email_hmac = hmac($1, $2, 'sha256')
			  and ( t1.setup_complete_2fa = 'y' or t1.require_2fa = 'n' )
	`
	err = pgxscan.Select(ctx, conn, &v2, stmt, pp.Email, aCfg.EncryptionPassword)
	if err != nil {
		log_enc.LogSQLError(c, stmt, err, "e!", pp.Email, aCfg.EncryptionPassword)
		return
	}

	out := X2faSetupSuccess{Status: "success"}
	// c.JSON(http.StatusOK, LogJsonReturned(perReqLog,out)) // 200
	if len(v2) > 0 {
		out.Msg = "2FA has been Setup"
		out.X2faValidated = "y"
		c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))
		return
	}

	out.Msg = "2FA *not* Setup"
	out.X2faValidated = "n"
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))

}

// -------------------------------------------------------------------------------------------------------------------------
// router.GET("/api/v1/auth/email-has-been-validated", authHandleEmailHasBeenSetup)                     //

// Output returned
type EmailSetupSuccess struct {
	Status         string `json:"status"`
	Msg            string `json:"msg"`
	EmailValidated string `json:"email_validated,omitempty"`
}

// authHandleEmailHasBeenSetup godoc
// @Summary Confirm the email from registration.
// @Schemes
// @Description Return status that shows if the email address has been confirmed.  Prior to this point you can not recover the password.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   email     formData    string     true        "Email Address"
// @Produce json
// @Success 200 {object} jwt_auth.X2faSetupSuccess
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/email-has-been-validated [get]
func authHandleEmailHasBeenSetup(c *gin.Context) {
	perReqLog := tf.GetLogFilePtr(c)
	var err error
	var pp ApiEmail
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	time.Sleep(500 * time.Millisecond)

	var v2 []*SQLStringType
	stmt := `
		select 'found' as "x" 
			from q_qr_users  as t1
			where t1.email_hmac = hmac($1, $2, 'sha256')
			  and t1.email_validated = 'y'
	`
	err = pgxscan.Select(ctx, conn, &v2, stmt, pp.Email, aCfg.EncryptionPassword)
	if err != nil {
		log_enc.LogSQLError(c, stmt, err, "e!", pp.Email, aCfg.EncryptionPassword)
		return
	}

	out := EmailSetupSuccess{Status: "success"}
	if len(v2) > 0 {
		out.Msg = "Email has been Setup"
		out.EmailValidated = "y"
	} else {
		out.Msg = "Email *not* Setup"
		out.EmailValidated = "n"
		time.Sleep(1000 * time.Millisecond)
	}
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))

}

// -------------------------------------------------------------------------------------------------------------------------
// router.GET("/api/v1/auth/acct-status", authHandleAcctHasBeenSetup)                                   // (new)

type SQLAcctStatusType struct {
	SetupComplete2fa string `json:"setup_complete_2fa" db:"setup_complete_2fa"`
	EmailValidated   string `json:"email_validated"    db:"email_validated"`
	Require2fa       string `json:"require_2fa"        db:"require_2fa"`
}

// Output returned
type AcctSetupSuccess struct {
	Status         string `json:"status"`
	X2faValidated  string `json:"x2fa_validated,omitempty"`
	EmailValidated string `json:"email_validated,omitempty"`
	Msg            string `json:"msg,omitempty"`
}

// authHandleAcctHasBeenSetup godoc
// @Summary Return 2fa and email validation setup information.
// @Schemes
// @Description search the account to show if 2fa is setup and email have been validated.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   email     formData    string     true        "Email Address"
// @Produce json
// @Success 200 {object} jwt_auth.AcctSetupSuccess
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/acct-status [get]
func authHandleAcctHasBeenSetup(c *gin.Context) {
	perReqLog := tf.GetLogFilePtr(c)
	var err error
	var pp ApiEmail
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	time.Sleep(500 * time.Millisecond)

	var v2 []*SQLAcctStatusType
	stmt := `
		select t1.setup_complete_2fa 
				, t1.email_validated 
				, t1.require_2fa
			from q_qr_users  as t1
			where t1.email_hmac = hmac($1, $2, 'sha256')
	`
	err = pgxscan.Select(ctx, conn, &v2, stmt, pp.Email, aCfg.EncryptionPassword)
	if err != nil {
		log_enc.LogSQLError(c, stmt, err, "e!", pp.Email, aCfg.EncryptionPassword)
		return
	}
	if len(v2) > 0 {
		out := AcctSetupSuccess{Status: "success",
			X2faValidated:  v2[0].SetupComplete2fa,
			EmailValidated: v2[0].EmailValidated,
		}
		if v2[0].Require2fa == "n" {
			out.X2faValidated = "y"
		}
		c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))
		return
	}
	out := AcctSetupSuccess{Status: "error", Msg: "User Not Found"}
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))

}

// -------------------------------------------------------------------------------------------------------------------------
// router.GET("/api/v1/setDebugFlag", authHandlerSetDebugFlag)

// Input for api endpoint
type ApiAuthSetDebugFlag struct {
	Name    string `json:"name"          form:"name"           binding:"required"`
	Value   string `json:"value"         form:"value"          binding:"required"`
	AuthKey string `json:"auth_key"      form:"auth_key"`
}

// Output returned
type SetDebugFlagSuccess struct {
	Status string `json:"status"`
}

// authHandlerSetDebugFlag godoc
// @Summary Turns on or off a debug flag.
// @Schemes
// @Description Enable/Disable debugging/testing flags.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   name     formData    string     true        "Flag Name"
// @Param   value    formData    string     true        "true=Enabled, false=Disabled, y/n, Y/N, etc...""
// @Produce json
// @Success 200 {object} jwt_auth.AcctSetupSuccess
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/set-debug-flag [get]
func authHandlerSetDebugFlag(c *gin.Context) {
	perReqLog := tf.GetLogFilePtr(c)
	var pp ApiAuthSetDebugFlag
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	if HashStrings.HashStrings(pp.AuthKey) != "d1925935f59354de774257bd02867eca749b617b21641f66aba49447f02ae377" {
		out := SetDebugFlagSuccess{Status: "error"}
		c.JSON(http.StatusUnauthorized, LogJsonReturned(perReqLog, out)) // 401
		return
	}

	exi := ParseBool(pp.Value)
	XDbOnLock.Lock()
	XDbOn[pp.Name] = exi
	XDbOnLock.Unlock()

	out := SetDebugFlagSuccess{Status: "success"}
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))
	return
}

// -------------------------------------------------------------------------------------------------------------------------
// router.POST("/api/v1/auth/validate-2fa-token", authHandleValidate2faToken)                           // 2nd step 2fa - create auth-token / jwtToken Sent

// DB Reutrn Data
type RvValidate2faTokenType struct {
	StdErrorReturn
	UserId         string   `json:"user_id,omitempty"`
	AuthToken      string   `json:"auth_token,omitempty"` // May be "" - meaning no auth.
	Token          string   `json:"token,omitempty"`
	Expires        string   `json:"expires,omitempty"`
	Privileges     []string `json:"privileges,omitempty"`
	Secret2fa      string   `json:"secret_2fa,omitempty"`
	EmailValidated string   `json:"email_validated,omitempty"`
	X2faValidated  string   `json:"x2fa_validated,omitempty"`
	ClientId       string   `json:"client_id,omitempty"`
	AcctState      string   `json:"acct_state,omitempty"`
}

type RvGetSecretType struct {
	StdErrorReturn
	Secret2fa  string `json:"secret_2fa"`
	UserId     string `json:"user_id"`
	Require2fa string `json:"require_2fa,omitempty"`
}

var PrivilegedNames = []string{"__is_logged_in__", "__user_id__", "__auth_token__", "__privs__", "__privs_map__", "__jwt_token__", "__email_hmac_password__", "__user_password__", "__client_id__"}

// authHandleValidate2faToken is called after login to validate a 2fa token and after registration to comnplete the registration.
//
// This calls: "q_auth_v1_validate_2fa_token ( $1, $2, $3, $4, $5 )" in the databse.
// This sets q_qr_users.setup_complete_2fa  = 'y' to mark the account as fully registered.
// Login requires that this is a 'y' before login occures.
//
// Input for api endpoint
type ApiAuthValidate2faToken struct {
	Email            string `json:"email"      form:"email"      binding:"required"`
	TmpToken         string `json:"tmp_token"  form:"tmp_token"  binding:"required"`
	X2FaPin          string `json:"x2fa_pin"   form:"x2fa_pin"   binding:"required"`
	AmIKnown         string `json:"am_i_known" form:"am_i_known"` //
	XsrfId           string `json:"xsrf_id"    form:"xsrf_id"`    // From Login
	FPData           string `json:"fp_data"    form:"fp_data"`    // fingerprint data
	ScID             string `json:"scid"       form:"scid"`       // y_id - local storage ID
	EmailVerifyToken string `json:"email_verify_token" form:"email_verify_token"`

	// You can set any value for the 'no_cookie' data field.   Normally if you want to skip cookies send 'nc' for the value.
	NoCookie string `json:"no_cookie"  form:"no_cookie"` // default is to NOT send cookie if cookies and headers (both ==> , "token_header_vs_cookie": "both") are defined,
}

// Output returned
type Validate2faTokenSuccess struct {
	Status         string `json:"status"`
	Token          string `json:"token,omitempty"`
	EmailValidated string `json:"email_validated,omitempty"`
	X2faValidated  string `json:"x2fa_validated,omitempty"`
	Expires        string `json:"expires,omitempty"`
	AcctState      string `json:"acct_state,omitempty"`
}

// authHandleValidate2faToken godoc
// @Summary validate an email address.
// @Schemes
// @Description is called after login to validate a 2fa token and after registration to comnplete the registration.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   email       formData    string     true        "Email Address"
// @Param   tmp_token   formData    string     true        "tmp_token from /api/v1/register"
// @Param   x2fa_pin    formData    string     true        "2fa 6 Digit Pin"
// @Param   am_i_known  formData    string     true        "UUID from id.json file - for this device"
// @Produce json
// @Success 200 {object} jwt_auth.Validate2faTokenSuccess
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/validate-2fa-token [post]
func authHandleValidate2faToken(c *gin.Context) {
	var pp ApiAuthValidate2faToken
	if err := BindFormOrJSON(c, &pp); err != nil {
		md.AddCounter("jwt_auth_failed_login_attempts", 1)
		return
	}

	pp.Email = cleanupEmail(pp.Email)

	perReqLog := tf.GetLogFilePtr(c)

	// AmIKnown         string `json:"am_i_known" form:"am_i_known"` //
	// XsrfId           string `json:"xsrf_id"    form:"xsrf_id"`    // From Login
	// FPData           string `json:"fp_data"    form:"fp_data"`    // fingerprint data
	// ScID             string `json:"scid"       form:"scid"`       // y_id - local storage ID

	if pp.EmailVerifyToken != "" {
		rv, stmt, err := ConfirmEmailAccount(c, pp.EmailVerifyToken)
		if err != nil {
			md.AddCounter("jwt_auth_failed_login_attempts", 1)
			return
		}

		dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
		var rvEmailConfirm RvEmailConfirm
		err = json.Unmarshal([]byte(rv), &rvEmailConfirm)
		if rvEmailConfirm.Status != "success" {
			md.AddCounter("jwt_auth_failed_login_attempts", 1)
			rvEmailConfirm.LogUUID = GenUUID()
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvEmailConfirm))
			c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, rvEmailConfirm.StdErrorReturn)) // 400
			return
		}
	}

	stmt := "q_auth_v1_2fa_get_secret ( $1, $2 )"
	rv, e0 := CallDatabaseJSONFunction(c, stmt, "e.", pp.Email, aCfg.EncryptionPassword)
	if e0 != nil {
		md.AddCounter("jwt_auth_failed_login_attempts", 1)
		return
	}

	dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
	var rvSecret RvGetSecretType
	err := json.Unmarshal([]byte(rv), &rvSecret)
	if err != nil || rvSecret.Status != "success" {
		md.AddCounter("jwt_auth_failed_login_attempts", 1)
		rvSecret.LogUUID = GenUUID()
		dbgo.Printf("%(red)%(LF) -- err:%s rvSecret=%s\n", err, dbgo.SVarI(rvSecret))
		log_enc.LogStoredProcError(c, stmt, "e.", SVar(rvSecret), fmt.Sprintf("%s", err))
		c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, rvSecret.StdErrorReturn)) // 400
		return
	}

	if rvSecret.Require2fa == "y" && pp.X2FaPin == "" {
		rvSecret.LogUUID = GenUUID()
		dbgo.Printf("%(red)%(LF) -- err:%s rvSecret=%s\n", err, dbgo.SVarI(rvSecret))
		log_enc.LogStoredProcError(c, stmt, "e.", SVar(rvSecret), fmt.Sprintf("%s", err))
		c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, rvSecret.StdErrorReturn)) // 400
		return
	}

	// chkSecret allows for multiple secrets in a JSON list, otherwize it just uses the value.
	// So GS2RV3HVX2LTC2PZ is a good secret aw well as
	//    ["GS2RV3HVX2LTC2PZ","G6WAUNNFR6PXPWTL"]
	chkSecret := func(secret string) bool {
		if secret[0:1] == "[" {
			var secret_list []string
			err := json.Unmarshal([]byte(secret), &secret_list)
			if err != nil {
				rvStatus := StdErrorReturn{
					Status:   "error",
					Msg:      "Invalid  format for JSON data - user 2fa secret",
					Location: dbgo.LF(),
					LogUUID:  GenUUID(),
				}
				log_enc.LogAttentionError(c, fmt.Errorf("Internal Data Format Error: %s data %s", err, secret), SVar(rvStatus))
				return false
			}
			for ii, a_secret := range secret_list {
				dbgo.Fprintf(perReqLog, "		Secret[%d] = %s\n", ii, a_secret)
				rv := htotp.CheckRfc6238TOTPKeyWithSkew(pp.Email /*username*/, pp.X2FaPin /*pin2fa*/, a_secret, 1, 2)
				if rv {
					return true
				}
			}
			return false
		} else {
			return htotp.CheckRfc6238TOTPKeyWithSkew(pp.Email /*username*/, pp.X2FaPin /*pin2fa*/, secret, 1, 2)
		}
	}

	if rvSecret.Require2fa == "y" {

		if pp.X2FaPin == "" {
			c.JSON(http.StatusNotAcceptable, StdErrorReturn{ // 406
				Status:   "error",
				Msg:      "A 2fa Pin is Required",
				Code:     "9001",
				Location: dbgo.LF(),
				LogUUID:  GenUUID(),
			})
			// ------------------------------------------------------------------------------------------
			// Early Return if 2fa token is missing.
			// ------------------------------------------------------------------------------------------
			return
		}

		// If the 2fa token fails to validate - then we are done.
		// dbgo.Fprintf(perReqLog, "\n\n%(LF) Secret = %s\n", rvSecret.Secret2fa)
		dbgo.Fprintf(perReqLog, "\n\n%(LF)%(magenta) Secret = %(yellow)%s\n", rvSecret.Secret2fa)
		// if !htotp.CheckRfc6238TOTPKeyWithSkew(pp.Email /*username*/, pp.X2FaPin /*pin2fa*/, rvSecret.Secret2fa, 1, 2) {
		if !chkSecret(rvSecret.Secret2fa) {
			md.AddCounter("jwt_auth_failed_login_attempts", 1)
			dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
			// xyzzy - log event - TODO
			c.JSON(http.StatusBadRequest, StdErrorReturn{ // 400
				Status:   "error",
				Msg:      "Invalid PIN - Please enter a new PIN",
				Code:     "9000",
				Location: dbgo.LF(),
				LogUUID:  GenUUID(),
			})
			// ------------------------------------------------------------------------------------------
			// Early Return if 2fa token is not valid.
			// ------------------------------------------------------------------------------------------
			return
		}
		// dbgo.Fprintf(perReqLog, "%(LF) -- 2fa has been validated -- \n\n")
		dbgo.Fprintf(perReqLog, "%(LF)%(magenta)  -- 2fa has been validated -- %(reset)\n\n")

	}

	// ----------------------------------------------------------------------------------------------
	// Call when 2fa token is known to be valid for this device with this user_id (UserId,UserID)
	// ----------------------------------------------------------------------------------------------
	// create or replace function q_auth_v1_etag_device_mark ( p_seen_id varchar, p_user_id varchar, p_hmac_password varchar, p_userdata_password varchar )
	if pp.AmIKnown != "" {
		dbgo.Fprintf(perReqLog, "\n%(magenta)Marking device as seen : at:%(LF)\n%(yellow)    am_i_known(AmIKnown)=->%s<- user_id=->%s<-\n\n", pp.AmIKnown, rvSecret.UserId)
		stmt := "q_auth_v1_etag_device_mark ( $1, $2, $3, $4 )"
		rv, e0 := CallDatabaseJSONFunctionNoErr(c, stmt, "..!!", pp.AmIKnown, rvSecret.UserId, aCfg.EncryptionPassword, aCfg.UserdataPassword)
		_ = rv
		if e0 != nil {
			dbgo.Fprintf(perReqLog, "   %(red)Error on call to ->%s<- err: %s\n", stmt, err)
		}
	} else {
		dbgo.Printf("\n%(magenta)No marker am_i_known(AmIKnown) id at:%(LF)\n    user_id=%s\n\n", rvSecret.UserId)
	}
	// ----------------------------------------------------------------------------------------------

	dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)

	// xyzzyRedisUsePubSub gCfg.RedisUsePubSub   string `json:"redis_use_pub_sub" default:"no"`

	// rv, stmt, err := ConfirmEmailAccount(c, pp.EmailVerifyToken)
	// create or replace function q_auth_v1_validate_2fa_token ( p_un varchar, p_2fa_secret varchar, p_hmac_password varchar )
	stmt = "q_auth_v1_validate_2fa_token ( $1, $2, $3, $4, $5 )"
	rv, e0 = CallDatabaseJSONFunction(c, stmt, "e!e..", pp.Email, pp.TmpToken /*p_tmp_token*/, rvSecret.Secret2fa, aCfg.EncryptionPassword, aCfg.UserdataPassword)

	if e0 != nil {
		md.AddCounter("jwt_auth_failed_login_attempts", 1)
		err = e0
		return
	}

	dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
	var rvStatus RvValidate2faTokenType
	err = json.Unmarshal([]byte(rv), &rvStatus)
	if rvStatus.Status != "success" { // if the d.b. call is not success then done - report error
		md.AddCounter("jwt_auth_failed_login_attempts", 1)
		dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
		rvStatus.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
		c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, rvStatus.StdErrorReturn)) // 400
		return
	}

	dbgo.Fprintf(perReqLog, "%(LF): rvStatus.AuthToken= ->%s<- for ->%s<-\n", rvStatus.AuthToken, pp.Email)
	if rvStatus.AuthToken != "" {
		dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
		theJwtToken, err := CreateJWTSignedCookie(c, rvStatus.AuthToken, pp.Email, g_lib.IfTrue(pp.NoCookie == "nc", NoCookie, CookieUsed))
		if err != nil {
			md.AddCounter("jwt_auth_failed_login_attempts", 1)
			return
		}
		// dbgo.Fprintf(perReqLog, "!! Creating COOKIE Token, Logged In !!  at:%(LF): AuthToken=%s jwtCookieToken=%s email=%s\n", rvStatus.AuthToken, theJwtToken, pp.Email)
		dbgo.Fprintf(perReqLog, "%(green)!! Creating COOKIE Token, Logged In !!  at:%(LF): AuthToken=%s jwtCookieToken=%s email=%s\n", rvStatus.AuthToken, theJwtToken, pp.Email)
		c.Set("__is_logged_in__", "y")
		c.Set("__user_id__", rvStatus.UserId)
		c.Set("__auth_token__", rvStatus.AuthToken)
		rv, mr := ConvPrivs2(perReqLog, rvStatus.Privileges)
		c.Set("__privs__", rv)
		c.Set("__privs_map__", mr)
		c.Set("__email_hmac_password__", aCfg.EncryptionPassword)
		c.Set("__user_password__", aCfg.UserdataPassword) // __userdata_password__
		c.Set("__client_id__", rvStatus.ClientId)

		md.AddCounter("jwt_auth_success_login", 1)

		if theJwtToken != "" {
			// "Progressive improvement beats delayed perfection" -- Mark Twain
			if aCfg.TokenHeaderVSCookie == "cookie" {
				rvStatus.Token = ""
				c.Set("__jwt_cookie_only__", "yes")
			} else { // header or both
				rvStatus.Token = theJwtToken
			}
			c.Set("__jwt_token__", theJwtToken)
		}

	}
	dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)

	var out Validate2faTokenSuccess
	copier.Copy(&out, &rvStatus)
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out)) // 200

}

// -------------------------------------------------------------------------------------------------------------------------
// jwtConfig.authInternalHandlers["POST:/api/v1/auth/delete-acct"] = authHandleDeleteAccount

type RvDeleteAccountType struct {
	StdErrorReturn
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
}

// authHandleDeleteAccount godoc
// @Summary Remove an account
// @Schemes
// @Description Use the email to remove an account.  TODO - should have the current password also passed and checked!
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   email     formData    string     true        "Email Address"
// @Param   pw        formData    string     true        "Password"
// @Produce json
// @Success 200 {object} jwt_auth.ReturnSuccess
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/delete-acct [post]
func authHandleDeleteAccount(c *gin.Context) {
	var pp ApiEmail
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}
	perReqLog := tf.GetLogFilePtr(c)
	_, _, AuthToken := GetAuthToken(c)

	if AuthToken != "" { // if user is logged in then logout - else - just ignore.

		DumpParamsToLog("After Auth - Top", c)

		// create or replace function q_auth_v1_delete_account ( p_un varchar, p_pw varchar, p_hmac_password varchar )
		stmt := "q_auth_v1_delete_account ( $1, $2, $3 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, "e!.", pp.Email, AuthToken, aCfg.EncryptionPassword)
		if e0 != nil {
			return
		}

		dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
		var rvStatus RvDeleteAccountType
		err := json.Unmarshal([]byte(rv), &rvStatus)
		if err != nil || rvStatus.Status != "success" {
			rvStatus.LogUUID = GenUUID()
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
			c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, rvStatus)) // 400
			return
		}

		// send email about delete account
		em.SendEmail("account_deleted",
			"username", pp.Email,
			"email", pp.Email,
			"email_url_encoded", url.QueryEscape(pp.Email),
			"first_name", rvStatus.FirstName,
			"last_name", rvStatus.LastName,
			"real_name", rvStatus.FirstName+" "+rvStatus.LastName,
			"application_name", gCfg.AuthApplicationName,
			"realm", gCfg.AuthRealm,
			"server", gCfg.BaseServerURL,
			"reset_password_uri", gCfg.AuthPasswordRecoveryURI,
		)

		out := ReturnSuccess{Status: "success"}
		c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out)) // 200
		return
	} else {
		time.Sleep(1500 * time.Millisecond)
	}
	out := StdErrorReturn{
		Status:   "error",
		Msg:      "401 not authorized",
		Location: dbgo.LF(),
	}
	c.JSON(http.StatusUnauthorized, LogJsonReturned(perReqLog, out))

}

// -------------------------------------------------------------------------------------------------------------------------
// router.POST("/api/v1/auth/register-un-pw", LoginRequiredClosure(authHandleRegisterUnPw))               //

// Input for api endpoint
type ApiAuthUn struct {
	Email string `json:"email" form:"email"`
}

type RvRegisterUnPwAccountType struct {
	StdErrorReturn
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	Email     string `json:"email,omitempty"`
}

// authHandleRegisterUnPw godoc
// @Summary Register a Un/Pw accoutn
// @Schemes
// @Description Create an account as a child of an existing account that requries only username and password to login.  No 2fa is used.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   email     formData    string     true        "Email Address"
// @Produce json
// @Success 200 {object} jwt_auth.ReturnSuccess
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/register-un-pw [post]
func authHandleRegisterUnPw(c *gin.Context) {
	var pp ApiAuthUn
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	pp.Email = cleanupEmail(pp.Email)

	perReqLog := tf.GetLogFilePtr(c)
	UserId, _, AuthToken := GetAuthToken(c)

	if AuthToken != "" { // if user is logged in then logout - else - just ignore.

		DumpParamsToLog("After Auth - Top", c)

		// function q_auth_v1_register_un_pw ( p_parent_user_id uuid, p_email varchar, p_hmac_password varchar,  p_userdata_password varchar )
		stmt := "q_auth_v1_register_un_pw ( $1, $2, $3, $4 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, "!e..", UserId, pp.Email, aCfg.EncryptionPassword, aCfg.UserdataPassword)
		if e0 != nil {
			return
		}

		dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
		var rvStatus RvRegisterUnPwAccountType
		err := json.Unmarshal([]byte(rv), &rvStatus)
		if err != nil || rvStatus.Status != "success" {
			rvStatus.LogUUID = GenUUID()
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
			c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, rvStatus)) // 400
			return
		}

		// send email about registraiton of un/pw sub-account
		em.SendEmail("un_pw_account_created",
			"username", rvStatus.Email,
			"email", rvStatus.Email,
			"email_url_encoded", url.QueryEscape(rvStatus.Email),
			"first_name", rvStatus.FirstName,
			"last_name", rvStatus.LastName,
			"real_name", rvStatus.FirstName+" "+rvStatus.LastName,
			"application_name", gCfg.AuthApplicationName,
			"realm", gCfg.AuthRealm,
			"server", gCfg.BaseServerURL,
			"reset_password_uri", gCfg.AuthPasswordRecoveryURI,
		)

		out := ReturnSuccess{Status: "success"}
		c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out)) // 200
		return
	}
	out := StdErrorReturn{
		Status:   "error",
		Msg:      "401 not authorized",
		Location: dbgo.LF(),
	}
	c.JSON(http.StatusUnauthorized, LogJsonReturned(perReqLog, out))
}

// -------------------------------------------------------------------------------------------------------------------------
// router.POST("/api/v1/auth/register-token", LoginRequiredClosure(authHandleRegisterToken))              //

type RvRegisterTokenAccountType struct {
	StdErrorReturn
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	Email     string `json:"email,omitempty"`
}

// authHandleRegisterToken godoc
// @Summary Create an account that uses a token to login.
// @Schemes
// @Description Use a single authentiction token to login.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Produce json
// @Success 200 {object} jwt_auth.ReturnSuccess
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/register-token [post]
func authHandleRegisterToken(c *gin.Context) {

	UserId, _, AuthToken := GetAuthToken(c)
	perReqLog := tf.GetLogFilePtr(c)

	if AuthToken != "" { // if user is logged in then logout - else - just ignore.

		DumpParamsToLog("After Auth - Top", c)

		// function q_auth_v1_register_token ( p_parent_user_id uuid,  p_hmac_password varchar,  p_userdata_password varchar )
		stmt := "q_auth_v1_regiser_token ( $1, $2, $3 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, "!.", UserId, aCfg.EncryptionPassword)
		if e0 != nil {
			return
		}

		dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
		var rvStatus RvRegisterTokenAccountType
		err := json.Unmarshal([]byte(rv), &rvStatus)
		if err != nil || rvStatus.Status != "success" {
			rvStatus.LogUUID = GenUUID()
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
			c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, rvStatus)) // 400
			return
		}

		// send email about registring a token based account
		em.SendEmail("token_account_created",
			"username", rvStatus.Email,
			"email", rvStatus.Email,
			"email_url_encoded", url.QueryEscape(rvStatus.Email),
			"first_name", rvStatus.FirstName,
			"last_name", rvStatus.LastName,
			"real_name", rvStatus.FirstName+" "+rvStatus.LastName,
			"application_name", gCfg.AuthApplicationName,
			"realm", gCfg.AuthRealm,
			"server", gCfg.BaseServerURL,
			"reset_password_uri", gCfg.AuthPasswordRecoveryURI,
		)

		out := ReturnSuccess{Status: "success"}
		c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out)) // 200
		return
	}
	out := StdErrorReturn{
		Status:   "error",
		Msg:      "401 not authorized",
		Location: dbgo.LF(),
	}
	c.JSON(http.StatusUnauthorized, LogJsonReturned(perReqLog, out))
}

// -------------------------------------------------------------------------------------------------------------------------
// router.POST("/api/v1/auth/change-email-address", LoginRequiredClosure(authHandleChangeEmailAddress))   //

// Input for api endpoint
type ApiAuthChangeEmail struct {
	NewEmail string `json:"new_email"  form:"new_email"   binding:"required"`
	OldEmail string `json:"old_email"  form:"old_email"   binding:"required"`
	Pw       string `json:"password"   form:"password"    binding:"required"`
	X2FaPin  string `json:"x2fa_pin"   form:"x2fa_pin"  `
}

type RvChangeEmailAddressType struct {
	StdErrorReturn
	Email     string `json:"email,omitempty"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
}

type ChangeEmailSuccess struct {
	Status    string `json:"status"`
	Email     string `json:"email,omitempty"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
}

// authHandleChangeEmailAddress godoc
// @Summary Confirm the email from registration.
// @Schemes
// @Description Allow the user to chagne the email address for an account.   If the email is already used this will result in an error.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   new_email    formData    string     true        "New Email Address"
// @Param   old_email    formData    string     true        "Old Email Address"
// @Param   pw           formData    string     true        "Password"
// @Produce json
// @Success 200 {object} jwt_auth.ApiAuthLogin
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/change-email-address [post]
func authHandleChangeEmailAddress(c *gin.Context) {
	perReqLog := tf.GetLogFilePtr(c)
	var pp ApiAuthChangeEmail
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	pp.NewEmail = cleanupEmail(pp.NewEmail)
	pp.OldEmail = cleanupEmail(pp.OldEmail)
	pp.Pw = cleanupPw(pp.Pw)

	UserId, _, AuthToken := GetAuthToken(c)

	if AuthToken != "" { // if user is logged in then logout - else - just ignore.

		DumpParamsToLog("After Auth - password validated", c)

		// Check x2faPin for validity for this account.
		stmt := "q_auth_v1_2fa_get_secret ( $1, $2 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, "e.", pp.OldEmail, aCfg.EncryptionPassword)
		if e0 != nil {
			return
		}

		dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
		var rvSecret RvGetSecretType
		err := json.Unmarshal([]byte(rv), &rvSecret)
		if err != nil || rvSecret.Status != "success" {
			rvSecret.LogUUID = GenUUID()
			dbgo.Printf("%(red)%(LF) -- err:%s rvSecret=%s\n", err, dbgo.SVarI(rvSecret))
			log_enc.LogStoredProcError(c, stmt, "e.", SVar(rvSecret), fmt.Sprintf("%s", err))
			c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, rvSecret.StdErrorReturn)) // 400
			return
		}

		if rvSecret.Require2fa == "y" && pp.X2FaPin == "" {
			rvSecret.LogUUID = GenUUID()
			dbgo.Printf("%(red)%(LF) -- err:%s rvSecret=%s\n", err, dbgo.SVarI(rvSecret))
			log_enc.LogStoredProcError(c, stmt, "e.", SVar(rvSecret), fmt.Sprintf("%s", err))
			c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, rvSecret.StdErrorReturn)) // 400
			return
		}

		// chkSecret allows for multiple secrets in a JSON list, otherwize it just uses the value.
		// So GS2RV3HVX2LTC2PZ is a good secret aw well as
		//    ["GS2RV3HVX2LTC2PZ","G6WAUNNFR6PXPWTL"]
		chkSecret := func(secret string) bool {
			if secret[0:1] == "[" {
				var secret_list []string
				err := json.Unmarshal([]byte(secret), &secret_list)
				if err != nil {
					rvStatus := StdErrorReturn{
						Status:   "error",
						Msg:      "Invalid  format for JSON data - user 2fa secret",
						Location: dbgo.LF(),
						LogUUID:  GenUUID(),
					}
					log_enc.LogAttentionError(c, fmt.Errorf("Internal Data Format Error: %s data %s", err, secret), SVar(rvStatus))
					return false
				}
				for ii, a_secret := range secret_list {
					dbgo.Fprintf(perReqLog, "		Secret[%d] = %s\n", ii, a_secret)
					rv := htotp.CheckRfc6238TOTPKeyWithSkew(pp.OldEmail /*username*/, pp.X2FaPin /*pin2fa*/, a_secret, 1, 2)
					if rv {
						return true
					}
				}
				return false
			} else {
				return htotp.CheckRfc6238TOTPKeyWithSkew(pp.OldEmail /*username*/, pp.X2FaPin /*pin2fa*/, secret, 1, 2)
			}
		}

		if rvSecret.Require2fa == "y" {

			if pp.X2FaPin == "" {
				c.JSON(http.StatusNotAcceptable, StdErrorReturn{ // 406
					Status:   "error",
					Msg:      "A 2fa Pin is Required",
					Code:     "9001",
					Location: dbgo.LF(),
					LogUUID:  GenUUID(),
				})
				// ------------------------------------------------------------------------------------------
				// Early Return if 2fa token is missing.
				// ------------------------------------------------------------------------------------------
				return
			}

			// If the 2fa token fails to validate - then we are done.
			// dbgo.Fprintf(perReqLog, "\n\n%(LF) Secret = %s\n", rvSecret.Secret2fa)
			dbgo.Fprintf(perReqLog, "\n\n%(LF)%(magenta) Secret = %(yellow)%s\n", rvSecret.Secret2fa)
			// if !htotp.CheckRfc6238TOTPKeyWithSkew(pp.Email /*username*/, pp.X2FaPin /*pin2fa*/, rvSecret.Secret2fa, 1, 2) {
			if !chkSecret(rvSecret.Secret2fa) {
				dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
				// xyzzy - log event - TODO
				c.JSON(http.StatusBadRequest, StdErrorReturn{ // 400
					Status:   "error",
					Msg:      "Invalid PIN - Please enter a new PIN",
					Code:     "9001",
					Location: dbgo.LF(),
					LogUUID:  GenUUID(),
				})
				// ------------------------------------------------------------------------------------------
				// Early Return if 2fa token is not valid.
				// ------------------------------------------------------------------------------------------
				return
			}
			// dbgo.Fprintf(perReqLog, "%(LF) -- 2fa has been validated -- \n\n")
			dbgo.Fprintf(perReqLog, "%(LF)%(magenta)  -- 2fa has been validated -- %(reset)\n\n")

		}

		DumpParamsToLog("After Auth - 2fa validated, password validated", c)

		// create or replace function q_auth_v1_change_email_address ( p_old_email varchar, p_new_email varchar, p_pw varchar, p_hmac_password varchar, p_userdata_password varchar )
		stmt = "q_auth_v1_change_email_address ( $1, $2, $3, $4, $5, $6 )"
		rv, e0 = CallDatabaseJSONFunction(c, stmt, "eee!..", pp.OldEmail, pp.NewEmail, pp.Pw, UserId, aCfg.EncryptionPassword, aCfg.UserdataPassword)
		if e0 != nil {
			return
		}

		dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
		var rvStatus RvChangeEmailAddressType
		err = json.Unmarshal([]byte(rv), &rvStatus)
		if err != nil || rvStatus.Status != "success" {
			rvStatus.LogUUID = GenUUID()
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
			c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, rvStatus)) // 400
			return
		}

		// xyzzyLogoutForced - send message via websockt to log out all of this user.

		// send email that Email Address Changed (to both old and new address)
		em.SendEmail("email_address_changed_old_address",
			"username", pp.OldEmail,
			"email", pp.OldEmail,
			"email_url_encoded", url.QueryEscape(pp.OldEmail),
			"first_name", rvStatus.FirstName,
			"last_name", rvStatus.LastName,
			"real_name", rvStatus.FirstName+" "+rvStatus.LastName,
			"application_name", gCfg.AuthApplicationName,
			"realm", gCfg.AuthRealm,
			"server", gCfg.BaseServerURL,
			"reset_password_uri", gCfg.AuthPasswordRecoveryURI,
		)
		em.SendEmail("email_address_changed_new_address",
			"username", pp.NewEmail,
			"email", pp.NewEmail,
			"email_url_encoded", url.QueryEscape(pp.NewEmail),
			"first_name", rvStatus.FirstName,
			"last_name", rvStatus.LastName,
			"real_name", rvStatus.FirstName+" "+rvStatus.LastName,
			"application_name", gCfg.AuthApplicationName,
			"realm", gCfg.AuthRealm,
			"server", gCfg.BaseServerURL,
			"reset_password_uri", gCfg.AuthPasswordRecoveryURI,
		)

		out := ChangeEmailSuccess{Status: "success", Email: rvStatus.Email}
		c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out)) // 200
		return
	} else {
		time.Sleep(1500 * time.Millisecond)
	}

	out := StdErrorReturn{
		Status:   "error",
		Msg:      "401 not authorized",
		Location: dbgo.LF(),
	}
	c.JSON(http.StatusUnauthorized, LogJsonReturned(perReqLog, out))
}

// -------------------------------------------------------------------------------------------------------------------------
// router.POST("/api/v1/auth/change-account-info", LoginRequiredClosure(authHandleChangeAccountInfo))     //
type ApiAuthChangeAccountInfo struct {
	FirstName string `json:"first_name" form:"first_name"   binding:"required"`
	LastName  string `json:"last_name"  form:"last_name"    binding:"required"`
	X2FaPin   string `json:"x2fa_pin"   form:"x2fa_pin"  `
}

type RvChangeNameType struct {
	StdErrorReturn
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
}

type ChangeNameSuccess struct {
	Status    string `json:"status"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
}

// authHandleChangeAccountInfo godoc
// @Summary Chagne information tied to account.
// @Schemes
// @Description Chagne information tied to account.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   email     formData    string     true        "Email Address"
// @Produce json
// @Success 200 {object} jwt_auth.ApiAuthLogin
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/change-account-info [post]
func authHandleChangeAccountInfo(c *gin.Context) {
	perReqLog := tf.GetLogFilePtr(c)
	var pp ApiAuthChangeAccountInfo
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	UserId, _, AuthToken := GetAuthToken(c)

	if AuthToken == "" { // if user is logged in then logout - else - just ignore.
		time.Sleep(1500 * time.Millisecond)
		out := StdErrorReturn{
			Status:   "error",
			Msg:      "401 not authorized",
			Location: dbgo.LF(),
		}
		c.JSON(http.StatusUnauthorized, LogJsonReturned(perReqLog, out))
		return
	}

	DumpParamsToLog("After Auth - Top of Update Accoutn Info (first name, last-name)", c)

	var rvStatus RvChangeNameType
	// UserId, first_name, last_name, PW, PW
	//                                          1               2                     3                    4                        5
	// FUNCTION q_auth_v1_change_account_info ( p_user_id uuid, p_first_name varchar, p_last_name varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
	stmt := "q_auth_v1_change_account_info ( $1, $2, $3, $4, $5 )"
	//                                                        1       2             3            4                        5
	e0 := CallDatabaseFunction(c, &rvStatus, stmt, "e!.", UserId, pp.FirstName, pp.LastName, aCfg.EncryptionPassword, aCfg.UserdataPassword)
	if e0 != nil {
		return
	}

	out := ChangeNameSuccess{Status: "success", FirstName: rvStatus.FirstName, LastName: rvStatus.LastName}
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out)) // 200
	return

}

// -------------------------------------------------------------------------------------------------------------------------
// router.POST("/api/v1/auth/change-password-admin", LoginRequiredClosure(authHandleChangePasswordAdmin)) //

type RvChangePasswordAdminType struct {
	StdErrorReturn
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
}

type ApiAdminChangePassword struct {
	Email       string `json:"email"  form:"email"  binding:"required,email"`
	NewPassword string `json:"new_password"  form:"new_password"  binding:"new_password"`
}

// authHandleChangePasswordAdmin godoc
// @Summary Allows an admin to change a users password.
// @Schemes
// @Description Administrative reset on a users password.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   email     formData    string     true        "Email Address"
// @Produce json
// @Success 200 {object} jwt_auth.ReturnSuccess
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/change-password-admin [post]
func authHandleChangePasswordAdmin(c *gin.Context) {
	perReqLog := tf.GetLogFilePtr(c)
	var pp ApiAdminChangePassword
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	pp.Email = cleanupEmail(pp.Email)

	UserID, _, AuthToken := GetAuthToken(c)

	if AuthToken != "" { // if user is logged in then logout - else - just ignore.

		DumpParamsToLog("After Auth - Top", c)

		// function q_auth_v1_change_password_admin ( p_admin_user_id uuid, p_email varchar, p_new_pw varchar, p_hmac_password varchar, p_userdata_password varchar )
		stmt := "q_auth_v1_change_password_admin ( $1, $2, $3, $4, $5 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, "e!.", UserID, pp.Email, pp.NewPassword, aCfg.EncryptionPassword, aCfg.UserdataPassword)
		if e0 != nil {
			return
		}

		// “If opportunity doesn’t knock, build a door.” – Milton Berle

		dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
		var rvStatus RvChangePasswordAdminType
		err := json.Unmarshal([]byte(rv), &rvStatus)
		if err != nil || rvStatus.Status != "success" {
			rvStatus.LogUUID = GenUUID()
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
			c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, rvStatus)) // 400
			return
		}

		// xyzzyLogoutForced - send message via websockt to log out all of this user.

		// send email about admin changging password
		em.SendEmail("admin_password_changed",
			"username", pp.Email,
			"email", pp.Email,
			"email_url_encoded", url.QueryEscape(pp.Email),
			"first_name", rvStatus.FirstName,
			"last_name", rvStatus.LastName,
			"real_name", rvStatus.FirstName+" "+rvStatus.LastName,
			"application_name", gCfg.AuthApplicationName,
			"realm", gCfg.AuthRealm,
			"server", gCfg.BaseServerURL,
			"reset_password_uri", gCfg.AuthPasswordRecoveryURI,
		)

		out := ReturnSuccess{Status: "success"}
		c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out)) // 200
		return
	}
	out := StdErrorReturn{
		Status:   "error",
		Msg:      "401 not authorized",
		Location: dbgo.LF(),
	}
	c.JSON(http.StatusUnauthorized, LogJsonReturned(perReqLog, out))

}

// -------------------------------------------------------------------------------------------------------------------------
// TODO - should allso allow use of x2fa_pin as an alternative to "password" - xyzzy988098
// router.POST("/api/v1/auth/regen-otp", LoginRequiredClosure(authHandleRegenOTP))                        // regenerate list of One Time Passwords (OTP)

// DB Reutrn Data
type RvRegenOTPType struct {
	StdErrorReturn
	Otp       []string `json:"otp,omitempty"`
	FirstName string   `json:"first_name,omitempty"`
	LastName  string   `json:"last_name,omitempty"`
}

// Output returned
type RegenOTPSuccess struct {
	Status string   `json:"status"`
	Otp    []string `json:"otp,omitempty"`
	Msg    string   `json:"msg"`
}

// authHandleRegenOTP godoc
// @Summary Generate a new list of OTP.
// @Schemes
// @Description Generate a new list of 20 one time passwords (OTP).  The old list is discarded.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   email     formData    string     true        "Email Address"
// @Param   pw        formData    string     true        "Password"
// @Produce json
// @Success 200 {object} jwt_auth.RegenOTPSuccess
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/regen-otp [post]
func authHandleRegenOTP(c *gin.Context) {
	perReqLog := tf.GetLogFilePtr(c)
	var pp ApiAuthLogin
	/*
	   type ApiAuthLogin struct {
	   	Email    string `json:"email"      form:"email"       binding:"required,email"`
	   	Pw       string `json:"password"   form:"password"    binding:"required"`
	   	AmIKnown string `json:"am_i_known" form:"am_i_known"`
	   	XsrfId   string `json:"xsrf_id"    form:"xsrf_id"     binding:"required"`
	   }
	*/
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}
	_, _, AuthToken := GetAuthToken(c)

	if AuthToken != "" { // if user is logged in then generate new OTP else - just ignore.

		DumpParamsToLog("After Auth - Top", c)

		// function q_auth_v1_regen_otp ( p_email varchar, p_pw varchar, p_hmac_password varchar , p_userdata_password varchar )
		stmt := "q_auth_v1_regen_otp ( $1, $2, $3, $4 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, "e!..", pp.Email, pp.Pw, aCfg.EncryptionPassword, aCfg.UserdataPassword)
		if e0 != nil {
			return
		}

		dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
		var rvStatus RvRegenOTPType
		err := json.Unmarshal([]byte(rv), &rvStatus)
		if err != nil || rvStatus.Status != "success" {
			rvStatus.LogUUID = GenUUID()
			dbgo.Fprintf(perReqLog, "%(LF) email >%s< AuthToken >%s<\n", pp.Email, AuthToken)
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
			c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, rvStatus.StdErrorReturn)) // 400
			return
		}

		// "If you have to swallow a frog don't stare at it too long." -- Mark Twain

		// send email about this -- regeneration of OTP passwords
		em.SendEmail("regenerate_one_time_passwords",
			"username", pp.Email,
			"email", pp.Email,
			"email_url_encoded", url.QueryEscape(pp.Email),
			"first_name", rvStatus.FirstName,
			"last_name", rvStatus.LastName,
			"real_name", rvStatus.FirstName+" "+rvStatus.LastName,
			"application_name", gCfg.AuthApplicationName,
			"realm", gCfg.AuthRealm,
			"server", gCfg.BaseServerURL,
			"reset_password_uri", gCfg.AuthPasswordRecoveryURI,
		)

		out := RegenOTPSuccess{
			Status: "success",
			Otp:    rvStatus.Otp,
		}
		c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))
		return
	} else {
		time.Sleep(1500 * time.Millisecond)
	}

	out := StdErrorReturn{
		Status:   "error",
		Msg:      "401 not authorized",
		Location: dbgo.LF(),
	}
	c.JSON(http.StatusUnauthorized, LogJsonReturned(perReqLog, out))

}

// -------------------------------------------------------------------------------------------------------------------------
// {Method: "POST", Path: "/api/v1/auth/refresh-token", Fx: authHandleRefreshToken, UseLogin: LoginRequired},            // (TODO - wrong function now)
type RvRefreshTokenType struct {
	StdErrorReturn
	AuthToken   string            `json:"auth_token,omitempty"`
	Token       string            `json:"token,omitempty"` // the JWT Token???
	UserId      string            `json:"user_id,omitempty"`
	AccountType string            `json:"account_type,omitempty"`
	Email       string            `json:"email_address"`
	FirstName   string            `json:"first_name,omitempty"`
	LastName    string            `json:"last_name,omitempty"`
	AcctState   string            `json:"acct_state,omitempty"`
	UserConfig  map[string]string `json:"user_config,omitempty"`
}

// Output returned
type RefreshTokenSuccess struct {
	Status      string            `json:"status"`
	Token       string            `json:"token,omitempty"` // the JWT Token???
	AccountType string            `json:"account_type,omitempty"`
	FirstName   string            `json:"first_name,omitempty"`
	LastName    string            `json:"last_name,omitempty"`
	AcctState   string            `json:"acct_state,omitempty"`
	UserConfig  map[string]string `json:"user_config,omitempty"`
}

// Input for refresh token
type ApiAuthRefreshToken struct {
	AmIKnown string `json:"am_i_known" form:"am_i_known"`
	XsrfId   string `json:"xsrf_id"    form:"xsrf_id"     binding:"required"`

	// You can set any value for the 'no_cookie' data field.   Normally if you want to skip cookies send 'nc' for the value.
	NoCookie string `json:"no_cookie"  form:"no_cookie"` // default is to NOT send cookie if cookies and headers (both ==> , "token_header_vs_cookie": "both") are defined,
}

// authHandleRefreshToken godoc
// @Summary Refresh auth token.
// @Schemes
// @Description Given a valid logged in use and a current auth_token, refresh it.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Produce json
// @Success 200 {object} jwt_auth.RefreshTokenSuccess
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/refresh-token [post]
func authHandleRefreshToken(c *gin.Context) {
	perReqLog := tf.GetLogFilePtr(c)
	var pp ApiAuthRefreshToken
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	// validate inputs AmIKnown, if "" - then 401 - pass to q_auth_v1_refresh_token

	// validate inputs XsrfId, if "" - then 401
	if err := ValidateXsrfId(c, pp.XsrfId); err != nil {
		return
	}

	UserId, _, AuthToken := GetAuthToken(c)

	if AuthToken != "" { // if user is logged in then generate new OTP else - just ignore.

		DumpParamsToLog("After Auth - Top", c)

		// function q_auth_v1_regen_otp ( p_email varchar, p_pw varchar, p_hmac_password varchar , p_userdata_password varchar )
		stmt := "q_auth_v1_refresh_token ( $1, $2, $3, $4, $5 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, "e!..", UserId, AuthToken, pp.AmIKnown, aCfg.EncryptionPassword, aCfg.UserdataPassword)
		if e0 != nil {
			return
		}

		dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
		var rvStatus RvRefreshTokenType
		err := json.Unmarshal([]byte(rv), &rvStatus)
		if rvStatus.Status == "401" {
			goto no_auth
		}
		if err != nil || rvStatus.Status != "success" {
			rvStatus.LogUUID = GenUUID()
			// dbgo.Fprintf(perReqLog, "%(LF) email >%s< AuthToken >%s<\n", pp.Email, AuthToken)
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
			c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, rvStatus.StdErrorReturn)) // 400
			return
		}

		// “Do what you can, with what you have, where you are.” – Theodore Roosevelt

		// replace current cookie/header with new signed token
		if rvStatus.AuthToken != "" {
			theJwtToken, err := CreateJWTSignedCookie(c, rvStatus.AuthToken, rvStatus.Email, g_lib.IfTrue(pp.NoCookie == "nc", NoCookie, CookieUsed))
			if err != nil {
				return
			}
			// dbgo.Fprintf(perReqLog, "!! Creating COOKIE Token, Logged In !!  at:%(LF): AuthToken=%s jwtCookieToken=%s email=%s\n", rvStatus.AuthToken, theJwtToken, rvStatus.Email)
			dbgo.Fprintf(perReqLog, "%(green)!! Creating COOKIE Token, Logged In !!  at:%(LF): AuthToken=%s jwtCookieToken=%s email=%s\n", rvStatus.AuthToken, theJwtToken, rvStatus.Email)

			c.Set("__auth_token__", rvStatus.AuthToken)

			md.AddCounter("jwt_auth_success_login", 1)

			if theJwtToken != "" {
				// "Progressive improvement beats delayed perfection" -- Mark Twain
				if aCfg.TokenHeaderVSCookie == "cookie" {
					rvStatus.Token = ""
					c.Set("__jwt_token__", "")
					c.Set("__jwt_cookie_only__", "yes")
				} else { // header or both
					rvStatus.Token = theJwtToken
					c.Set("__jwt_token__", theJwtToken)
				}

			}
		}

		var out RefreshTokenSuccess
		copier.Copy(&out, &rvStatus)
		c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))
		return
	}

no_auth:

	// Error Return -----------------------------------------------------------------------
	// Sleep to mitigate DDOS attacks using this call to find out if a token is valid
	time.Sleep(1500 * time.Millisecond)

	out := StdErrorReturn{
		Status:   "error",
		Msg:      "401 not authorized",
		Location: dbgo.LF(),
	}
	c.JSON(http.StatusUnauthorized, LogJsonReturned(perReqLog, out))
	return

}

// -------------------------------------------------------------------------------------------------------------------------
// router.GET("/api/v1/auth/no-login-status", authHandleNoLoginStatus)                                  //

// authHandleNoLoginStatus godoc
// @Summary Return status - Login Not Required
// @Schemes
// @Description Return a status message
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Produce json
// @Success 200 {object} jwt_auth.ReturnStatusSuccess
// @Router /api/v1/auth/no-login-status [get]
func authHandleNoLoginStatus(c *gin.Context) {
	perReqLog := tf.GetLogFilePtr(c)
	out := ReturnStatusSuccess{
		Status: "success",
		Msg:    fmt.Sprintf("No Login Requried to Reach .../no-login-status %s\n", dbgo.LF()),
	}
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))
}

// -------------------------------------------------------------------------------------------------------------------------
// {Method: "POST", Path: "/api/v1/auth/resend-registration-email", Fx: authHandleResendRegistrationEmail, UseLogin: PublicApiCall},             // Must have password to send.

// DB Reutrn Data
type RvResendEmailRegisterType struct {
	StdErrorReturn
	UserId           *int   `json:"user_id,omitempty"`
	EmailVerifyToken string `json:"email_verify_token,omitempty"`
	Require2fa       string `json:"require_2fa,omitempty"`
	Secret2fa        string `json:"secret_2,omitempty"`
	URLFor2faQR      string `json:"url_for_2fa_qr"`
	TotpSecret       string `json:"totp_secret"`
	TmpToken         string `json:"tmp_token,omitempty"` // May be "" - used in 2fa part 1 / 2
	FirstName        string `json:"first_name"`
	LastName         string `json:"last_name"`
	N6               string `json:"n6"`
}

// Input for api endpoint
type ApiAuthResendEmailRegister struct {
	Email    string `json:"email"      form:"email"       binding:"required,email"` // yes
	TmpToken string `json:"tmp_token"  form:"tmp_token"`
}

// Output returned
type ResendEmailRegisterSuccess struct {
	Status      string `json:"status"`
	URLFor2faQR string `json:"url_for_2fa_qr,omitempty"`
	TotpSecret  string `json:"totp_secret,omitempty"`
	TmpToken    string `json:"tmp_token,omitempty"` // May be "" - used in 2fa part 1 / 2
	Require2fa  string `json:"require_2fa,omitempty"`
}

// authHandleNoLoginStatus godoc
// @Summary Resend registration email.
// @Schemes
// @Description A call to this will use the email and the tmp_token to resend the registration email.
// @Tags auth
// @Param   email     	  formData    string     true        "Email Address"
// @Param   tmp_token     formData    string     false       "Tmp Token From Registration (optional)"
// @Accept json,x-www-form-urlencoded
// @Produce json
// @Success 200 {object} jwt_auth.ReturnStatusSuccess
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/auth/resend-registration-email [post]
func authHandleResendRegistrationEmail(c *gin.Context) {
	var err error
	var pp ApiAuthResendEmailRegister
	var RegisterResp RvResendEmailRegisterType
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	pp.Email = cleanupEmail(pp.Email)

	perReqLog := tf.GetLogFilePtr(c)

	var secret string
	secret = ""

	if IsXDBOn("authHandleRegister:error01") {
		RegisterResp.LogUUID = GenUUID()
		RegisterResp.Status = "error"
		RegisterResp.Msg = "Simulated Error"
		RegisterResp.Code = "0000"
		RegisterResp.Location = dbgo.LF()
		c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, RegisterResp.StdErrorReturn))
		return
	}

	//                                   1                2                   3                         4                            5
	// q_auth_v1_resend_email_register ( p_email varchar, p_tmp_token varchar, p_hmac_password varchar, p_userdata_password varchar, p_n6_flag varchar ) RETURNS text
	stmt := "q_auth_v1_resend_email_register ( $1, $2, $3, $4, $5 )"
	//                                                      1         2            3                        4                       5
	rv, err := CallDatabaseJSONFunction(c, stmt, "ee.ee..", pp.Email, pp.TmpToken, aCfg.EncryptionPassword, aCfg.UserdataPassword, gCfg.AuthEmailToken)
	if err != nil {
		return
	}
	dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
	err = json.Unmarshal([]byte(rv), &RegisterResp)
	if RegisterResp.Status != "success" {
		RegisterResp.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "ee", SVar(RegisterResp), pp.Email, pp.TmpToken /*aCfg.EncryptionPassword,*/ /*, aCfg.UserdataPassword*/)
		c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, RegisterResp.StdErrorReturn))
		return
	}

	if gCfg.AuthEmailToken == "n6" {
		RegisterResp.EmailVerifyToken = RegisterResp.N6
	}

	// ---------------------------------------------------------------------------------------------------------------------
	// send email with validation - using: RegisterResp.EmailVerifyToken
	// ---------------------------------------------------------------------------------------------------------------------
	dbgo.Fprintf(perReqLog, "%(magenta)================================================================================================%(reset)\n")
	dbgo.Fprintf(perReqLog, "%(yellow)%(LF) - sending 2nd email - %s%(reset)\n", RegisterResp.EmailVerifyToken)
	dbgo.Fprintf(perReqLog, "%(magenta)================================================================================================%(reset)\n")
	em.SendEmail("welcome_registration", // Email Template
		"username", pp.Email,
		"email", pp.Email,
		"email_url_encoded", url.QueryEscape(pp.Email),
		"first_name", RegisterResp.FirstName,
		"last_name", RegisterResp.LastName,
		"real_name", RegisterResp.FirstName+" "+RegisterResp.LastName,
		"token", RegisterResp.EmailVerifyToken,
		"user_id", RegisterResp.UserId,
		"server", gCfg.BaseServerURL,
		"application_name", gCfg.AuthApplicationName,
		"realm", gCfg.AuthRealm,
	)

	dbgo.Printf("%(yellow)Databse Data ->%s<- %(LF)\n", dbgo.SVarI(RegisterResp))

	// ---------------------------------------------------------------------------------------------------------------------
	// setup the QR code and link for 2fa tool, if using 2fa
	// ---------------------------------------------------------------------------------------------------------------------
	if RegisterResp.Require2fa == "n" {
		RegisterResp.TotpSecret = ""
		RegisterResp.URLFor2faQR = ""
	} else {
		RegisterResp.TotpSecret = secret     // 	if htotp.CheckRfc6238TOTPKeyWithSkew(username, pin2fa, RegisterResp.Secret2fa, 0, 1) {
		totp := htotp.NewDefaultTOTP(secret) // totp := htotp.NewDefaultTOTP(RegisterResp.Secret2fa)
		QRUrl := totp.ProvisioningUri(pp.Email /*username*/, gCfg.AuthRealm)
		RegisterResp.URLFor2faQR = MintQRPng(c, QRUrl)
	}

	var out ResendEmailRegisterSuccess
	copier.Copy(&out, &RegisterResp)
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))
}

// -------------------------------------------------------------------------------------------------------------------------
// router.POST("/api/v1/auth/login-status", LoginRequiredClosure(authHandleLoginStatus))                  //	Test of Login Required Stuff

// Output returned
type ReturnStatusSuccess struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
}

// authHandleEmailConfirm godoc
// @Summary Return stattus but only if logged in.
// @Schemes
// @Description Login status requires login to succede.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   email     formData    string     true        "Email Address"
// @Param   pw        formData    string     true        "Password"
// @Param   again     formData    string     true        "Password Again"
// @Produce json
// @Success 200 {object} jwt_auth.ReturnStatusSuccess
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/login-status [post]
func authHandleLoginStatus(c *gin.Context) {
	perReqLog := tf.GetLogFilePtr(c)
	out := ReturnStatusSuccess{
		Status: "success",
		Msg:    fmt.Sprintf("Login Requried to Reach .../login-status %s\n", dbgo.LF()),
	}

	if gCfg.ReleaseMode != "dev" { // slow down any password searchin using this interface (in production)
		time.Sleep(5)
	}

	DumpParamsToLog("At - Top", c)

	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))
}

// -------------------------------------------------------------------------------------------------------------------------
// DB Reutrn Data
type RvGetUserConfigType struct {
	StdErrorReturn
	UserConfig map[string]string `json:"user_config,omitempty" db:"user_config"`
}

// Output returned
type GetUserConfigSuccess struct {
	Status     string            `json:"status"`
	UserConfig map[string]string `json:"user_config,omitempty"`
}

// xyzzy201312 - done-TODO - get user_config /api/v1/get-user-config -> array
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
func authHandleGetUserConfig(c *gin.Context) {
	perReqLog := tf.GetLogFilePtr(c)

	var DBGetUserDataResp RvGetUserConfigType

	UserId, err := GetUserId(c)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": "unrachable-code",
		})
		return
	}

	DumpParamsToLog("After Auth - Top", c)

	// create or replace function q_auth_v1_get_user_config ( p_user_id uuid, varchar, p_hmac_password varchar, p_userdata_password varchar )
	stmt := "q_auth_v1_get_user_config ( $1, $2, $3 )"
	//                                                      1         2            3                        4             5            6                      7
	rv, err := CallDatabaseJSONFunction(c, stmt, "ee.ee..", UserId, aCfg.EncryptionPassword, aCfg.UserdataPassword)
	if err != nil {
		return
	}
	dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
	err = json.Unmarshal([]byte(rv), &DBGetUserDataResp)
	if DBGetUserDataResp.Status != "success" {
		DBGetUserDataResp.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "e", SVar(DBGetUserDataResp), UserId /*aCfg.EncryptionPassword,*/ /*, aCfg.UserdataPassword*/)
		c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, DBGetUserDataResp.StdErrorReturn))
		return
	}

	var out GetUserConfigSuccess
	copier.Copy(&out, &DBGetUserDataResp)
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))
}

// -------------------------------------------------------------------------------------------------------------------------
type ApiSetUserConfig struct {
	Name  string `json:"name,omitempty"  form:"name"`
	Value string `json:"value,omitempty" form:"value"`
}

// xyzzy201312 - TODO - set/add/upd user_config /api/v1/set-user-config -> [ { id / name / value } , ..., { "name":"value" } ]
// {Method: "POST", Path: "/api/v1/auth/set-user-config", Fx: authHandleSetUserConfig, UseLogin: LoginRequired},

// authHandleSetUserConfig godoc
// @Summary Set (insert or update) an item from the per-user configuration.
// @Schemes
// @Description Creates or updates a configuration item.   The user must be logged in.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   user_config        formData    string     true        "An JSON array of config items to delete"
// @Produce json
// @Success 200 {object} jwt_auth.LoginSuccess
// @Failure 403 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/set-user-config [post]
func authHandleSetUserConfig(c *gin.Context) {
	perReqLog := tf.GetLogFilePtr(c)

	var pp ApiSetUserConfig
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	var DBGetUserDataResp RvGetUserConfigType

	UserId, err := GetUserId(c)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": "unrachable-code",
		})
		return
	}

	DumpParamsToLog("After Auth - Top", c)

	// create or replace function q_auth_v1_set_user_config ( p_user_id uuid, varchar, p_hmac_password varchar, p_userdata_password varchar )
	stmt := "q_auth_v1_set_user_config ( $1, $2, $3, $4, $5 )"
	//                                                      1            2        3         4       5                        6
	rv, err := CallDatabaseJSONFunction(c, stmt, "eee..", pp.Name, pp.Value, UserId, aCfg.EncryptionPassword, aCfg.UserdataPassword)
	if err != nil {
		return
	}
	dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
	err = json.Unmarshal([]byte(rv), &DBGetUserDataResp)
	if DBGetUserDataResp.Status != "success" {
		DBGetUserDataResp.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "e", SVar(DBGetUserDataResp), UserId /*aCfg.EncryptionPassword,*/ /*, aCfg.UserdataPassword*/)
		c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, DBGetUserDataResp.StdErrorReturn))
		return
	}

	var out GetUserConfigSuccess
	copier.Copy(&out, &DBGetUserDataResp)
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))
	return

}

// -------------------------------------------------------------------------------------------------------------------------
// Use:
//
//	AuthJWTPublic            string `json:"auth_jwt_public_file" default:""`                                                     // Public Key File
//	AuthJWTPrivate           string `json:"auth_jwt_private_file" default:""`                                                    // Private Key File
//	AuthJWTKeyType           string `json:"auth_jwt_key_type" default:"ES" validate:"v.In(['ES256','RS256', 'ES512', 'RS512'])"` // Key type ES = ESDSA or RS = RSA
type SQLUserIdPrivsType struct {
	UserId     string `json:"user_id,omitempty"      db:"user_id"`
	Privileges string `json:"privileges,omitempty"`
	ClientId   string `json:"client_id,omitempty"    db:"client_id"`
	Email      string `json:"email"                  db:"email"`
	// , min(t2.expires) as expires
	// , ceil(EXTRACT(EPOCH FROM min(t2.expires))) as seconds_till_expires
	Expires            string `json:"expires" 		db:"expires"`
	SecondsTillExpires int64  `json:"seconds_till_expires" db:"seconds_till_expires"`
}

func GetAuthToken(c *gin.Context) (UserId, Email, AuthToken string) {
	perReqLog := tf.GetLogFilePtr(c)
	// dbgo.Fprintf(perReqLog, "    In GetAuthToken at:%(LF), aCfg.TokenHeaderVSCookie==%s\n", aCfg.TokenHeaderVSCookie)
	dbgo.Fprintf(perReqLog, "    %(magenta)In GetAuthToken at:%(LF), aCfg.TokenHeaderVSCookie==%s%(reset)\n", aCfg.TokenHeaderVSCookie)
	// dbgo.Fprintf(os.Stderr, "    %(magenta)In GetAuthToken at:%(LF), aCfg.TokenHeaderVSCookie==%s%(reset)\n", aCfg.TokenHeaderVSCookie) // t1t1xyzzy

	// -----------------------------------------------------------------------------------------------------------------------
	// Look for the auth token in multiple places.
	// if cookie | both - then
	//		check for it as a cookie
	// if header | robht - then
	//		look for it as an "Authorization bearer <tok>" token
	//		look for it as an "X-Authentication" header.
	//	if not found then -- not authorized, done => 401 not authorized return value.
	// -----------------------------------------------------------------------------------------------------------------------
	jwtTok, has := "", false
	if aCfg.TokenHeaderVSCookie == "cookie" || aCfg.TokenHeaderVSCookie == "both" {
		has, jwtTok = HasCookie("X-Authentication", c)
		if has {
			// dbgo.Fprintf(perReqLog, "COOKIE: %(Green) has=%v val=%s for X-Authentication - %(LF)\n", has, jwtTok)
			dbgo.Fprintf(perReqLog, "COOKIE: %(Green) has=%v val=->%s<- for X-Authentication - %(LF)\n", has, jwtTok)
		} else {
			// dbgo.Fprintf(perReqLog, "COOKIE: %(Red) has=%v val=%s for X-Authentication - %(LF)\n", has, jwtTok)
			dbgo.Fprintf(perReqLog, "COOKIE: %(Red) has=%v val=%s for X-Authentication - %(LF)\n", has, jwtTok)
		}
	}
	if !has && (aCfg.TokenHeaderVSCookie == "header" || aCfg.TokenHeaderVSCookie == "both") {
		s := c.Request.Header.Get("Authorization")
		if s != "" {
			ss := strings.Split(s, " ")
			if len(ss) == 2 {
				if strings.ToLower(ss[0]) == "bearer" {
					has = true
					jwtTok = ss[1]
				}
			}
		} else {
			s = c.Request.Header.Get("X-Authentication")
			if s != "" {
				has = true
				jwtTok = s
			}
		}
		if has {
			// dbgo.Fprintf(perReqLog, "AuthorizationBearer: %(Green) has=%v val=%s for Authorization - %(LF)\n", has, jwtTok)
			dbgo.Fprintf(perReqLog, "AuthorizationBearer: %(Green) has=%v val=%s for Authorization - %(LF)\n", has, jwtTok)
		} else {
			// dbgo.Fprintf(perReqLog, "AuthorizationBearer:  has=%v val=%s for Authorization   - NO TOKEN - %(LF)\n", has, jwtTok)
			dbgo.Fprintf(perReqLog, "AuthorizationBearer: %(Red) has=%v val=%s for Authorization   %(yellow) - NO TOKEN - %(LF)\n", has, jwtTok)
		}
	}

	if !has {
		// dbgo.Fprintf(perReqLog, "Authorization:  has=%v -- false -- means not logged in. No Cookie, No Authorization: berrer <token>, %(LF), %s\n", has, dbgo.SVarI(c.Request))
		dbgo.Fprintf(perReqLog, "Authorization: %(red) has=%v -- false -- means not logged in. No Cookie, No Authorization: berrer <token>, %(LF)\n", has)
		return
	} else {

		dbgo.Fprintf(perReqLog, "    %(magenta)In GetAuthToken has is true at:%(LF)%(reset)\n")
		dbgo.Fprintf(os.Stderr, "    %(magenta)In GetAuthToken has is true at:%(LF)%(reset)\n") // t1t1xyzzy

		// Parse and Validate the JWT Berrer
		// Extract the auth_token
		// Validate in the d.b. that this is a valid auth_token
		// get the user_id  -- if have user_id, then ...
		// if valid - then reutrn it.

		// Parse the JWT string and store the result in `claims`.
		// Note that we are passing the key in this method as well. This method will return an error
		// if the token is invalid (if it has expired according to the expiry time we set on sign in),
		// or if the signature does not match
		var err error

		// func VerifyToken(rawToken []byte, alg string, keyData []byte) (token *jwt.Token, err error) {
		// token, err := jwtlib.VerifyToken([]byte(token), gCfg.AuthJWTKeyType, gCfg.AuthJWTPublic )
		// dbgo.Fprintf(os.Stderr, "%(green)== Authentication == New Section ======================================== at: %(LF)\n")

		var tkn *jwt.Token
		if len(gCfg.AuthJWTKey) == 0 && jwtlib.IsHs(gCfg.AuthJWTKeyType) {
			// fmt.Fprintf(os.Stderr, "Fatal Error: Invalid configuration, HS* key and AuthJWTKey not set\n")
			fmt.Fprintf(perReqLog, "Fatal Error: Invalid configuration, HS* key and AuthJWTKey not set\n")
			os.Exit(1)
		} else if len(gCfg.AuthJWTKey) > 0 && jwtlib.IsHs(gCfg.AuthJWTKeyType) {
			tkn, err = jwtlib.VerifyToken([]byte(jwtTok), gCfg.AuthJWTKeyType, []byte(gCfg.AuthJWTKey))
		} else {
			tkn, err = jwtlib.VerifyToken([]byte(jwtTok), gCfg.AuthJWTKeyType, []byte(gCfg.AuthJWTPublic)) // Validate with Public
		}
		if err != nil {
			// dbgo.Fprintf(os.Stderr, "%(LF) Error: Invalid Token : %s token->%s<-\n", err, jwtTok)
			dbgo.Fprintf(perReqLog, "%(LF) Error: Invalid Token : %s token->%s<-\n", err, jwtTok)
		}
		if err != nil || tkn == nil || !tkn.Valid {
			dbgo.Fprintf(perReqLog, "X-Authentication - %(LF)\n")
			// dbgo.Fprintf(os.Stderr, "X-Authentication - %(LF) - token not valid\n")
			// log-xyzzy-log  Log info to log xyzzy
			c.Writer.WriteHeader(http.StatusUnauthorized) // 401
			return
		}

		// return NewWithClaims(method, MapClaims{})
		// type MapClaims map[string]interface{}
		cc, ok := tkn.Claims.(jwt.MapClaims)
		if ok {
			// dbgo.Fprintf(os.Stderr, "%(green)== Mapped the claims to jwt.MapClaims\n")
			AuthToken, ok = cc["auth_token"].(string)
			if !ok {
				AuthToken = ""
				dbgo.Fprintf(perReqLog, "%(red)== Failed! Mapped [auth_token] to string\n")
				// } else {
				// 	dbgo.Fprintf(os.Stderr, "%(green)== Mapped [auth_token] to string\n")
			}
		} else {
			dbgo.Fprintf(perReqLog, "%(red)== Failed! Mapped the claims to jwt.MapClaims\n")
		}

		// dbgo.Fprintf(perReqLog, "X-Authentication - AuthToken = ->%s<- %(LF) --", AuthToken)
		dbgo.Fprintf(perReqLog, "X-Authentication - Have an auth_token - %(green)AuthToken = ->%s<-%(reset) %(LF) --", AuthToken)

		var v2 []*SQLUserIdPrivsType

		// -----------------------------------------------------------------------------------------------------------------------
		// The function will perform this query - but the query is in a stored procedure so it is pre-planned.
		// In this case this will double the performance of the query.
		// -----------------------------------------------------------------------------------------------------------------------
		// The function will perform this query - but the query is in a stored procedure so it is pre-planned.
		//		stmt := `
		//			select t1.user_id as "user_id", json_agg(t3.priv_name)::text as "privileges", coalesce(t1.client_id::text,'') as client_id
		//				 , pgp_sym_decrypt(t1.email_enc, $2)::text as email
		//			from q_qr_users as t1
		//				join q_qr_auth_tokens as t2 on ( t1.user_id = t2.user_id )
		//				left join q_qr_user_to_priv as t3 on ( t1.user_id = t3.user_id )
		//			where t2.token = $1
		//		      and ( t1.start_date < current_timestamp or t1.start_date is null )
		//		      and ( t1.end_date > current_timestamp or t1.end_date is null )
		//			  and t1.email_validated = 'y'
		//		      and ( t1.setup_complete_2fa = 'y' or t1.require_2fa = 'n' )
		//			  and t2.expires > current_timestamp
		//			group by t1.user_id
		//		`
		// -----------------------------------------------------------------------------------------------------------------------
		var has bool
		if v2, has = RedisGetCachedToken(AuthToken, aCfg.UserdataPassword, perReqLog); has {
		} else {
			stmt := `select user_id, privileges, client_id, email, seconds_till_expires from q_qr_validate_user_auth_token ( $1, $2 )`

			err = pgxscan.Select(ctx, conn, &v2, stmt, AuthToken, aCfg.UserdataPassword) // __userdata_password__
			dbgo.Fprintf(perReqLog, "Yep - should be a user_id and a set of privs, output from call >%s<- at:%(LF) stmt=%s auth_token->%s<- gCfg.UserdataPassword->%s<-\n", dbgo.SVarI(v2), stmt, AuthToken, aCfg.UserdataPassword)
			dbgo.Fprintf(os.Stderr, "Yep - should be a user_id and a set of privs, output from call >%s<- at:%(LF) stmt=%s auth_token->%s<- gCfg.UserdataPassword->%s<-\n", dbgo.SVarI(v2), stmt, AuthToken, aCfg.UserdataPassword)
			if err != nil {
				dbgo.Fprintf(perReqLog, "%(red)%(LF) Error:%s stmt ->%s<- data:%s %s\n", err, stmt, AuthToken, aCfg.UserdataPassword)
				log_enc.LogSQLError(c, stmt, err, "e", AuthToken, aCfg.UserdataPassword)
				return
			}
			RedisCacheAuthTokens(AuthToken, aCfg.UserdataPassword, v2, perReqLog)
		}

		// dbgo.Fprintf(os.Stderr, "%(green)%(LF) stmt ->%s<- data:%s %s\n", stmt, AuthToken, aCfg.UserdataPassword)
		// dbgo.Fprintf(perReqLog, "X-Authentication - after select len(v2) = %d %(LF)\n", len(v2))
		// dbgo.Fprintf(os.Stderr, "X-Authentication - after select len(v2) = %d %(LF), data=%s\n", len(v2), dbgo.SVarI(v2))
		if len(v2) > 0 {
			UserId = v2[0].UserId
			Email = v2[0].Email
			// dbgo.Fprintf(perReqLog, "Is Authenticated! ----------------------- X-Authentication - %(LF)\n")
			dbgo.Fprintf(perReqLog, "%(green)Is Authenticated! - %(LF)\n")
			c.Set("__is_logged_in__", "y")
			c.Set("__user_id__", UserId)
			c.Set("__auth_token__", AuthToken)
			rv, mr := ConvPrivs(perReqLog, v2[0].Privileges)
			c.Set("__privs__", rv)
			c.Set("__privs_map__", mr)
			c.Set("__email_hmac_password__", aCfg.EncryptionPassword)
			c.Set("__user_password__", aCfg.UserdataPassword) // __userdata_password__
			c.Set("__client_id__", v2[0].ClientId)
			c.Set("__login_email_addr__", v2[0].Email)
		} else {
			// dbgo.Fprintf(perReqLog, "X-Authentication - %(LF) - did not find auth_token in database - Not Authenticated\n")
			dbgo.Fprintf(perReqLog, "X-Authentication - %(LF) - %(red)did not find auth_token in database - Not Authenticated\n")
			UserId = ""
			AuthToken = ""
		}

	}
	// dbgo.Fprintf(perReqLog, "X-Authentication - at:%(LF)\n")
	// dbgo.Fprintf(os.Stderr, "X-Authentication - at:%(LF) AuthToken=->%s<-\n", AuthToken) // t1t1xyzzy
	return
}

// -------------------------------------------------------------------------------------------------------------------------
// Use:
//	AuthJWTPublic            string `json:"auth_jwt_public_file" default:""`                                                     // Public Key File
//	AuthJWTPrivate           string `json:"auth_jwt_private_file" default:""`                                                    // Private Key File
//	AuthJWTKeyType           string `json:"auth_jwt_key_type" default:"ES" validate:"v.In(['ES256','RS256', 'ES512', 'RS512'])"` // Key type ES = ESDSA or RS = RSA

func CreateJWTSignedCookie(c *gin.Context, DBAuthToken, email_addr string, NoCookieRequested NoCookieType) (rv string, err error) {

	perReqLog := tf.GetLogFilePtr(c)
	if DBAuthToken != "" { // If the Database code created an auth-token, then this needs to be converted to a JWT-Token and sent back to the user (Coookie, Header etc)

		claims := jwt.MapClaims{
			"auth_token": DBAuthToken,
		}

		dbgo.Fprintf(perReqLog, "%(green)== Authentication == New Sign/Cookie Section ======================================== at: %(LF)\n")
		if len(gCfg.AuthJWTKey) == 0 && jwtlib.IsHs(gCfg.AuthJWTKeyType) {
			// fmt.Fprintf(perReqLog, "Fatal Error: Invalid configuration, HS* key and AuthJWTKey not set\n")
			fmt.Fprintf(perReqLog, "Fatal Error: Invalid configuration, HS* key and AuthJWTKey not set\n")
			os.Exit(1)
		} else if len(gCfg.AuthJWTKey) > 0 && jwtlib.IsHs(gCfg.AuthJWTKeyType) {
			dbgo.Fprintf(perReqLog, "%(green)== HS type key - this is good.\n")
			rv, err = jwtlib.SignToken([]byte("{}"), gCfg.AuthJWTKeyType, map[string]string{}, claims, []byte(gCfg.AuthJWTKey))
		} else {
			dbgo.Fprintf(perReqLog, "%(green)== ES/RS/EdDSA type key - this is new. ->%s<- -- using a pub/private key\n", gCfg.AuthJWTKeyType)
			// dbgo.Fprintf(perReqLog, "%(green)== Private Key ->%s<-\n", gCfg.AuthJWTPrivate)
			// jwtlib. SignToken(rawToken []byte, Alg string, Head map[string]string, claims jwt.MapClaims, keyData []byte) (signedToken string, err error) {
			rv, err = jwtlib.SignToken([]byte("{}"), gCfg.AuthJWTKeyType, map[string]string{}, claims, []byte(gCfg.AuthJWTPrivate)) // Sign with Private
		}
		if err != nil {
			log_enc.LogMiscError(c, err, fmt.Sprintf("Unable to convert JWT key to []byte from hex ->%s<-", err))
			return
		}

		// "Progressive improvement beats delayed perfection" -- Mark Twain
		if aCfg.TokenHeaderVSCookie == "header" || aCfg.TokenHeaderVSCookie == "both" {
			c.Writer.Header().Set("Authorization", "Bearer "+rv)
			if gCfg.ReleaseMode == "dev" {
				c.Writer.Header().Set("Authentication-User", email_addr)
			}
		}
		if aCfg.TokenHeaderVSCookie == "cookie" || aCfg.TokenHeaderVSCookie == "both" {
			// Skip cookeis - this is useful for browser extensions that can not use a "cookie" for auth.
			// You can set any value for the 'no_cookie' data field.   Normally if you want to skip cookies
			// send 'nc' for the value.
			dbgo.Printf("%(magenta)AT: %(LF) - woofing cookies\n")
			if NoCookieRequested == CookieUsed {
				SetCookie("X-Authentication", rv, c) // Will be a secure http cookie on TLS.
				dbgo.Printf("%(magenta)AT: %(LF) - cookies %s %s\n", "X-Authentication", rv)
				if gCfg.ReleaseMode == "dev" {
					SetCookie("X-Authentication-User", email_addr, c) // Will be a secure http cookie on TLS.
					dbgo.Printf("%(magenta)AT: %(LF) - cookies %s %s\n", "X-Authentication-User", email_addr)
				}
				dbgo.Printf("%(magenta)AT: %(LF) - cookies %s %s\n", "X-Is-Logged-In", "yes")
				SetInsecureCookie("X-Is-Logged-In", "yes", c) // To let the JS code know that it is logged in.		// xyzzy-Expire
			}
		}
	}

	return
}

// -------------------------------------------------------------------------------------------------------------------------
// Use:
//	AuthJWTPublic            string `json:"auth_jwt_public_file" default:""`                                                     // Public Key File
//	AuthJWTPrivate           string `json:"auth_jwt_private_file" default:""`                                                    // Private Key File
//	AuthJWTKeyType           string `json:"auth_jwt_key_type" default:"ES" validate:"v.In(['ES256','RS256', 'ES512', 'RS512'])"` // Key type ES = ESDSA or RS = RSA

func CreateJWTSignedCookieNoErr(c *gin.Context, DBAuthToken, email_addr string) (rv string, err error) {

	perReqLog := tf.GetLogFilePtr(c)
	if DBAuthToken != "" { // If the Database code created an auth-token, then this needs to be converted to a JWT-Token and sent back to the user (Coookie, Header etc)

		claims := jwt.MapClaims{
			"auth_token": DBAuthToken,
		}

		dbgo.Fprintf(perReqLog, "%(green)== Authentication == New Sign/Cookie Section ======================================== at: %(LF)\n")
		if len(gCfg.AuthJWTKey) == 0 && jwtlib.IsHs(gCfg.AuthJWTKeyType) {
			md.AddCounter("jwt_auth_misc_fatal_error", 1)
			// fmt.Fprintf(perReqLog, "Fatal Error: Invalid configuration, HS* key and AuthJWTKey not set\n")
			fmt.Fprintf(perReqLog, "Fatal Error: Invalid configuration, HS* key and AuthJWTKey not set\n")
			os.Exit(1)
		} else if len(gCfg.AuthJWTKey) > 0 && jwtlib.IsHs(gCfg.AuthJWTKeyType) {
			dbgo.Fprintf(perReqLog, "%(green)== HS type key - this is good.\n")
			rv, err = jwtlib.SignToken([]byte("{}"), gCfg.AuthJWTKeyType, map[string]string{}, claims, []byte(gCfg.AuthJWTKey))
		} else {
			dbgo.Fprintf(perReqLog, "%(green)== ES/RS/EdDSA type key - this is new. ->%s<- -- using a pub/private key\n", gCfg.AuthJWTKeyType)
			rv, err = jwtlib.SignToken([]byte("{}"), gCfg.AuthJWTKeyType, map[string]string{}, claims, []byte(gCfg.AuthJWTPrivate)) // Sign with Private
		}
		if err != nil {
			md.AddCounter("jwt_auth_misc_error", 1)
			if logger != nil {
				fields := []zapcore.Field{
					zap.String("message", "Error In Signing a Cookie as a JWT Token"),
					zap.Error(err),
					zap.String("location", dbgo.LF()),
				}
				logger.Error("failed-to-sign-jwt-token", fields...)
			} else {
				dbgo.Fprintf(perReqLog, "Error: Error occured in signing a cookie as a JWT token: %s at:%(LF)\n", err)
			}
			return
		}
	}
	return
}

// -------------------------------------------------------------------------------------------------------------------------
func Confirm2faSetupAccount(c *gin.Context, UserId string) {
	perReqLog := tf.GetLogFilePtr(c)
	// create or replace function q_auth_v1_setup_2fa ( p_user_id varchar )
	stmt := "q_auth_v1_setup_2fa_test ( $1, $2, $3 )"
	rv, err := CallDatabaseJSONFunction(c, stmt, "!", UserId, aCfg.EncryptionPassword, aCfg.UserdataPassword)
	if err != nil {
		return
	}
	dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
	return
}

// -------------------------------------------------------------------------------------------------------------------------
func GenerateSecret() string {
	return htotp.RandomSecret(16)
}

// -------------------------------------------------------------------------------------------------------------------------
//
//	ConfirmEmailAccount uses the token to lookup a user and confirms that the email that received the token is real.
func ConfirmEmailAccount(c *gin.Context, EmailVerifyToken string) (rv, stmt string, err error) {

	perReqLog := tf.GetLogFilePtr(c)
	// xyzzyRedisUsePubSub gCfg.RedisUsePubSub   string `json:"redis_use_pub_sub" default:"no"`

	//                          1                             2                        3                            4
	// q_auth_v1_email_verify ( p_email_verify_token varchar, p_hmac_password varchar, p_userdata_password varchar, p_n6_flag varchar ) RETURNS text
	stmt = "q_auth_v1_email_verify ( $1, $2, $3, $4 )"
	//                                                 1                 2                        3                      4
	rv, err = CallDatabaseJSONFunction(c, stmt, "!!!", EmailVerifyToken, aCfg.EncryptionPassword, aCfg.UserdataPassword, gCfg.AuthEmailToken)
	if err != nil {
		return
	}
	dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
	return
}

// -------------------------------------------------------------------------------------------------------------------------
func SaveState(cookieValue string, UserId string, c *gin.Context) (err error) {
	perReqLog := tf.GetLogFilePtr(c)
	// set Cookie for SavedState -- Save into database!
	//jwt, err := GetJWTAuthResponceWriterFromWWW(www, req)
	//if err != nil {
	//	return
	//}
	// jwt := GetCreateParsedParams(www, req)
	// jwt.SavedStateVars["__test__"] = "State Saved"
	c.Set("__test__", "Saved State")
	// xyzzy100 - TODO  -- how to get all state to save it.
	/*
		stateData := SVarI(jwt.SavedStateVars)
	*/
	stateData := "{}" // xyzzy100 - TODO
	/*
		CREATE TABLE if not exists q_qr_saved_state (
			saved_state_id		uuid DEFAULT uuid_generate_v4() not null primary key, -- this is the X-Saved-State cookie
			user_id 			int not null,	-- should FK to user
			data				jsonb,			-- the data.
			expires 			timestamp not null,
			updated 			timestamp, 									 						-- Project update timestamp (YYYYMMDDHHMMSS timestamp).
			created 			timestamp default current_timestamp not null 						-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
		);
	*/
	stmt := `insert into q_qr_saved_state ( saved_state_id, user_id, data ) values ( $1, $2, $3 )
		on conflict on constraint q_qr_saved_state_pkey
		do update set data = $3
	`
	res, err := conn.Exec(ctx, stmt, cookieValue, UserId, stateData)
	if err != nil {
		dbgo.Fprintf(perReqLog, " at %(LF)\n")
		log_enc.LogSQLError(c, stmt, err, "e.e", cookieValue, UserId, stateData)
		return fmt.Errorf("Sql error")
	}
	_ = res
	return
}

// -------------------------------------------------------------------------------------------------------------------------
// IsLoggedIn returns true if the user is currently logged in or if the user can be logged in.  The login can be determined
// with a cookie or an berrer auth token.   This call has side-effects - it will add authentication information to the
// context like, __is_logged_in__.    See GetAuthToken().
//
// This is the fucntion to call to login a user.
func IsLoggedIn(c *gin.Context) (ItIs bool) {
	perReqLog := tf.GetLogFilePtr(c)
	s := c.GetString("__is_logged_in__")
	if s == "y" {
		ItIs = true
	} else {
		UserId, _, AuthToken := GetAuthToken(c)
		if AuthToken != "" {
			dbgo.Fprintf(perReqLog, " %(LF) 2nd part of authorization: user_id=%s auth_token=->%s<-\n", UserId, AuthToken)
			ItIs = true
		} else {
			dbgo.Fprintf(perReqLog, " %(LF) ****not authoriazed ****2nd part of authorization: user_id=%s auth_token=->%s<-\n", UserId, AuthToken)
		}
	}
	return
}

// Input : [{"priv_name":"May Change Password"}, {"priv_name":"May Password"}]
// Outupt : {"May Change Password":true, "May Password":true}
// func ConvPrivs(perReqLog *os.File, Privileges string) (rv string, mr map[string]bool) {
// func ConvPrivs(perReqLog io.WriteCloser, Privileges string) (rv string, mr map[string]bool) {
func ConvPrivs(perReqLog io.WriteCloser, Privileges string) (rv string, mr map[string]bool) {

	if Privileges == "" {
		return
	}
	var PrivData []string
	mr = make(map[string]bool)
	err := json.Unmarshal([]byte(Privileges), &PrivData)
	if err != nil {
		dbgo.Fprintf(perReqLog, "Invalid syntax ->%s<- %s at:%(LF)\n", Privileges, err)
		rv = ""
		return
	}
	for _, vv := range PrivData {
		mr[vv] = true
	}

	rv = SVarI(mr)
	return
}

// Input : ["May Change Password", "May Do Whatever"]
// Outupt : {"May Change Password":true, "May Do Whatever":true}
// func ConvPrivs2(perReqLog *os.File, Privileges []string) (rv string, mr map[string]bool) {
func ConvPrivs2(perReqLog io.WriteCloser, Privileges []string) (rv string, mr map[string]bool) {
	// dbgo.Fprintf(perReqLog, "%(cyan)%(LF) -- ConvPrivs2(%s) ==\n", dbgo.SVar(Privileges))

	mr = make(map[string]bool)
	if len(Privileges) == 0 {
		return
	}

	for _, vv := range Privileges {
		mr[vv] = true
	}

	rv = SVarI(mr)
	return
}

/* should make this middlware! */
/* From: https://techwasti.com/log-requests-and-responses-in-go-gin */
func peekAtBody(c *gin.Context) {

	// dbgo.Fprintf(perReqLog, "\n\n%(magenta)Request\n===============================================================================================================%(reset)\n%(yellow)Headers\n")
	//
	//	for name, values := range c.Request.Header {
	//		// Loop over all values for the name.
	//		for _, value := range values {
	//			dbgo.Printf("%(yellow)\t%s ->%s<-\n", name, value)
	//		}
	//	}
	//
	// body, err := io.ReadAll(c.Request.Body)
	//
	//	if err != nil {
	//		dbgo.Fprintf(perReqLog, "%(red)request body pee resulted in error: %s\n", err)
	//	} else {
	//
	//		dbgo.Fprintf(perReqLog, "%(yellow)request body ->%s<-\n", body)
	//		c.Request.Body = io.NopCloser(bytes.NewReader(body))
	//	}

}

func BindFormOrJSON(c *gin.Context, bindTo interface{}) (err error) {

	perReqLog := tf.GetLogFilePtr(c)
	peekAtBody(c)
	if err = c.ShouldBind(bindTo); err != nil {
		// dbgo.Printf("%(red)In BindFormOrJSON at:%(LF) err=%s\n", err)
		dbgo.Fprintf(perReqLog, "%(red)In BindFormOrJSON at:%(LF) err=%s\n", err)
		c.JSON(http.StatusNotAcceptable, LogJsonReturned(perReqLog, gin.H{ // 406
			"status": "error",
			"msg":    fmt.Sprintf("Error: %s", err),
		}))
		return
	}

	dbgo.Fprintf(perReqLog, "%(cyan)Parameters: %s at %s\n", dbgo.SVarI(bindTo), dbgo.LF(2))
	// dbgo.Fprintf(perReqLog, "Parameters: %s at %s\n", dbgo.SVarI(bindTo), dbgo.LF(2))
	return
}

func BindFormOrJSONOptional(c *gin.Context, bindTo interface{}) (err error) {

	perReqLog := tf.GetLogFilePtr(c)
	peekAtBody(c)
	if err = c.ShouldBind(bindTo); err != nil {
		dbgo.Fprintf(perReqLog, "%(yellow)In BindFormOrJSONOptional at:%(LF) GET Query err=%s\n", err)
		// dbgo.Fprintf(perReqLog, "In BindFormOrJSONOptional at:%(LF) GET Query err=%s\n", err)
		return
	}

	// dbgo.Printf("# BindData %(cyan)Parameters: %s at %s\n", dbgo.SVarI(bindTo), dbgo.LF(2))
	dbgo.Fprintf(perReqLog, "# BindData: Parameters: %s at %s\n", dbgo.SVarI(bindTo), dbgo.LF(2))
	return
}

// func LogJsonReturned(perReqLog *os.File, x interface{}) interface{} {
func LogJsonReturned(perReqLog io.WriteCloser, x interface{}) interface{} {
	if y, ok := x.(string); ok {
		dbgo.Fprintf(perReqLog, "%(cyan)Returns: %s at:%s\n", y, dbgo.LF(2))
		// dbgo.Fprintf(perReqLog, "Returns: %s at:%s\n", y, dbgo.LF(2))
	} else {
		dbgo.Fprintf(perReqLog, "%(cyan)Returns: %s at:%s\n", dbgo.SVarI(x), dbgo.LF(2))
		// dbgo.Fprintf(perReqLog, "Returns: %s at:%s\n", dbgo.SVarI(x), dbgo.LF(2))
	}
	return x
}

func convertStringArrayToInterface(ss []string) (rv []interface{}) {
	for _, vv := range ss {
		rv = append(rv, vv)
	}
	return
}

func TestSendEmail(SendTestEmail, SendTestEmailTemplateToRun, AdditionalData string) {

	// var SendTestEmailTemplateToRun = flag.String("send-test-email-template-to-run", "", "ONLY! run 1 ttemplate")
	// jwt_auth.TestSendEmail ( *SendTestEmail, *SendTestEmailTemplateToRun )
	// ---------------------------------------------------------------------------------------------------------------------
	// send registration email.
	// ---------------------------------------------------------------------------------------------------------------------
	Email := SendTestEmail
	FirstName := "John"
	LastName := "Smith"
	EmailVerifyToken := "e35940af-720c-4438-be52-000000002001"
	EmailVerifyToken = "45faa5c6-3f6f-4fb1-8ede-83611ecd3597"
	UserId := "18207657-b420-445a-aea5-000000002023"
	RecoveryToken := "e35940af-720c-4438-be52-000000222001"
	dbgo.Printf("Email Test is Using (at:%(LF)) %s ------------ Predefined Values ------------ \n",
		dbgo.SVarI(map[string]interface{}{
			"username":           Email,
			"email":              Email,
			"email_url_encoded":  url.QueryEscape(Email),
			"first_name":         FirstName,
			"last_name":          LastName,
			"real_name":          FirstName + " " + LastName,
			"application_name":   gCfg.AuthApplicationName,
			"realm":              gCfg.AuthRealm,
			"server":             gCfg.BaseServerURL,
			"reset_password_uri": gCfg.AuthPasswordRecoveryURI,
			"RecoveryToken":      RecoveryToken,
		}),
	)

	ss := strings.Split(AdditionalData, ",")
	if len(ss) > 0 {
		//		"application_name":   gCfg.AuthApplicationName,
		//		"realm":              gCfg.AuthRealm,
		//		"server":             gCfg.BaseServerURL,
		//		"reset_password_uri": gCfg.AuthPasswordRecoveryURI,
		ss = append(ss, "email")
		ss = append(ss, Email)
		ss = append(ss, "application_name")
		ss = append(ss, gCfg.AuthApplicationName)
		ss = append(ss, "realm")
		ss = append(ss, gCfg.AuthRealm)
		ss = append(ss, "server")
		ss = append(ss, gCfg.BaseServerURL)
		ss = append(ss, "reset_password_uri")
		ss = append(ss, gCfg.AuthPasswordRecoveryURI)
		dbgo.Printf("Email Test is Using (at:%(LF)) %s ------------ User Values ------------ \n    These are values used if you are NOT runing a pre-defined email\n", dbgo.SVarI(ss))
	}

	if SendTestEmailTemplateToRun == "welcome_registration" || SendTestEmailTemplateToRun == "" {
		em.SendEmail("welcome_registration", // Email Template
			"username", Email,
			"email", Email,
			"email_url_encoded", url.QueryEscape(Email),
			"first_name", FirstName,
			"last_name", LastName,
			"real_name", FirstName+" "+LastName,
			"token", EmailVerifyToken,
			"user_id", UserId,
			"server", gCfg.BaseServerURL,
			"application_name", gCfg.AuthApplicationName,
			"realm", gCfg.AuthRealm,
		)
	} else if SendTestEmailTemplateToRun == "login_new_device" {
		em.SendEmail("login_new_device",
			"username", Email,
			"email", Email,
			"email_url_encoded", url.QueryEscape(Email),
			"first_name", FirstName,
			"last_name", LastName,
			"real_name", FirstName+" "+LastName,
			"application_name", gCfg.AuthApplicationName,
			"realm", gCfg.AuthRealm,
			"server", gCfg.BaseServerURL,
			"reset_password_uri", gCfg.AuthPasswordRecoveryURI,
		)
	} else if SendTestEmailTemplateToRun == "password_changed" {
		em.SendEmail("password_changed",
			"username", Email,
			"email", Email,
			"email_url_encoded", url.QueryEscape(Email),
			"first_name", FirstName,
			"last_name", LastName,
			"real_name", FirstName+" "+LastName,
			"application_name", gCfg.AuthApplicationName,
			"realm", gCfg.AuthRealm,
			"server", gCfg.BaseServerURL,
			"reset_password_uri", gCfg.AuthPasswordRecoveryURI,
		)
	} else if SendTestEmailTemplateToRun == "recover_password" {
		em.SendEmail("recover_password",
			"username", Email,
			"email", Email,
			"email_url_encoded", url.QueryEscape(Email),
			"token", RecoveryToken,
			"first_name", FirstName,
			"last_name", LastName,
			"real_name", FirstName+" "+LastName,
			"application_name", gCfg.AuthApplicationName,
			"realm", gCfg.AuthRealm,
			"server", gCfg.BaseServerURL,
			"reset_password_uri", gCfg.AuthPasswordRecoveryURI,
		)
	} else if SendTestEmailTemplateToRun == "password_updated" {
		em.SendEmail("password_updated",
			"username", Email,
			"email", Email,
			"email_url_encoded", url.QueryEscape(Email),
			"first_name", FirstName,
			"last_name", LastName,
			"real_name", FirstName+" "+LastName,
			"application_name", gCfg.AuthApplicationName,
			"token", RecoveryToken,
			"realm", gCfg.AuthRealm,
			"server", gCfg.BaseServerURL,
		)
	} else if SendTestEmailTemplateToRun == "account_deleted" {
		em.SendEmail("account_deleted",
			"username", Email,
			"email", Email,
			"email_url_encoded", url.QueryEscape(Email),
			"first_name", FirstName,
			"last_name", LastName,
			"real_name", FirstName+" "+LastName,
			"application_name", gCfg.AuthApplicationName,
			"realm", gCfg.AuthRealm,
			"server", gCfg.BaseServerURL,
			"reset_password_uri", gCfg.AuthPasswordRecoveryURI,
		)
	} else if SendTestEmailTemplateToRun == "admin_password_changed" {
		em.SendEmail("admin_password_changed",
			"username", Email,
			"email", Email,
			"email_url_encoded", url.QueryEscape(Email),
			"first_name", FirstName,
			"last_name", LastName,
			"real_name", FirstName+" "+LastName,
			"application_name", gCfg.AuthApplicationName,
			"realm", gCfg.AuthRealm,
			"server", gCfg.BaseServerURL,
			"reset_password_uri", gCfg.AuthPasswordRecoveryURI,
		)
	} else {
		em.SendEmail(SendTestEmailTemplateToRun, convertStringArrayToInterface(ss)...)
	}
}

// xyzzy34343455 TODO ----------------------------- Check to see if there is an usage "AUTH" token on CLI
/*
	CREATE TABLE if not exists q_qr_auth_tokens (
		auth_token_id 	uuid default uuid_generate_v4() primary key not null,
		user_id 				uuid not null,
		token			 		uuid not null,
		api_encryption_key		text,
		expires 				timestamp not null
	);

	UserID, AuthToken  = jwt_auth.CheckUsageAuthToken ( c )
	...
	// firstname := c.DefaultQuery("use_token", "")

	// to Create...
	// AuthToken  = jwt_auth.CreateUsageAuthToken ( c, UserID )

		// xyzzy34343455 TODO ----------------------------- Check to see if there is an usage "AUTH" token on CLI (tat==TmpAuthToken)

			UserID, AuthToken  = jwt_auth.CheckTmpAuthToken ( c, pp.TmpAuthToken )
					CREATE OR REPLACE FUNCTION q_auth_v1_create_use_token ( p_user_id uuid, p_token varchar ) RETURNS text

			// firstname := c.DefaultQuery("use_token", "")

			// to Create... (when link is created)
			// AuthToken  = jwt_auth.CreateUsageAuthToken ( c, UserID )
					CREATE OR REPLACE FUNCTION q_auth_v1_valid_use_token ( p_token varchar ) RETURNS text


CREATE OR REPLACE FUNCTION q_auth_v1_valid_use_token ( p_token varchar ) RETURNS text
AS $$
DECLARE
	l_data				text;
	l_fail				bool;
	l_user_id			uuid;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	select  user_id
		into l_user_id
		from q_qr_auth_tokens as t1
		where t1.api_encryption_key = p_token
		;
	if not found then
		l_fail = true;
		l_data = '{"status":"error","msg":"Invalid Use Token","code":"m4_count()","location":"m4___file__ m4___line__"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Use Token', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "user_id":'  			||coalesce(to_json(l_user_id)::text,'""')
			||', "auth_token":'  			||coalesce(to_json(p_token)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;


-- select q_auth_v1_set_client ( 'bob@example.com', 'iLoves',  'my long secret password' );



CREATE OR REPLACE FUNCTION q_auth_v1_create_use_token ( p_user_id uuid, p_token varchar ) RETURNS text
AS $$
DECLARE
	l_data				text;
	l_fail				bool;
	l_auth_token		uuid;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_auth_token = uuid_generate_v4();
	insert into q_qr_auth_tokens ( token, user_id, api_encryption_key ) values ( l_auth_token, p_user_id, p_token );

	if not l_fail then
		l_data = '{"status":"success"'
			||', "user_id":'  			||coalesce(to_json(p_user_id)::text,'""')
			||', "auth_token":'  			||coalesce(to_json(l_auth_token)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;


-- select q_auth_v1_set_client ( 'bob@example.com', 'iLoves',  'my long secret password' );
select q_auth_v1_create_use_token ( '88fc6df6-96ba-4073-b248-941af617bd58'::uuid, 'abc' );
select q_auth_v1_valid_use_token ( 'abc' );

*/

type RvValidUseToken struct {
	StdErrorReturn
	UserId    string `json:"user_id,omitempty"    db:"user_id"`
	AuthToken string `json:"auth_token,omitempty" db:"auth_token"`
}

func CheckTmpAuthToken(c *gin.Context, AToken string) (UserId, AuthToken string, err error) {

	perReqLog := tf.GetLogFilePtr(c)
	var DBValidUseToken RvValidUseToken
	var rv string

	// Validate AToken (Temporary Token) and return an actual UserId and AuthToken.
	// CREATE OR REPLACE FUNCTION q_auth_v1_valid_use_token ( p_token varchar ) RETURNS text
	stmt := "q_auth_v1_valid_use_token ( $1 )"
	//                                                1
	rv, err = CallDatabaseJSONFunction(c, stmt, ".", AToken)
	if err != nil {
		return
	}
	dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
	err = json.Unmarshal([]byte(rv), &DBValidUseToken)
	if DBValidUseToken.Status != "success" {
		DBValidUseToken.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "e", SVar(DBValidUseToken), AToken)
		c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, DBValidUseToken.StdErrorReturn))
		return
	}

	UserId = DBValidUseToken.UserId
	AuthToken = DBValidUseToken.AuthToken
	return
}

type RvCreateUseToken struct {
	StdErrorReturn
	AuthToken string `json:"auth_token,omitempty" db:"auth_token"`
}

func CreateTmpAuthToken(c *gin.Context, UserId string) (AToken string, err error) {

	perReqLog := tf.GetLogFilePtr(c)
	var DBCreateUseToken RvCreateUseToken
	var rv string

	AToken = GenUUID()

	// AuthToken - this is the returned token that is the "Temporary Token"
	// CREATE OR REPLACE FUNCTION q_auth_v1_create_use_token ( p_user_id uuid, p_token varchar ) RETURNS text
	stmt := "q_auth_v1_create_use_token ( $1, $2 )"
	//                                                1
	rv, err = CallDatabaseJSONFunction(c, stmt, ".", UserId, AToken)
	if err != nil {
		return
	}
	dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
	err = json.Unmarshal([]byte(rv), &DBCreateUseToken)
	if DBCreateUseToken.Status != "success" {
		DBCreateUseToken.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "e", SVar(DBCreateUseToken), UserId)
		c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, DBCreateUseToken.StdErrorReturn))
		return
	}

	return
}

// -------------------------------------------------------------------------------------------------------------------------
// {Method: "POST", Path: "/api/v1/auth/validate-token", Fx: authHandleValidateToken, UseLogin: LoginRequired},                      //  Checks that AuthToken + Fingerprint data is valid, if not display a Login

type RvValidateTokenType struct {
	StdErrorReturn
	AuthToken   string            `json:"auth_token,omitempty"`
	Token       string            `json:"token,omitempty"` // the JWT Token???
	UserId      string            `json:"user_id,omitempty"`
	AccountType string            `json:"account_type,omitempty"`
	Email       string            `json:"email_address"`
	FirstName   string            `json:"first_name,omitempty"`
	LastName    string            `json:"last_name,omitempty"`
	AcctState   string            `json:"acct_state,omitempty"`
	UserConfig  map[string]string `json:"user_config,omitempty"`
}

// Output returned
type ValidateTokenSuccess struct {
	Status      string            `json:"status"`
	Token       string            `json:"token,omitempty"` // the JWT Token???
	AccountType string            `json:"account_type,omitempty"`
	FirstName   string            `json:"first_name,omitempty"`
	LastName    string            `json:"last_name,omitempty"`
	AcctState   string            `json:"acct_state,omitempty"`
	UserConfig  map[string]string `json:"user_config,omitempty"`
}

// Input for refresh token
type ApiAuthValidateToken struct {
	AmIKnown string `json:"am_i_known" form:"am_i_known"`
	XsrfId   string `json:"xsrf_id"    form:"xsrf_id"     binding:"required"`

	FPData string `json:"fp_data"    form:"fp_data"` // fingerprint data
	ScID   string `json:"scid"       form:"scid"`    // y_id - local storage ID

	// You can set any value for the 'no_cookie' data field.   Normally if you want to skip cookies send 'nc' for the value.
	NoCookie string `json:"no_cookie"  form:"no_cookie"` // default is to NOT send cookie if cookies and headers (both ==> , "token_header_vs_cookie": "both") are defined,
}

// authHandleValidateToken godoc
// @Summary Validate auth token.
// @Schemes
// @Description Given a valid logged in use and a current auth_token, refresh it.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Produce json
// @Success 200 {object} jwt_auth.ValidateTokenSuccess
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/validate-token [post]
func authHandleValidateToken(c *gin.Context) {
	var pp ApiAuthValidateToken
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}
	perReqLog := tf.GetLogFilePtr(c)

	// validate inputs AmIKnown, if "" - then 401 - pass to q_auth_v1_refresh_token

	// validate inputs XsrfId, if "" - then 401
	if err := ValidateXsrfId(c, pp.XsrfId); err != nil {
		return
	}

	UserId, _, AuthToken := GetAuthToken(c)

	if AuthToken != "" { // if user is logged in then generate new OTP else - just ignore.

		DumpParamsToLog("After Auth - Top", c)

		// function q_auth_v1_regen_otp ( p_email varchar, p_pw varchar, p_hmac_password varchar , p_userdata_password varchar )
		stmt := "q_auth_v1_validate_token ( $1, $2, $3, $4, $5 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, "e!..", UserId, AuthToken, pp.AmIKnown, aCfg.EncryptionPassword, aCfg.UserdataPassword)
		if e0 != nil {
			return
		}

		dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)
		var rvStatus RvValidateTokenType
		err := json.Unmarshal([]byte(rv), &rvStatus)
		if rvStatus.Status == "401" {
			goto no_auth
		}
		if err != nil || rvStatus.Status != "success" {
			rvStatus.LogUUID = GenUUID()
			// dbgo.Fprintf(perReqLog, "%(LF) email >%s< AuthToken >%s<\n", pp.Email, AuthToken)
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
			c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, rvStatus.StdErrorReturn)) // 400
			return
		}

		// “Do what you can, with what you have, where you are.” – Theodore Roosevelt

		// replace current cookie/header with new signed token
		if rvStatus.AuthToken != "" {
			theJwtToken, err := CreateJWTSignedCookie(c, rvStatus.AuthToken, rvStatus.Email, g_lib.IfTrue(pp.NoCookie == "nc", NoCookie, CookieUsed))
			if err != nil {
				return
			}
			// dbgo.Fprintf(perReqLog, "!! Creating COOKIE Token, Logged In !!  at:%(LF): AuthToken=%s jwtCookieToken=%s email=%s\n", rvStatus.AuthToken, theJwtToken, rvStatus.Email)
			dbgo.Fprintf(perReqLog, "%(green)!! Creating COOKIE Token, Logged In !!  at:%(LF): AuthToken=%s jwtCookieToken=%s email=%s\n", rvStatus.AuthToken, theJwtToken, rvStatus.Email)

			c.Set("__auth_token__", rvStatus.AuthToken)

			md.AddCounter("jwt_auth_success_login", 1)

			if theJwtToken != "" {
				// "Progressive improvement beats delayed perfection" -- Mark Twain
				if aCfg.TokenHeaderVSCookie == "cookie" {
					rvStatus.Token = ""
					c.Set("__jwt_token__", "")
					c.Set("__jwt_cookie_only__", "yes")
				} else { // header or both
					rvStatus.Token = theJwtToken
					c.Set("__jwt_token__", theJwtToken)
				}

			}
		}

		var out ValidateTokenSuccess
		copier.Copy(&out, &rvStatus)
		c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))
		return
	}

no_auth:

	// Error Return -----------------------------------------------------------------------
	// Sleep to mitigate DDOS attacks using this call to find out if a token is valid
	time.Sleep(1500 * time.Millisecond)

	out := StdErrorReturn{
		Status:   "error",
		Msg:      "401 not authorized",
		Location: dbgo.LF(),
	}
	c.JSON(http.StatusUnauthorized, LogJsonReturned(perReqLog, out))
	return

}

func UrlJoinPath(t string, s ...string) (rv string) {
	var err error
	rv, err = url.JoinPath(t, s...)
	if err != nil {
		// dbgo.Fprintf(perReqLog, "URL Join Error : ->%s<-\n An error occured in joining the path: %s at:%s\n", t, err, dbgo.LF(-2))
		dbgo.Fprintf(logFilePtr, "%(red)URL Join Error : ->%s<-\n An error occured in joining the path: %s at:%s\n", t, err, dbgo.LF(-2))
		rv = gCfg.BaseServerURL
	}
	return
}

/*
		if [ "$server" = "http://localhost:15080" ] ; then
			${PSQL}  <<XXxx
		select *
			from q_qr_token_registration
			;
XXxx
		else

			wget --keep-session-cookies --load-cookies ../cookies.txt --save-cookies ../cookies.txt \
				-o list-token-registration.err -O list-token-registration.out \
				--post-data "a=b"
				"${server}/api/v1/auth/list-token-registration"

			echo ""
			cat list-token-registration.err
			echo ""
			cat list-token-registration.out
			echo ""

		fi
*/

// -------------------------------------------------------------------------------------------------------------------------

// DB Reutrn Data
type RvRequires2faType struct {
	StdErrorReturn
	Require2fa string `json:"require_2fa,omitempty"`
}

// Input for login
type ApiAuthRequires2fa struct {
	Email string `json:"email"      form:"email"       binding:"required,email"`
}

// Output returned
type Requires2faSuccess struct {
	Status     string `json:"status"`
	Require2fa string `json:"require_2fa,omitempty"`
}

// authHandleLogin will validate a user's username and password using the stored procedure `q_auth_v1_login` - if the user is
// validated then create a JWT token and send it back to the client as a secure cookie.   Send a "is-logged-in" regular
// cookie.
// func authHandleLogin(c *gin.Context, config interface{}) (err error) {

// {Method: "GET", Path: "/api/v1/auth/requires-2fa", Fx: authHandler2faRequired, UseLogin: PublicApiCall},                                      // reutrn y/n if 2fa is used  for htis account

// authHandleLogin godoc
// @Summary Login a user - Part 1 before 2FA
// @Schemes
// @Description Call checks a users email/password and returns informaiton on part 2 validation.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   email        formData    string     true        "Email Address"
// @Produce json
// @Success 200 {object} jwt_auth.Requires2faSuccess
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/login [post]
func authHandlerRequires2fa(c *gin.Context) {
	var err error
	var pp ApiAuthRequires2fa
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	pp.Email = cleanupEmail(pp.Email)

	perReqLog := tf.GetLogFilePtr(c)

	time.Sleep(5000 * time.Millisecond) // Slow down to prevent searching for valid email

	//                                   1                2                        3
	// FUNCTION q_auth_v1_requires_2fa ( p_email varchar, p_hmac_password varchar, p_userdata_password varchar )
	stmt := "q_auth_v1_requires_2fa ( $1, $2, $3 )"
	//                                                 1          2                        3
	rv, err := CallDatabaseJSONFunction(c, stmt, ".!!", pp.Email, aCfg.EncryptionPassword, aCfg.UserdataPassword)
	if err != nil {
		return
	}
	dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)

	var rvStatus RvRequires2faType
	err = json.Unmarshal([]byte(rv), &rvStatus)
	if rvStatus.Status != "success" {
		rvStatus.LogUUID = GenUUID()

		if logger != nil {
			fields := []zapcore.Field{
				zap.String("message", "Stored Procedure (q_auth_v1_requires_2fa) error return"),
				zap.String("go_location", dbgo.LF()),
			}
			fields = AppendStructToZapLog(fields, rvStatus)
			logger.Error("failed-to-failed-to-report-2fa-status", fields...)
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
		} else {
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
		}
		c.JSON(http.StatusUnauthorized, LogJsonReturned(perReqLog, rvStatus.StdErrorReturn)) // 401
		return
	}

	var out Requires2faSuccess
	copier.Copy(&out, &rvStatus)
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))
}

func RedisBrodcast(AuthToken string, data string) {
	/*
		From: wsender/wsender.go:253
		    var PubSubGeneralChannel = "ws:pub-sub-channel"

		   	type Message struct {
		   		Sender   string           `json:"sender,omitempty"` // auth_token for the sender
		   		To       string           `json:"to,omitempty"`
		   		Cmd      string           `json:"cmd,omitempty"`
		   		Msg      string           `json:"msg,omitempty"`
		   		Params   []xlib.NameValue `json:"params,omitempty"`
		   		LineFile string           `json:"line_file,omitempty"` // Line/File where message is from
		   		SvrName  string           `json:"origin,omitempty"`    // Server SvrName, so can check for echo
		   	}

		   	func (wsend *WsenderData) PublishToRedis(message Message) {
		   		dbgo.Printf("Publish to %s %s\n", PubSubGeneralChannel, dbgo.SVar(message))
		   		if err := wsend.rdb.Publish(wsend.ctx, PubSubGeneralChannel, dbgo.SVar(message)).Err(); err != nil {
		   			log.Println(err)
		   		}
		   	}
	*/
}

type ApiAuthTokenDeleteAdmin struct {
	Email     string `json:"email"         form:"email"       binding:"required,email"`
	AuthToken string `json:"auth_token"    form:"auth_token"  binding:"required"`
	DeleteAct string `json:"delete_act"    form:"delete_act"`
}

// {Method: "POST", Path: "/api/v1/auth/auth-token-delete-admin", Fx: authHandleAuthTokenDeleteAdmin, UseLogin: LoginRequired},       //
func authHandleAuthTokenDeleteAdmin(c *gin.Context) {
	var pp ApiAuthTokenDeleteAdmin
	if err := BindFormOrJSON(c, &pp); err != nil {
		md.AddCounter("jwt_auth_failed_login_attempts", 1)
		return
	}

	pp.Email = cleanupEmail(pp.Email)

	perReqLog := tf.GetLogFilePtr(c)

	if pp.DeleteAct == "auth_token" || pp.DeleteAct == "" {
		_, err := callme.CallAuthGetAllTokens(c, pp.AuthToken, pp.DeleteAct)
		if err != nil {
			c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, gin.H{ // 400
				"status": "error",
				"msg":    fmt.Sprintf("From Redis Error: %s", err),
			}))
			return
		}

		err = rdb.Del(ctx, fmt.Sprintf("auth_token:%s", pp.AuthToken)).Err()
		if err != nil {
			c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, gin.H{ // 400
				"status": "error",
				"msg":    fmt.Sprintf("From Redis Error: %s", err),
			}))
			return
		}

		return
	} else if pp.DeleteAct == "all" || pp.DeleteAct == "both" {
		rv, err := callme.CallAuthGetAllTokens(c, pp.AuthToken, pp.DeleteAct)
		if err != nil {
			c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, gin.H{ // 400
				"status": "error",
				"msg":    fmt.Sprintf("From Redis Error: %s", err),
			}))
			return
		}

		var tl []string
		err = json.Unmarshal([]byte(rv.TokenList), &tl)
		if err != nil {
			c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, gin.H{ // 400
				"status": "error",
				"msg":    fmt.Sprintf("From Redis Error: %s", err),
			}))
			return
		}

		for _, AnAuthToken := range tl {
			err := rdb.Del(ctx, fmt.Sprintf("auth_token:%s", AnAuthToken)).Err
			if err != nil {
				c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, gin.H{ // 400
					"status": "error",
					"msg":    fmt.Sprintf("From Redis Error: %s", err),
				}))
				return
			}
		}

		return
	} else {
		c.JSON(http.StatusNotAcceptable, LogJsonReturned(perReqLog, gin.H{ // 406
			"status": "error",
			"msg":    "Error: DeleteAct must be '', 'all, 'both', 'auth_token'",
		}))
		return
	}
}

/*
	user_id                |                                                                                                                                                                         privileges                                                                                                                                                                         | client_id |          email           |          expires           | seconds_till_expires

--------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+--------------------------+----------------------------+----------------------

	0ed721f8-2aed-42f2-8ad3-76bad390a4f4 | ["May AN", "AN Admin", "May Login", "Modify Role", "May Register", "AutoJob Admin", "May Call Test", "May Create Coupon", "AutoJob Client User", "AutoJob Client Admin", "May Accept AN at Price", "May Administrate Coupons", "May Change Other Password", "May Create Role Based User", "Admin: May Create Admin User", "May Create Registration Token"] |           | admin@write-it-right.com | 2024-01-27 18:19:18.290637 |           1706379559

(1 row)

	type SQLUserIdPrivsType struct {
		UserId     string `json:"user_id,omitempty"      db:"user_id"`
		Privileges string `json:"privileges,omitempty"`
		ClientId   string `json:"client_id,omitempty"    db:"client_id"`
		Email      string `json:"email"                  db:"email"`
					 //, min(t2.expires) as expires
					 //, ceil(EXTRACT(EPOCH FROM min(t2.expires))) as seconds_till_expires
		Expires string `json:"expires"`
		SecondsTillExpires int64 `json:"seconds_till_expires"`
	}
*/
// var rdb *redis.Client

// func RedisCacheAuthTokens(AuthToken, UserdataPassword string, v2 []*SQLUserIdPrivsType, perReqLog *os.File) {
func RedisCacheAuthTokens(AuthToken, UserdataPassword string, v2 []*SQLUserIdPrivsType, perReqLog io.WriteCloser) {
	if len(v2) <= 0 {
		return
	}
	vX := v2[0]

	// SHOULD BE:  NEW.expires := current_timestamp + interval '31 days';
	// dbgo.Fprintf(perReqLog, "%(red)-------------------------------------------------------------------------------------------------------\n")
	// dbgo.Fprintf(perReqLog, "%(yellow)-------------------------------------------------------------------------------------------------------\n")
	dbgo.Fprintf(perReqLog, "%(green)-------------------------------------------------------------------------------------------------------\n")
	dbgo.Fprintf(perReqLog, "Redis Cache of ->%s<- for %d seconds: %s ---- %v, should be: %v seconds 86400*31\n", AuthToken, vX.SecondsTillExpires, dbgo.SVar(vX), time.Duration(int64(vX.SecondsTillExpires)*int64(time.Second)), 86400*31)
	dbgo.Fprintf(perReqLog, "%(green)-------------------------------------------------------------------------------------------------------\n")
	// dbgo.Fprintf(perReqLog, "%(yellow)-------------------------------------------------------------------------------------------------------\n")
	// dbgo.Fprintf(perReqLog, "%(red)-------------------------------------------------------------------------------------------------------\n")

	// time.Duration(timeout * float64(time.Second))

	// Set in redis with key 'auth_token:UUID` and expires of vX.SecondsTillExpires
	rdb.Set(ctx, fmt.Sprintf("auth_token:%s", AuthToken), dbgo.SVar(vX), time.Duration(int64(vX.SecondsTillExpires)*int64(time.Second)))
}

// func RedisGetCachedToken(AuthToken, UserdataPassword string, perReqLog *os.File) (v2 []*SQLUserIdPrivsType, has bool) {
func RedisGetCachedToken(AuthToken, UserdataPassword string, perReqLog io.WriteCloser) (v2 []*SQLUserIdPrivsType, has bool) {
	has = false

	// get from redis, if found then "has" set to true.
	val, err := rdb.Get(ctx, fmt.Sprintf("auth_token:%s", AuthToken)).Result()
	if err != nil || val == "" {
		return
	}

	// parse the data
	var vX SQLUserIdPrivsType
	err = json.Unmarshal([]byte(val), &vX)
	if err != nil {
		return
	}
	v2 = make([]*SQLUserIdPrivsType, 1, 1)
	has = true
	v2[0] = &vX
	return
}

// -------------------------------------------------------------------------------------------------------------------------

// DB Reutrn Data
type RvUpdateAcctStateType struct {
	StdErrorReturn
	AcctState string `json:"acct_state,omitempty"`
}

// Input for login
type ApiUpdateAcctState struct {
	Email     string `json:"email"         form:"email"       binding:"required,email"`
	AcctState string `json:"acct_state"    form:"acct_state"       binding:"required"`
}

// Output returned
type UpdateAcctStateSuccess struct {
	Status    string `json:"status"`
	AcctState string `json:"acct_state"`
}

// authHandlerUpdateAcctState updates the acct_state field in the q_qr_auth_users table for the current user.
// After registraion it is reg0 or reg1.  This is repoted to the front end.

// {Method: "POST", Path: "/api/v1/auth/update-acct-state", Fx: authHandlerUpdateAcctState, UseLogin: PublicApiCall},                                      // reutrn y/n if 2fa is used  for htis account

// authHandleUpdateAcctState godoc
// @Summary update the acct_stae field in the q_qr_auth_users table.
// @Schemes
// @Description Update the acct_state field in the q_qr_users_table.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   email           formData    string     true        "Email Address"
// @Param   acct_state      formData    string     true        "Account State"
// @Produce json
// @Success 200 {object} jwt_auth.UpdateAcctStateSuccess
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/update-acct-state [post]
func authHandlerUpdateAcctState(c *gin.Context) {
	var err error
	var pp ApiUpdateAcctState
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	pp.Email = cleanupEmail(pp.Email)

	perReqLog := tf.GetLogFilePtr(c)

	//                                        1                2                     3                        4
	// FUNCTION q_auth_v1_update_acct_state ( p_email varchar, p_acct_state varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
	stmt := "q_auth_v1_update_acct_state ( $1, $2, $3, $4 )"
	//                                                 1          2             3                        4
	rv, err := CallDatabaseJSONFunction(c, stmt, "..!!", pp.Email, pp.AcctState, aCfg.EncryptionPassword, aCfg.UserdataPassword)
	if err != nil {
		return
	}
	dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)

	var rvStatus RvUpdateAcctStateType
	err = json.Unmarshal([]byte(rv), &rvStatus)
	if rvStatus.Status != "success" {
		rvStatus.LogUUID = GenUUID()

		if logger != nil {
			fields := []zapcore.Field{
				zap.String("message", "Stored Procedure (q_auth_v1_update_acct_state) error return"),
				zap.String("go_location", dbgo.LF()),
			}
			fields = AppendStructToZapLog(fields, rvStatus)
			logger.Error("failed-to-failed-to-report-2fa-status", fields...)
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
		} else {
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
		}
		c.JSON(http.StatusUnauthorized, LogJsonReturned(perReqLog, rvStatus.StdErrorReturn)) // 401
		return
	}

	var out UpdateAcctStateSuccess
	copier.Copy(&out, &rvStatus)
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))
}

// Input for login
type ApiGetAcctState struct {
	Email string `json:"email"         form:"email"       binding:"required,email"`
}

// authHandlerGetAcctState gets the acct_state field in the q_qr_auth_users table for the current user.
// After registraion it is reg0 or reg1.  This is repoted to the front end.

// {Method: "POST", Path: "/api/v1/auth/get-acct-state", Fx: authHandlerGetAcctState, UseLogin: PublicApiCall},                                      // reutrn y/n if 2fa is used  for htis account

// authHandlerGetAcctState godoc
// @Summary get the acct_stae field in the q_qr_auth_users table.
// @Schemes
// @Description Get the acct_state field in the q_qr_users_table.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   email           formData    string     true        "Email Address"
// @Param   acct_state      formData    string     true        "Account State"
// @Produce json
// @Success 200 {object} jwt_auth.UpdateAcctStateSuccess
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/get-acct-state [post]
func authHandlerGetAcctState(c *gin.Context) {
	var err error
	var pp ApiGetAcctState
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	pp.Email = cleanupEmail(pp.Email)

	perReqLog := tf.GetLogFilePtr(c)

	//                                     1                2                        3
	// FUNCTION q_auth_v1_get_acct_state ( p_email varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
	stmt := "q_auth_v1_get_acct_state ( $1, $2, $3 )"
	//                                                 1          2                        3
	rv, err := CallDatabaseJSONFunction(c, stmt, ".!!", pp.Email, aCfg.EncryptionPassword, aCfg.UserdataPassword)
	if err != nil {
		return
	}
	dbgo.Fprintf(perReqLog, "%(LF): rv=%s\n", rv)

	var rvStatus RvUpdateAcctStateType
	err = json.Unmarshal([]byte(rv), &rvStatus)
	if rvStatus.Status != "success" {
		rvStatus.LogUUID = GenUUID()

		if logger != nil {
			fields := []zapcore.Field{
				zap.String("message", "Stored Procedure (q_auth_v1_update_acct_state) error return"),
				zap.String("go_location", dbgo.LF()),
			}
			fields = AppendStructToZapLog(fields, rvStatus)
			logger.Error("failed-to-failed-to-report-2fa-status", fields...)
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
		} else {
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
		}
		c.JSON(http.StatusUnauthorized, LogJsonReturned(perReqLog, rvStatus.StdErrorReturn)) // 401
		return
	}

	var out UpdateAcctStateSuccess
	copier.Copy(&out, &rvStatus)
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))
}

type ApiSetEmailRedirect struct {
	EmailFrom string `json:"email_from"      form:"email_from"     binding:"required,email"`
	EmailTo   string `json:"email_to"        form:"email_to"       binding:"required,email"`
	AuthKey   string `json:"auth_key"        form:"auth_key"       binding:"required"`
}

type SetEmailRedirectSuccess struct {
	Status string `json:"status"`
}

// authHandlerSetEmailRedirect godoc
// @Summary get the acct_stae field in the q_qr_auth_users table.
// @Schemes
// @Description Get the acct_state field in the q_qr_users_table.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   email_from         formData    string     true        "Email Address"
// @Param   email_to           formData    string     true        "Email Address"
// @Produce json
// @Success 200 {object} jwt_auth.UpdateAcctStateSuccess
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/set-email-remap [post]
func authHandlerSetEmailRedirect(c *gin.Context) {
	var pp ApiSetEmailRedirect
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	if !ValidateHmacAuthKey(c, pp.AuthKey) {
		return
	}

	pp.EmailFrom = cleanupEmail(pp.EmailFrom)
	pp.EmailTo = cleanupEmail(pp.EmailTo)

	perReqLog := tf.GetLogFilePtr(c)

	if gCfg.RedirectEmailSendTo == nil {
		gCfg.RedirectEmailSendTo = make(map[string]string)
	}

	gCfg.RedirectEmailSendTo[pp.EmailFrom] = pp.EmailTo

	dbgo.Fprintf(perReqLog, "Email Remap is now %s\n", dbgo.SVarI(gCfg.RedirectEmailSendTo))

	out := SetEmailRedirectSuccess{
		Status: "success",
	}
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))
}

type ApiHasPriv struct {
	ForEmail string `json:"for_email"   form:"for_email"  binding:"required,email"`
	Priv     string `json:"priv"        form:"priv"       binding:"required"`
}

type HasPrivSuccess struct {
	Status     string `json:"status"`
	PrivNeeded string `json:"priv_needed,omitempty"`
	Msg        string `json:"msg"`
}

// {Method: "GET", Path: "/api/v1/auth/has-priv", Fx: authHandlerHasPriv, UseLogin: LoginRequired},                                   //

// authHandlerHasPriv godoc
// @Summary check if an an account has a privilage
// @Schemes
// @Description Return status success if the account has the privilage
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   for_email      formData    string     true        "For Email Address"
// @Param   priv           formData    string     true        "Priv to check"
// @Produce json
// @Success 200 {object} jwt_auth.UpdateAcctStateSuccess
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/has-priv [get]
func authHandlerHasPriv(c *gin.Context) {
	var pp ApiHasPriv
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	perReqLog := tf.GetLogFilePtr(c)

	pp.ForEmail = cleanupEmail(pp.ForEmail)

	// func CallQQrAdminHasPrivEmail(c *gin.Context, email string, privNeeded string) (rv RvQQrAdminHasPrivEmail, err error) {
	rv, err := callme.CallQQrAdminHasPrivEmail(c, pp.ForEmail, pp.Priv)

	if err != nil {
		c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, gin.H{ // 400
			"status": "error",
			"msg":    fmt.Sprintf("Error: %s", err),
		}))
		return
	}

	var out HasPrivSuccess
	copier.Copy(&out, &rv)
	out.Status = rv.Status
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))

}

type ApiListPriv struct {
	ForEmail string `json:"for_email"   form:"for_email"  binding:"required,email"`
}

type ListPrivSuccess struct {
	Status     string   `json:"status"`
	UserId     string   `json:"user_id,omitempty"`
	Privileges []string `json:"privileges,omitempty"`
	RoleName   string   `json:"role_name,omitempty"`
}

// # {Method: "POST", Path: "/api/v1/auth/list-priv", Fx: authHandlerListPriv, UseLogin: LoginRequired},                                 //

// authHandlerListPriv godoc
// @Summary list the privilages that an account has
// @Schemes
// @Description Return status success if the account has the privilage
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   for_email      formData    string     true        "For Email Address"
// @Param   priv           formData    string     true        "Priv to check"
// @Produce json
// @Success 200 {object} jwt_auth.UpdateAcctStateSuccess
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/has-priv [get]
func authHandlerListPriv(c *gin.Context) {
	var pp ApiListPriv
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	perReqLog := tf.GetLogFilePtr(c)

	pp.ForEmail = cleanupEmail(pp.ForEmail)

	// xyzzyPriv
	/*
	   type RvQQrAdminListPriv struct {
	   	StdErrorReturn
	   	UserId     string   `json:"user_id,omitempty"`
	   	Privileges []string `json:"privileges,omitempty"`
	   	RoleName   string   `json:"role_name,omitempty"`
	   }
	*/
	// func CallQQrAdminListPriv(c *gin.Context, email string) (rv RvQQrAdminListPriv, err error) {
	rv, err := callme.CallQQrAdminListPriv(c, pp.ForEmail)

	if err != nil {
		c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, gin.H{ // 400
			"status": "error",
			"msg":    fmt.Sprintf("Error: %s", err),
		}))
		return
	}

	var out ListPrivSuccess
	copier.Copy(&out, &rv)
	out.Status = rv.Status
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))

}

type ApiAddPrivTo struct {
	ForEmail string `json:"for_email"   form:"for_email"  binding:"required,email"`
	Priv     string `json:"priv"        form:"priv"       binding:"required"`
}

type AddPrivToSuccess struct {
	Status string `json:"status"`
}

// {Method: "POST", Path: "/api/v1/auth/add-priv-to", Fx: authHandlerAddPrivTo, UseLogin: LoginRequired},                //

// authHandlerAddPrivTo godoc
// @Summary give an account a privilage
// @Schemes
// @Description Return status success if you can give the account the specified privilage
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   for_email      formData    string     true        "For Email Address"
// @Param   priv           formData    string     true        "Priv to check"
// @Produce json
// @Success 200 {object} jwt_auth.UpdateAcctStateSuccess
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/has-priv [post]
func authHandlerAddPrivTo(c *gin.Context) {
	var pp ApiAddPrivTo
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	perReqLog := tf.GetLogFilePtr(c)

	UserId, _, AuthToken := GetAuthToken(c)
	if AuthToken == "" {
		out := StdErrorReturn{
			Status:   "error",
			Msg:      "401 not authorized",
			Location: dbgo.LF(),
		}
		c.JSON(http.StatusUnauthorized, LogJsonReturned(perReqLog, out))
	}

	pp.ForEmail = cleanupEmail(pp.ForEmail)

	// func CallAuthAddPrivlageToEmail(c *gin.Context, userId string, email string, privNeeded string) (rv RvAuthAddPrivlageToEmail, err error) {
	rv, err := callme.CallAuthAddPrivlageToEmail(c, UserId, pp.ForEmail, pp.Priv)

	if err != nil {
		c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, gin.H{ // 400
			"status": "error",
			"msg":    fmt.Sprintf("Error: %s", err),
		}))
		return
	}

	var out AddPrivToSuccess
	out.Status = rv.Status
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))

}

/*
	--post-data "{
		\"for_email\": \"${FOR_EMAIL}\",
		\"priv\": \"${PRIV}\"
	}" \

"${server}/api/v1/auth/rm-priv-from"

select '{"a": 1, "b": 2}'::jsonb - 'a';
*/
func authHandlerRmPrivFrom(c *gin.Context) {
	var pp ApiAddPrivTo
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	perReqLog := tf.GetLogFilePtr(c)

	UserId, _, AuthToken := GetAuthToken(c)
	if AuthToken == "" {
		out := StdErrorReturn{
			Status:   "error",
			Msg:      "401 not authorized",
			Location: dbgo.LF(),
		}
		c.JSON(http.StatusUnauthorized, LogJsonReturned(perReqLog, out))
	}

	pp.ForEmail = cleanupEmail(pp.ForEmail)

	// FUNCTION q_auth_v1_rm_privlage_from_email ( p_user_id uuid, p_email varchar, p_priv_needed varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
	rv, err := callme.CallAuthRmPrivlageFromEmail(c, UserId, pp.ForEmail, pp.Priv)
	if err != nil {
		c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, gin.H{ // 400
			"status": "error",
			"msg":    fmt.Sprintf("Error: %s", err),
		}))
		return
	}

	var out AddPrivToSuccess
	out.Status = rv.Status
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))

}

/* vim: set noai ts=4 sw=4: */
