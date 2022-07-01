package jwt_auth

// Copyright (c) Philip Schlump, 2016-2018.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

//xyzzy-00000-remove-old-code

// xyzzy443 - send email about this
//		- get sendgrid account updated
//		- validate actual email
//		- put in each email

// xyzzy441 - do we have test for every call

// xyzzy448 - test for un/pw and token registration of acocunt, test of login, test of parent account deleted.

// xyzzy8888 -------------------------- TODO - add/remove 2fa secret

// xyzzy TODO ; switch jwt to : https://github.com/golang-jwt/jwt
//				https://pkg.go.dev/github.com/golang-jwt/jwt

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/jinzhu/copier"
	"github.com/pschlump/HashStrings"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/filelib"
	"github.com/pschlump/gintools/email"
	"github.com/pschlump/gintools/log_enc"
	"github.com/pschlump/gintools/qr_svr2"
	"github.com/pschlump/htotp"
	"github.com/pschlump/json"
	"github.com/pschlump/scany/pgxscan"
)

// jwt "github.com/dgrijalva/jwt-go"

type GinLoginType struct {
	Path     string
	Method   string
	Fx       func(c *gin.Context)
	UseLogin int // 0 required - or not found in table, 1 not required, 2 optional
}

const (
	LoginRequired = 1
	PublicApiCall = 0
	LoginOptional = 2
)

var GinSetupTable = []GinLoginType{

	// No Login UseLogin
	{Method: "POST", Path: "/api/v1/auth/login", Fx: authHandleLogin, UseLogin: PublicApiCall},
	{Method: "POST", Path: "/api/v1/auth/register", Fx: authHandleRegister, UseLogin: PublicApiCall},                                             // un + pw + first_name + last_name
	{Method: "POST", Path: "/api/v1/auth/validate-2fa-token", Fx: authHandleValidate2faToken, UseLogin: PublicApiCall},                           // 2nd step 2fa - create auth-token / jwtToken Sent
	{Method: "POST", Path: "/api/v1/auth/email-confirm", Fx: authHandlerEmailConfirm, UseLogin: PublicApiCall},                                   // token
	{Method: "GET", Path: "/api/v1/auth/email-confirm", Fx: authHandlerEmailConfirm, UseLogin: PublicApiCall},                                    // token
	{Method: "POST", Path: "/api/v1/auth/recover-password-01-setup", Fx: authHandleRecoverPassword01Setup, UseLogin: PublicApiCall},              //
	{Method: "GET", Path: "/api/v1/auth/recover-password-01-setup", Fx: authHandleRecoverPassword01Setup, UseLogin: PublicApiCall},               //
	{Method: "POST", Path: "/api/v1/auth/recover-password-02-fetch-info", Fx: authHandleRecoverPassword02FetchInfo, UseLogin: PublicApiCall},     //
	{Method: "GET", Path: "/api/v1/auth/recover-password-02-fetch-info", Fx: authHandleRecoverPassword02FetchInfo, UseLogin: PublicApiCall},      //
	{Method: "POST", Path: "/api/v1/auth/recover-password-03-set-password", Fx: authHandleRecoverPassword03SetPassword, UseLogin: PublicApiCall}, //
	{Method: "GET", Path: "/api/v1/auth/recover-password-03-set-password", Fx: authHandleRecoverPassword03SetPassword, UseLogin: PublicApiCall},  //
	{Method: "GET", Path: "/api/v1/auth/no-login-status", Fx: authHandleNoLoginStatus, UseLogin: PublicApiCall},                                  //
	{Method: "POST", Path: "/api/v1/auth/no-login-status", Fx: authHandleNoLoginStatus, UseLogin: PublicApiCall},                                 //
	{Method: "GET", Path: "/api/v1/auth/2fa-has-been-setup", Fx: authHandle2faHasBeenSetup, UseLogin: PublicApiCall},                             //
	{Method: "GET", Path: "/api/v1/auth/email-has-been-validated", Fx: authHandleEmailHasBeenSetup, UseLogin: PublicApiCall},                     //
	{Method: "GET", Path: "/api/v1/auth/acct-status", Fx: authHandleAcctHasBeenSetup, UseLogin: PublicApiCall},                                   //
	{Method: "GET", Path: "/api/v1/id.json", Fx: loginTrackingJsonHandler, UseLogin: PublicApiCall},                                              //
	{Method: "GET", Path: "/api/v1/set-debug-flag", Fx: authHandlerSetDebugFlag, UseLogin: PublicApiCall},                                        //

	{Method: "GET", Path: "/api/v1/auth/logout", Fx: authHandleLogout, UseLogin: LoginOptional},  // just logout - destroy auth-token
	{Method: "POST", Path: "/api/v1/auth/logout", Fx: authHandleLogout, UseLogin: LoginOptional}, // just logout - destroy auth-token

	// Login UseLogin
	{Method: "POST", Path: "/api/v1/auth/login-status", Fx: authHandleLoginStatus, UseLogin: LoginRequired},                  //	Test of Login UseLogin Stuff
	{Method: "GET", Path: "/api/v1/auth/login-status", Fx: authHandleLoginStatus, UseLogin: LoginRequired},                   //	Test of Login UseLogin Stuff
	{Method: "POST", Path: "/api/v1/auth/refresh-token", Fx: authHandleAcctHasBeenSetup, UseLogin: LoginRequired},            // (TODO - wrong function now)
	{Method: "POST", Path: "/api/v1/auth/change-password", Fx: authHandleChangePassword, UseLogin: LoginRequired},            // change passwword
	{Method: "POST", Path: "/api/v1/auth/delete-acct", Fx: authHandleDeleteAccount, UseLogin: LoginRequired},                 // self-terminate account
	{Method: "POST", Path: "/api/v1/auth/regen-otp", Fx: authHandleRegenOTP, UseLogin: LoginRequired},                        // regenerate list of OTP list
	{Method: "POST", Path: "/api/v1/auth/register-un-pw", Fx: authHandleRegisterUnPw, UseLogin: LoginRequired},               //
	{Method: "POST", Path: "/api/v1/auth/register-token", Fx: authHandleRegisterToken, UseLogin: LoginRequired},              //
	{Method: "POST", Path: "/api/v1/auth/change-email-address", Fx: authHandleChangeEmailAddress, UseLogin: LoginRequired},   //
	{Method: "POST", Path: "/api/v1/auth/change-account-info", Fx: authHandleChangeAccountInfo, UseLogin: LoginRequired},     //
	{Method: "POST", Path: "/api/v1/auth/change-password-admin", Fx: authHandleChangePasswordAdmin, UseLogin: LoginRequired}, //
	{Method: "POST", Path: "/api/v1/auth/add-2fa-secret", Fx: authHandleAdd2faSecret, UseLogin: LoginRequired},               //
	{Method: "POST", Path: "/api/v1/auth/remove-2fa-secret", Fx: authHandleRemove2faSecret, UseLogin: LoginRequired},         //
}

// -------------------------------------------------------------------------------------------------------------------------
func AppendToSecurityTable(x ...GinLoginType) {
	GinSetupTable = append(GinSetupTable, x...)
}

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
				dbgo.Fprintf(os.Stderr, "Invalid %s [pos %d in table] method in setup at %(LF) -- fatal internal error\n", vv.Method, ii)
				os.Exit(1)
			}
		}
	}
}

// -------------------------------------------------------------------------------------------------------------------------
/*
create table q_qr_users (
	user_id 				serial not null primary key,
	email_hmac 				text not null,
	email_enc 				text,		-- todo - add this in with encrypted/decryptable email address
	password_hash 			text not null,
	first_name_enc			bytea not null,
	last_name_enc			bytea not null,
	email_verified			varchar(1) default 'n' not null,
	email_verify_token		uuid,
	email_verify_expire 	timestamp,
	password_reset_token	uuid,
	password_reset_time		timestamp,
	failed_login_timeout 	timestamp,
	login_failures 			int default 0 not null,
	parent_user_id 			int,
	account_type			varchar(20) default 'login' not null check ( account_type in ( 'login', 'un/pw', 'token', 'other' ) ),
	require_2fa 			varchar(1) default 'y' not null,
	secret_2fa 				varchar(20),
	setup_complete_2fa 		varchar(1) default 'n' not null,
	start_date				timestamp default current_timestamp not null,
	end_date				timestamp,
	updated 				timestamp, 									 						-- Project update timestamp (YYYYMMDDHHMMSS timestamp).
	created 				timestamp default current_timestamp not null 						-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);
*/

// @BasePath /api
// @title jwt auth code

type JwtClaims struct {
	AuthToken string `json:"auth_token"`
	jwt.StandardClaims
}

type StdErrorReturn struct {
	Status   string `json:"status"`
	Msg      string `json:",omitempty"`
	Code     string `json:",omitempty"`
	Location string `json:",omitempty"`
	LogUUID  string `json:",omitempty"`
}

// -------------------------------------------------------------------------------------------------------------------------

type RvLoginType struct {
	StdErrorReturn
	UserId      *int   `json:"user_id,omitempty"`
	AuthToken   string `json:"auth_token,omitempty"` // May be "" - meaning no auth.
	TmpToken    string `json:"tmp_token,omitempty"`  // May be "" - used in 2fa part 1 / 2
	Token       string `json:"token,omitempty"`      // the JWT Token???
	Require2fa  string `json:"require_2fa,omitempty"`
	Secret2fa   string `json:"secret_2fa,omitempty"`
	AccountType string `json:"account_type,omitempty"`
	Privileges  string `json:"privileges,omitempty"`
	FirstName   string `json:"first_name,omitempty"`
	LastName    string `json:"last_name,omitempty"`
}

// Input for login
type ApiAuthLogin struct {
	Email    string `json:"email"      form:"email"       binding:"required,email"`
	Pw       string `json:"password"   form:"password"    binding:"required"`
	AmIKnown string `json:"am_i_known" form:"am_i_known"`
}

// Output - returned on success
// copier.Copy(&employee, &user)
type LoginSuccess struct {
	Status     string `json:"status"`
	TmpToken   string `json:"tmp_token,omitempty"` // May be "" - used in 2fa part 1 / 2
	Token      string `json:"token,omitempty"`     // the JWT Token???
	Require2fa string `json:"require_2fa,omitempty"`
	Privileges string `json:"privileges,omitempty"`
	FirstName  string `json:"first_name,omitempty"`
	LastName   string `json:"last_name,omitempty"`
	// Not returned
	//	UserId      *int   `json:"user_id,omitempty"`
	//	AuthToken   string `json:"auth_token,omitempty"` // May be "" - meaning no auth.
	//	Secret2fa   string `json:"secret_2fa,omitempty"`
	//	AccountType string `json:"account_type,omitempty"`
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
// @Param   am_i_known   formData    string     false        "Id from id.json if available"
// @Produce json
// @Success 200 {object} jwt_auth.LoginSuccess
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /v1/auth/login [post]
func authHandleLogin(c *gin.Context) {
	var err error
	var pp ApiAuthLogin
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	// xyzzy4000 - check for the etag/hash pair - if found - then no 2fa required.

	// create or replace function q_auth_v1_login ( p_un varchar, p_pw varchar, p_am_i_knwon varchar, p_hmac_password varchar, p_userdata_password varchar )
	stmt := "q_auth_v1_login ( $1, $2, $3, $4, $5 )"
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF): %s\n", stmt)
	rv, err := CallDatabaseJSONFunction(c, stmt, "ee.!!", pp.Email, pp.Pw, pp.AmIKnown, gCfg.EncryptionPassword, gCfg.UserdataPassword)
	if err != nil {
		return
	}
	dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)

	var rvStatus RvLoginType
	err = json.Unmarshal([]byte(rv), &rvStatus)
	if rvStatus.Status != "success" {
		rvStatus.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
		c.JSON(http.StatusUnauthorized, logJsonReturned(rvStatus.StdErrorReturn)) // 401
		return
	}

	// xyzzy1212-  TokenHeaderVSCookie string `json:"token_header_vs_cookie" default:"cookie"`
	if rvStatus.AuthToken != "" {
		theJwtToken := CreateJWTSignedCookie(c, rvStatus.AuthToken)
		dbgo.Fprintf(logFilePtr, "%(green)!! Creating COOKIE Token, Logged In !!  at:%(LF): AuthToken=%s jwtCookieToken=%s\n", rvStatus.AuthToken, theJwtToken)

		c.Set("__is_logged_in__", "y")
		c.Set("__user_id__", fmt.Sprintf("%d", rvStatus.UserId))
		c.Set("__auth_token__", rvStatus.AuthToken)
		rv, mr := ConvPrivs2(rvStatus.Privileges)
		c.Set("__privs__", rv)
		c.Set("__privs_map__", mr)
		c.Set("__email_hmac_password__", gCfg.EncryptionPassword)
		c.Set("__user_password__", gCfg.UserdataPassword)

		if theJwtToken != "" {
			// "Progressive improvement beats delayed perfection" -- Mark Twain
			if gCfg.TokenHeaderVSCookie == "cookie" {
				rvStatus.Token = ""
				c.Set("__jwt_token__", "")
			} else { // header or both
				rvStatus.Token = theJwtToken
				c.Set("__jwt_token__", theJwtToken)
			}

		}
	}

	// xyzzy443 - TODO - send email if a login is from a new device. ??

	var out LoginSuccess
	copier.Copy(&out, &rvStatus)
	c.JSON(http.StatusOK, logJsonReturned(out))
}

// -------------------------------------------------------------------------------------------------------------------------

// Returned form stored procedure
//		l_data = '{"status":"error","msg":"Account already exists.  Please login or recover password.","code":"0007","location":"m4___file__ m4___line__"}';
//			||', "user_id":' ||coalesce(to_json(l_user_id)::text,'""')
type RvRegisterType struct {
	StdErrorReturn
	UserId           *int     `json:"user_id,omitempty"`
	EmailVerifyToken string   `json:"email_verify_token,omitempty"`
	Require2fa       string   `json:"require_2fa,omitempty"`
	Secret2fa        string   `json:"secret_2,omitempty"`
	URLFor2faQR      string   `json:"url_for_2fa_qr"`
	TotpSecret       string   `json:"totp_secret"`
	Otp              []string `json:"otp"`
	TmpToken         string   `json:"tmp_token,omitempty"` // May be "" - used in 2fa part 1 / 2
}

// Input for api endpoint
type ApiAuthRegister struct {
	Email     string `json:"email"      form:"email"       binding:"required,email"`
	FirstName string `json:"first_name" form:"first_name"  binding:"required"`
	LastName  string `json:"last_name"  form:"last_name"   binding:"required"`
	Pw        string `json:"password"   form:"password"          binding:"required"`
}

type RegisterSuccess struct {
	Status      string   `json:"status"`
	URLFor2faQR string   `json:"url_for_2fa_qr"`
	TotpSecret  string   `json:"totp_secret"`
	Otp         []string `json:"otp"`
	TmpToken    string   `json:"tmp_token,omitempty"` // May be "" - used in 2fa part 1 / 2
}

// authHandleRegister godoc
// @Summary Register a new user - Part 1 before 2FA pin and email validation.  Part 2 and 3 are the email conformation and the use of the 6 digit 2fa pin.
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
// @Router /v1/auth/register [post]
func authHandleRegister(c *gin.Context) {
	var err error
	var pp ApiAuthRegister
	var RegisterResp RvRegisterType
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	if IsXDBOn("authHandleRegister:error01") {
		RegisterResp.LogUUID = GenUUID()
		RegisterResp.Status = "error"
		RegisterResp.Msg = "Simulated Error"
		RegisterResp.Code = "0000"
		RegisterResp.Location = dbgo.LF()
		c.JSON(http.StatusBadRequest, logJsonReturned(RegisterResp.StdErrorReturn))
		return
	}

	secret := GenerateSecret()

	//                                                 1             2             3                        4                     5                    6                            7
	// create or replace function q_auth_v1_register ( p_un varchar, p_pw varchar, p_hmac_password varchar, p_first_name varchar, p_last_name varchar, p_userdata_password varchar, p_secret varchar )
	stmt := "q_auth_v1_register ( $1, $2, $3, $4, $5, $6, $7 )"
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF): %s\n", stmt)
	//                                                      1         2      3                        4             5            6                      7
	rv, err := CallDatabaseJSONFunction(c, stmt, "ee.ee..", pp.Email, pp.Pw, gCfg.EncryptionPassword, pp.FirstName, pp.LastName, gCfg.UserdataPassword, secret)
	if err != nil {
		return
	}
	dbgo.Fprintf(logFilePtr, "%(yellow)%(LF): rv=%s\n", rv)
	err = json.Unmarshal([]byte(rv), &RegisterResp)
	if RegisterResp.Status != "success" {
		RegisterResp.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "ee!ee!!", SVar(RegisterResp), pp.Email, pp.Pw /*gCfg.EncryptionPassword,*/, pp.FirstName, pp.LastName /*, gCfg.UserdataPassword*/, secret)
		c.JSON(http.StatusBadRequest, logJsonReturned(RegisterResp.StdErrorReturn))
		return
	}

	// set Cookie for SavedState -- Save into database
	cookieValue := GenUUID()
	SetCookie("X-Saved-State", cookieValue, c)
	err = SaveState(cookieValue, *RegisterResp.UserId, c)
	if err != nil {
		return
	}

	// ---------------------------------------------------------------------------------------------------------------------
	// send email with validation - using: RegisterResp.EmailVerifyToken
	// ---------------------------------------------------------------------------------------------------------------------
	// ConfirmEmailAccount(c, RegisterResp.EmailVerifyToken)

	email.SendEmail(
		"welcome_registration", // Email Template
		"username", pp.Email,
		"email", pp.Email,
		"first_name", pp.FirstName,
		"last_name", pp.LastName,
		"real_name", pp.FirstName+" "+pp.LastName,
		"token", RegisterResp.EmailVerifyToken,
		"user_id", RegisterResp.UserId,
		"server", gCfg.BaseServerUrl,
		"application_name", gCfg.AuthApplicationName,
		"realm", gCfg.AuthRealm,
	)

	// ---------------------------------------------------------------------------------------------------------------------
	// setup the QR code and link for 2fa tool
	// ---------------------------------------------------------------------------------------------------------------------
	// Confirm2faSetupAccount(c, *RegisterResp.UserId)

	RegisterResp.TotpSecret = secret                                     // 	if htotp.CheckRfc6238TOTPKeyWithSkew(username, pin2fa, RegisterResp.Secret2fa, 0, 1) {
	totp := htotp.NewDefaultTOTP(secret)                                 // totp := htotp.NewDefaultTOTP(RegisterResp.Secret2fa)
	QRUrl := totp.ProvisioningUri(pp.Email /*username*/, gCfg.AuthRealm) // otpauth://totp/issuerName:demoAccountName?secret=4S62BZNFXXSZLCRO&issuer=issuerName
	RegisterResp.URLFor2faQR = MintQRPng(c, QRUrl)

	var out RegisterSuccess
	copier.Copy(&out, &RegisterResp)
	c.JSON(http.StatusOK, logJsonReturned(out))
}

// -------------------------------------------------------------------------------------------------------------------------
func MintQRPng(c *gin.Context, InputString string) (qrurl string) {

	dbgo.Fprintf(logFilePtr, "at:%(LF)\n")
	qrid := GenUUID() // generate ID
	qrid10 := qrid[0:8] + qrid[9:11]

	redundancy := qr_svr2.Highest

	baseurl := gCfg.QrBaseServerURL
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
		"qr2":             qrid[0:2],              // xyzzy - pull off first 2 chars of qrid
		"qrid10":          qrid[0:8] + qrid[9:11], // xyzzy - pull off first 8 chars of qrid
		"slash_if_needed": sin,
	}

	fn := filelib.Qt(gCfg.QrFilePath, mdata)
	mdata["fn"] = fn
	mdata["qrfn"] = fn
	pth := filepath.Dir(fn)
	mdata["pth"] = pth
	basefn := filepath.Base(fn)
	mdata["basefn"] = basefn
	qrurl = filelib.Qt("%{baseurl%}%{slash_if_needed%}qr/%{qr2%}/%{basefn%}", mdata)
	mdata["qrurl"] = filelib.Qt(gCfg.QrURLPath, mdata)

	dbgo.Fprintf(logFilePtr, "%s - at:%(LF)\n", dbgo.SVarI(mdata))

	// create directory
	os.MkdirAll(pth, 0755)

	// open file
	fp, err := filelib.Fopen(fn, "w")
	if err != nil {
		log_enc.LogMiscError(c, err, "Unable to open file")
		return
	}
	defer fp.Close()

	dbgo.Fprintf(logFilePtr, "at:%(LF)\n")

	// Generate the QR code in internal format
	var q *qr_svr2.QRCode
	dbgo.DbFprintf("dump-qr-encode-string", logFilePtr, "%(Yellow)Encoding  ->%s<- intooo QR.png at:%(LF)\n", InputString)
	q, err = qr_svr2.New(InputString, redundancy)
	qr_svr2.CheckError(err)

	dbgo.Fprintf(logFilePtr, "at:%(LF)\n")

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

type RvEmailConfirm struct {
	StdErrorReturn
	TmpToken string `json:"tmp_token,omitempty"` // May be "" - used in 2fa part 1 / 2
}

type ApiAuthEmailValidate struct {
	EmailVerifyToken string `json:"email_verify_token" form:"email_verify_token"   binding:"required"`
}

type EmailConfirmSuccess struct {
	Status   string `json:"status"`
	TmpToken string `json:"tmp_token"`
}

// authHandlerEmailConfirm uses the token to lookup a user and confirms that the email that received the token is real.
// `redirect_to` is ignored at this point.
//
// From: router.POST("/api/v1/auth/email-confirm", authHandlerEmailConfirm)

// authHandleEmailConfirm godoc
// @Summary Confirm the email from registration.
// @Schemes
// @Description Call uses the provided token to confirm the users email.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   email     formData    string     true        "Email Address"
// @Param   pw        formData    string     true        "Password"
// @Param   again     formData    string     true        "Password Again"
// @Produce json
// @Success 200 {object} jwt_auth.EmailConfirmSuccess
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /v1/auth/email-confirm [post]
func authHandlerEmailConfirm(c *gin.Context) {
	var err error
	var pp ApiAuthEmailValidate
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	rv, stmt, err := ConfirmEmailAccount(c, pp.EmailVerifyToken)
	if err != nil {
		return
	}

	dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)
	var rvEmailConfirm RvEmailConfirm
	err = json.Unmarshal([]byte(rv), &rvEmailConfirm)
	if rvEmailConfirm.Status != "success" {
		rvEmailConfirm.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "e", SVar(rvEmailConfirm))
		c.JSON(http.StatusBadRequest, logJsonReturned(rvEmailConfirm.StdErrorReturn)) // 400
		return
	}

	var out EmailConfirmSuccess
	copier.Copy(&out, &rvEmailConfirm)
	c.JSON(http.StatusOK, logJsonReturned(out)) // 200

}

// -------------------------------------------------------------------------------------------------------------------------
// jwtConfig.authInternalHandlers["POST:/api/v1/auth/change-password"] = authHandleChangePassword                       // change passwword
type ApiAuthChangePassword struct {
	Email string `json:"email"  form:"email"   binding:"required,email"`
	NewPw string `json:"new_pw" form:"new_pw"  binding:"required"`
	OldPw string `json:"old_pw" form:"old_pw"  binding:"required"`
}

type ReturnSuccess struct {
	Status string `json:"status"`
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
// @Router /v1/auth/change-password [post]
func authHandleChangePassword(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF)\n")
	var pp ApiAuthChangePassword
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	if pp.NewPw == pp.OldPw {
		// xyzzy - should be a log call - with a log_enc.LogInputValidationError... call...
		c.JSON(http.StatusNotAcceptable, logJsonReturned(gin.H{ // 406
			"status": "error",
			"msg":    "Old and new password should be different",
		}))
		return
	}

	_, AuthToken := GetAuthToken(c)

	if AuthToken != "" { // if user is logged in then logout - else - just ignore.

		// create or replace function q_auth_v1_change_password ( p_un varchar, p_pw varchar, p_new_pw varchar, p_hmac_password varchar, p_userdata_password varchar )
		stmt := "q_auth_v1_change_password ( $1, $2, $3, $4, $5 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, "e....", pp.Email, pp.OldPw, pp.NewPw, gCfg.EncryptionPassword, gCfg.UserdataPassword)
		if e0 != nil {
			// err = e0
			return
		}

		dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)
		// var rvStatus RvStatusType
		var rvStatus StdErrorReturn
		err := json.Unmarshal([]byte(rv), &rvStatus)
		if err != nil || rvStatus.Status != "success" {
			rvStatus.LogUUID = GenUUID()
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))
			c.JSON(http.StatusBadRequest, logJsonReturned(rvStatus)) // 400
			return
		}

		// xyzzy443 - send email about change

		// email.SendEmail("password_updated", "username", un, "email", emailaddr, "real_name", real_name, "token", recovery_token, "realm", gCfg.AuthRealm, "server", gCfg.AuthSelfURL)
	}

	out := ReturnSuccess{Status: "success"}
	c.JSON(http.StatusOK, logJsonReturned(out)) // 200

}

// -------------------------------------------------------------------------------------------------------------------------
//	router.POST("/api/v1/auth/recover-password-01-setup", authHandleRecoverPassword01Setup)              //
//	router.GET("/api/v1/auth/recover-password-01-setup", authHandleRecoverPassword01Setup)               //

type RvRecoverPassword01Setup struct {
	StdErrorReturn
	RecoveryToken string `json:"recovery_token,omitempty"`
	FirstName     string `json:"first_name,omitempty"`
	LastName      string `json:"last_name,omitempty"`
}

type ApiEmail struct {
	Email string `json:"email"  form:"email"  binding:"required,email"`
}

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
// @Router /v1/auth/recover-password-01-setup [post]
func authHandleRecoverPassword01Setup(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF)\n")
	var pp ApiEmail
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	// create or replace function q_auth_v1_recover_password_01_setup ( p_un varchar, p_hmac_password varchar, p_userdata_password varchar )
	stmt := "q_auth_v1_recover_password_01_setup ( $1, $2, $3 )"
	rv, e0 := CallDatabaseJSONFunction(c, stmt, "e..", pp.Email, gCfg.EncryptionPassword, gCfg.UserdataPassword)
	if e0 != nil {
		return
	}

	dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)
	var rvStatus RvRecoverPassword01Setup
	err := json.Unmarshal([]byte(rv), &rvStatus)
	if err != nil || rvStatus.Status != "success" {
		rvStatus.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))                // xyzzy - encrypt xyzzy - Encrypted Log File Data
		c.JSON(http.StatusBadRequest, logJsonReturned(rvStatus.StdErrorReturn)) // 400
		return
	}

	email.SendEmail("recover_password",
		"username", pp.Email,
		"email", pp.Email,
		"token", rvStatus.RecoveryToken,
		"first_name", rvStatus.FirstName,
		"last_name", rvStatus.LastName,
		"application_name", gCfg.AuthApplicationName,
		"realm", gCfg.AuthRealm,
		"server", gCfg.BaseServerUrl,
	)

	out := ReturnSuccess{Status: "success"}
	c.JSON(http.StatusOK, logJsonReturned(out)) // 200

}

// -------------------------------------------------------------------------------------------------------------------------
// router.POST("/api/v1/auth/recover-password-02-fetch-info", authHandleRecoverPassword02FetchInfo)     //
// router.GET("/api/v1/auth/recover-password-02-fetch-info", authHandleRecoverPassword02FetchInfo)      //

type RvRecoverPassword02FetchInfo struct {
	StdErrorReturn
	Email     string `json:"email,omitempty"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
}

type ApiAuthRecoveryPassword02FetchInfo struct {
	Email         string `json:"email"          form:"email"            binding:"required,email"`
	RecoveryToken string `json:"recovery_token" form:"recovery_token"   binding:"required"`
}

type RecoverPassword02Success struct {
	Status    string `json:"status"`
	Email     string `json:"email,omitempty"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
}

// authHandleEmailConfirm godoc
// @Summary Return information to recovery form.
// @Schemes
// @Description Information is returned based on an Email and a Token to a recovery form.  The inforaiton if the token is valid is the name of the user.   xyzzy-TODO = return informaiton if the token has expired or if it is not valid.  The call has a built in sleep so that it is bandwidth limited.
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
// @Router /v1/auth/recover-password-02-fetch-info [post]
func authHandleRecoverPassword02FetchInfo(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF)\n")
	var pp ApiAuthRecoveryPassword02FetchInfo
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	// create or replace function q_auth_v1_recover_password_02_fetch_info ( p_un varchar, p_recovery_token varchar, p_hmac_password varchar, p_userdata_password varchar )
	stmt := "q_auth_v1_recover_password_02_fetch_info ( $1, $2, $3, $4 )"
	rv, e0 := CallDatabaseJSONFunction(c, stmt, "e!..", pp.Email, pp.RecoveryToken, gCfg.EncryptionPassword, gCfg.UserdataPassword)
	if e0 != nil {
		return
	}

	dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)
	var rvStatus RvRecoverPassword02FetchInfo
	err := json.Unmarshal([]byte(rv), &rvStatus)
	if err != nil || rvStatus.Status != "success" {
		rvStatus.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))                // xyzzy - Encrypted Log File Data
		c.JSON(http.StatusBadRequest, logJsonReturned(rvStatus.StdErrorReturn)) // 400
		return
	}

	var out RecoverPassword02Success
	copier.Copy(&out, &rvStatus)
	c.JSON(http.StatusOK, logJsonReturned(out)) // 200

}

// -------------------------------------------------------------------------------------------------------------------------
// router.POST("/api/v1/auth/recover-password-03-set-password", authHandleRecoverPassword03SetPassword) //
// router.GET("/api/v1/auth/recover-password-03-set-password", authHandleRecoverPassword03SetPassword)  //

type RvRecoverPassword03SetPassword struct {
	StdErrorReturn
	RecoveryToken string `json:"recovery_token,omitempty"`
	FirstName     string `json:"first_name,omitempty"`
	LastName      string `json:"last_name,omitempty"`
}

type ApiAuthRecoverPassword03SetPassword struct {
	Email         string `json:"email"          form:"email"           binding:"required,email"`
	NewPw         string `json:"new_pw"         form:"new_pw"          binding:"required"`
	RecoveryToken string `json:"recovery_token" form:"recovery_token"  binding:"required"`
}

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
// @Router /v1/auth/recover-password-03-set-password [post]
func authHandleRecoverPassword03SetPassword(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF)\n")
	var pp ApiAuthRecoverPassword03SetPassword
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	// create or replace function q_auth_v1_recover_password_03_set_password ( p_un varchar, p_new_pw varchar, p_recovery_token varchar, p_hmac_password varchar, p_userdata_password varchar )
	stmt := "q_auth_v1_recover_password_03_set_password ( $1, $2, $3, $4, $5 )"
	rv, e0 := CallDatabaseJSONFunction(c, stmt, "ee!..", pp.Email, pp.NewPw, pp.RecoveryToken, gCfg.EncryptionPassword, gCfg.UserdataPassword)
	if e0 != nil {
		return
	}

	dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)
	var rvStatus RvRecoverPassword03SetPassword
	err := json.Unmarshal([]byte(rv), &rvStatus)
	if err != nil || rvStatus.Status != "success" {
		rvStatus.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))                // xyzzy - Encrypted Log File Data
		c.JSON(http.StatusBadRequest, logJsonReturned(rvStatus.StdErrorReturn)) // 400
		return
	}

	email.SendEmail("password_updated",
		"username", pp.Email,
		"email", pp.Email,
		"first_name", rvStatus.FirstName,
		"last_name", rvStatus.LastName,
		"token", rvStatus.RecoveryToken,
		"realm", gCfg.AuthRealm,
		"server", gCfg.BaseServerUrl,
	)

	var out RecoverPassword03SetPasswordSuccess
	copier.Copy(&out, &rvStatus)
	c.JSON(http.StatusOK, logJsonReturned(out)) // 200

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
// @Router /v1/auth/logout [post]
func authHandleLogout(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF)\n")
	var AuthToken string
	var pp ApiEmailOptional
	if err := BindFormOrJSONOptional(c, &pp); err != nil {
		goto done
	}
	if pp.Email == "" {
		goto done
	}
	_, AuthToken = GetAuthToken(c)
	if AuthToken == "" {
		goto done
	}

	dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF)\n")

	if AuthToken != "" { // if user is logged in then logout - else - just ignore.
		dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF)\n")
		// create or replace function q_auth_v1_logout ( p_un varchar, p_auth_token varchar, p_hmac_password varchar )
		stmt := "q_auth_v1_logout ( $1, $2, $3 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, "e!.", pp.Email, AuthToken, gCfg.EncryptionPassword)
		if e0 != nil {
			dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF)\n")
			return
		}

		dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)
		// var rvStatus RvStatusType
		var rvStatus StdErrorReturn
		err := json.Unmarshal([]byte(rv), &rvStatus)
		if err != nil || rvStatus.Status != "success" {
			dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF)\n")
			rvStatus.LogUUID = GenUUID()
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus)) // xyzzy - Encrypted Log File Data
			c.JSON(http.StatusBadRequest, logJsonReturned(rvStatus)) // 400
			return
		}
		dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF)\n")
	}

done:

	dbgo.Fprintf(os.Stderr, "%(cyan)In Handler at %(LF) - Logout / not authenticated on server side\n")
	dbgo.Fprintf(logFilePtr, "# %(cyan)In Handler at %(LF) - Logout / not authenticated on server side\n")

	// Cookies Reset
	SetCookie("X-Authentication", "", c)         // Will be a secure http cookie on TLS.
	SetInsecureCookie("X-Is-Logged-In", "no", c) // To let the JS code know that it is logged in.

	out := ReturnSuccess{Status: "success"}
	c.JSON(http.StatusOK, logJsonReturned(out)) // 200

}

// -------------------------------------------------------------------------------------------------------------------------
// jwtConfig.authInternalHandlers["GET:/api/v1/auth/2fa-has-been-setup"] = authHandle2faHasBeenSetup

type X2faSetupSuccess struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
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
// @Router /v1/auth/2fa-has-been-setup [get]
func authHandle2faHasBeenSetup(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF)\n")
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
			where t1.email_hmac = encode(hmac($1, $2, 'sha256'), 'base64')
			  and t1.setup_complete_2fa = 'y'
	`
	err = pgxscan.Select(ctx, conn, &v2, stmt, pp.Email, gCfg.EncryptionPassword)
	if err != nil {
		log_enc.LogSQLError(c, stmt, err, "e!", pp.Email, gCfg.EncryptionPassword)
		return
	}

	out := X2faSetupSuccess{Status: "success"}
	c.JSON(http.StatusOK, logJsonReturned(out)) // 200
	if len(v2) > 0 {
		out.Msg = "2FA has been Setup"
	} else {
		out.Status = "error"
		out.Msg = "2FA *not* Setup"
	}
	c.JSON(http.StatusOK, logJsonReturned(out))

}

// -------------------------------------------------------------------------------------------------------------------------
// router.GET("/api/v1/auth/email-has-been-validated", authHandleEmailHasBeenSetup)                     //

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
// @Router /v1/auth/email-has-been-validated [get]
func authHandleEmailHasBeenSetup(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF)\n")
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
			where t1.email_hmac = encode(hmac($1, $2, 'sha256'), 'base64')
			  and t1.email_verified = 'y'
	`
	err = pgxscan.Select(ctx, conn, &v2, stmt, pp.Email, gCfg.EncryptionPassword)
	if err != nil {
		log_enc.LogSQLError(c, stmt, err, "e!", pp.Email, gCfg.EncryptionPassword)
		return
	}

	out := X2faSetupSuccess{Status: "success"}
	if len(v2) > 0 {
		out.Msg = "Email has been Setup"
	} else {
		out.Status = "error"
		out.Msg = "Email *not* Setup"
	}
	c.JSON(http.StatusOK, logJsonReturned(out))

}

// -------------------------------------------------------------------------------------------------------------------------
// router.GET("/api/v1/auth/acct-status", authHandleAcctHasBeenSetup)                                   // (new)

type SQLAcctStatusType struct {
	SetupComplete2fa string `json:"setup_complete_2fa" db:"setup_complete_2fa"`
	EmailVerified    string `json:"email_verified"     db:"email_verified"`
}

type AcctSetupSuccess struct {
	Status           string `json:"status"`
	SetupComplete2fa string `json:"setup_complete_2fa,omitempty"`
	EmailVerified    string `json:"email_verified,omitempty"`
	Msg              string `json:"msg,omitempty"`
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
// @Router /v1/auth/acct-status [get]
func authHandleAcctHasBeenSetup(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF)\n")
	var err error
	var pp ApiEmail
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	time.Sleep(500 * time.Millisecond)

	var v2 []*SQLAcctStatusType
	stmt := `
		select t1.setup_complete_2fa 
			  , t1.email_verified 
			from q_qr_users  as t1
			where t1.email_hmac = encode(hmac($1, $2, 'sha256'), 'base64')
	`
	err = pgxscan.Select(ctx, conn, &v2, stmt, pp.Email, gCfg.EncryptionPassword)
	if err != nil {
		log_enc.LogSQLError(c, stmt, err, "e!", pp.Email, gCfg.EncryptionPassword)
		return
	}
	if len(v2) > 0 {
		out := AcctSetupSuccess{Status: "success",
			SetupComplete2fa: v2[0].SetupComplete2fa,
			EmailVerified:    v2[0].EmailVerified,
		}
		c.JSON(http.StatusOK, logJsonReturned(out))
		return
	}
	out := AcctSetupSuccess{Status: "error", Msg: "User Not Found"}
	c.JSON(http.StatusOK, logJsonReturned(out))

}

// -------------------------------------------------------------------------------------------------------------------------
// router.GET("/api/v1/setDebugFlag", authHandlerSetDebugFlag)

type ApiAuthSetDebugFlag struct {
	Name    string `json:"name"          form:"name"           binding:"required"`
	Value   string `json:"value"         form:"value"          binding:"required"`
	AuthKey string `json:"auth_key"		 form:"auth_key"`
}

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
// @Router /v1/auth/set-debug-flag [get]
func authHandlerSetDebugFlag(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In set-debug-flag handler at %(LF)\n")

	var pp ApiAuthSetDebugFlag
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	if HashStrings.HashStrings(pp.AuthKey) != "d1925935f59354de774257bd02867eca749b617b21641f66aba49447f02ae377" {
		out := SetDebugFlagSuccess{Status: "error"}
		c.JSON(http.StatusUnauthorized, logJsonReturned(out)) // 401
		return
	}

	exi := ParseBool(pp.Value)
	XDbOnLock.Lock()
	XDbOn[pp.Name] = exi
	XDbOnLock.Unlock()

	out := SetDebugFlagSuccess{Status: "success"}
	c.JSON(http.StatusOK, logJsonReturned(out))
	return
}

// -------------------------------------------------------------------------------------------------------------------------
// router.POST("/api/v1/auth/validate-2fa-token", authHandleValidate2faToken)                           // 2nd step 2fa - create auth-token / jwtToken Sent

type RvValidate2faTokenType struct {
	StdErrorReturn
	UserId         *int   `json:"user_id,omitempty"`
	AuthToken      string `json:"auth_token,omitempty"` // May be "" - meaning no auth.
	Token          string `json:"token,omitempty"`
	Expires        string `json:"expires,omitempty"`
	Privileges     string `json:"privileges,omitempty"`
	Secret2fa      string `json:"secret_2fa,omitempty"`
	EmailValidated string `json:"email_validated,omitempty"`
}

type RvGetSecretType struct {
	StdErrorReturn
	Secret2fa string `json:"secret_2fa"`
	UserId    int    `json:"user_id"`
}

var PrivilegedNames = []string{"__is_logged_in__", "__user_id__", "__auth_token__", "__privs__", "__jwt_token__", "__email_hmac_password__", "__user_password__"}

// authHandleValidate2faToken is called after login to validate a 2fa token and after registration to comnplete the registration.
//
// This calls: "q_auth_v1_validate_2fa_token ( $1, $2, $3, $4 )" in the databse.
// This sets q_qr_users.setup_complete_2fa  = 'y' to mark the account as fully registered.
// Login requires that this is a 'y' before login occures.
//
type ApiAuthValidate2faToken struct {
	Email    string `json:"email"      form:"email"      binding:"required"`
	TmpToken string `json:"tmp_token"  form:"tmp_token"  binding:"required"`
	X2FaPin  string `json:"x2fa_pin"   form:"x2fa_pin"   binding:"required"`
	AmIKnown string `json:"am_i_known" form:"am_i_known"`
	// MarkerId string `json:"marker_id"  form:"marker_id"`
}

type Validate2faTokenSuccess struct {
	Status         string `json:"status"`
	Token          string `json:"token,omitempty"`
	EmailValidated string `json:"email_validated,omitempty"`
	Expires        string `json:"expires,omitempty"`
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
// @Router /v1/auth/validate-2fa-token [post]
func authHandleValidate2faToken(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF)\n")
	var pp ApiAuthValidate2faToken
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	stmt := "q_auth_v1_2fa_get_secret ( $1, $2 )"
	rv, e0 := CallDatabaseJSONFunction(c, stmt, "e.", pp.Email, gCfg.EncryptionPassword)
	if e0 != nil {
		return
	}

	dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)
	var rvSecret RvGetSecretType
	err := json.Unmarshal([]byte(rv), &rvSecret)
	if err != nil || rvSecret.Status != "success" {
		rvSecret.LogUUID = GenUUID()
		dbgo.Printf("%(red)%(LF) -- err:%s rvSecret=%s\n", err, dbgo.SVarI(rvSecret))
		log_enc.LogStoredProcError(c, stmt, "e.", SVar(rvSecret), fmt.Sprintf("%s", err)) // xyzzy - Encrypted Log File Data
		c.JSON(http.StatusBadRequest, logJsonReturned(rvSecret.StdErrorReturn))           // 400
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
				dbgo.Fprintf(logFilePtr, "		%(magenta)Secret[%d] = %(yellow)%s\n", ii, a_secret)
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

	// If the 2fa token fails to validate - then we are done.
	dbgo.Fprintf(logFilePtr, "\n\n%(LF)%(magenta)Secret = %(yellow)%s\n\n", rvSecret.Secret2fa)
	// if !htotp.CheckRfc6238TOTPKeyWithSkew(pp.Email /*username*/, pp.X2FaPin /*pin2fa*/, rvSecret.Secret2fa, 1, 2) {
	if !chkSecret(rvSecret.Secret2fa) {
		dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)
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

	// ----------------------------------------------------------------------------------------------
	// New
	// ----------------------------------------------------------------------------------------------
	// create or replace function q_auth_v1_etag_device_mark ( p_seen_id varchar, p_user_id varchar, p_hmac_password varchar, p_userdata_password varchar )
	if pp.AmIKnown != "" {
		stmt := "q_auth_v1_etag_device_mark ( $1, $2, $3, $4 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, ".!!", pp.AmIKnown, rvSecret.UserId, gCfg.EncryptionPassword, gCfg.UserdataPassword)
		_ = rv
		if e0 != nil {
			fmt.Printf("Error on call to ->%s<- err: %s\n", stmt, err)
		}
	} else {
		dbgo.Printf("%(red)No marker id at:%(LF)\n")
	}
	// ----------------------------------------------------------------------------------------------
	// ----------------------------------------------------------------------------------------------

	dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)
	// TODO - stuff
	// rv, stmt, err := ConfirmEmailAccount(c, pp.EmailVerifyToken)
	// create or replace function q_auth_v1_validate_2fa_token ( p_un varchar, p_2fa_secret varchar, p_hmac_password varchar )
	stmt = "q_auth_v1_validate_2fa_token ( $1, $2, $3, $4 )"
	rv, e0 = CallDatabaseJSONFunction(c, stmt, "e!e.", pp.Email, pp.TmpToken /*p_tmp_token*/, rvSecret.Secret2fa, gCfg.EncryptionPassword)
	if e0 != nil {
		err = e0
		return
	}

	dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)
	var rvStatus RvValidate2faTokenType
	err = json.Unmarshal([]byte(rv), &rvStatus)
	if rvStatus.Status != "success" { // if the d.b. call is not success then done - report error
		dbgo.Fprintf(logFilePtr, "%(red)%(LF): rv=%s\n", rv)
		rvStatus.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))                // xyzzy - Encrypted Log File Data
		c.JSON(http.StatusBadRequest, logJsonReturned(rvStatus.StdErrorReturn)) // 400
		return
	}

	dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rvStatus.AuthToken= ->%s<-\n", rvStatus.AuthToken)
	if rvStatus.AuthToken != "" {
		dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)
		theJwtToken := CreateJWTSignedCookie(c, rvStatus.AuthToken)
		dbgo.Fprintf(logFilePtr, "%(green)!! Creating COOKIE Token, Logged In !!  at:%(LF): AuthToken=%s jwtCookieToken=%s\n", rvStatus.AuthToken, theJwtToken)
		c.Set("__is_logged_in__", "y")
		c.Set("__user_id__", fmt.Sprintf("%d", rvStatus.UserId))
		c.Set("__auth_token__", rvStatus.AuthToken)
		// c.Set("__privs__", ConvPrivs2(rvStatus.Privileges))
		rv, mr := ConvPrivs2(rvStatus.Privileges)
		c.Set("__privs__", rv)
		c.Set("__privs_map__", mr)
		c.Set("__email_hmac_password__", gCfg.EncryptionPassword)
		c.Set("__user_password__", gCfg.UserdataPassword)

		if theJwtToken != "" {
			// xyzzy1212-  TokenHeaderVSCookie string `json:"token_header_vs_cookie" default:"cookie"`
			// "Progressive improvement beats delayed perfection" -- Mark Twain
			if gCfg.TokenHeaderVSCookie == "cookie" {
				rvStatus.Token = ""
			} else { // header or both
				rvStatus.Token = theJwtToken
			}
			c.Set("__jwt_token__", theJwtToken)
		}

	}
	dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)

	var out Validate2faTokenSuccess
	copier.Copy(&out, &rvStatus)
	c.JSON(http.StatusOK, logJsonReturned(out)) // 200

}

// -------------------------------------------------------------------------------------------------------------------------
// GetUserId will return a UserID - if the user  is currently logged in then it is from __user_id__ in the context.  If
// the user is not logged in then 0 will be returned.
func GetUserId(c *gin.Context) (UserId int, err error) {
	li := c.GetString("__is_logged_in__")
	if li == "y" {
		s := c.GetString("__user_id__")
		if s == "" {
			dbgo.Fprintf(logFilePtr, "%(red)%(LF): - Failed to get UserID\n")
			return
		}
		UserId, err = strconv.Atoi(s)
		if err != nil {
			dbgo.Fprintf(logFilePtr, "%(red)%(LF): - Failed to get UserID\n")
			return
		}
	}
	return
}

// -------------------------------------------------------------------------------------------------------------------------
// jwtConfig.authInternalHandlers["POST:/api/v1/auth/delete-acct"] = authHandleDeleteAccount

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
// @Router /v1/auth/delete-acct [post]
func authHandleDeleteAccount(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF)\n")
	var pp ApiEmail
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}
	_, AuthToken := GetAuthToken(c)

	if AuthToken != "" { // if user is logged in then logout - else - just ignore.

		// create or replace function q_auth_v1_delete_account ( p_un varchar, p_pw varchar, p_hmac_password varchar )
		stmt := "q_auth_v1_delete_account ( $1, $2, $3 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, "e!.", pp.Email, AuthToken, gCfg.EncryptionPassword)
		if e0 != nil {
			return
		}

		dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)
		// var rvStatus RvStatusType
		var rvStatus StdErrorReturn
		err := json.Unmarshal([]byte(rv), &rvStatus)
		if err != nil || rvStatus.Status != "success" {
			rvStatus.LogUUID = GenUUID()
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus)) // xyzzy - Encrypted Log File Data
			c.JSON(http.StatusBadRequest, logJsonReturned(rvStatus)) // 400
			return
		}

		// xyzzy443 - send email about delete account

		out := ReturnSuccess{Status: "success"}
		c.JSON(http.StatusOK, logJsonReturned(out)) // 200
		return
	}
	out := StdErrorReturn{
		Status:   "error",
		Msg:      "401 not authorized",
		Location: dbgo.LF(),
	}
	c.JSON(http.StatusUnauthorized, logJsonReturned(out))

}

// -------------------------------------------------------------------------------------------------------------------------
// router.POST("/api/v1/auth/register-un-pw", LoginRequiredClosure(authHandleRegisterUnPw))               //

type ApiAuthUn struct {
	Email string `json:"email" form:"email"`
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
// @Router /v1/auth/register-un-pw [post]
func authHandleRegisterUnPw(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF)\n")
	var pp ApiAuthUn
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}
	UserId, AuthToken := GetAuthToken(c)

	if AuthToken != "" { // if user is logged in then logout - else - just ignore.

		// create or replace function q_auth_v1_register_un_pw ( p_parent_user_id int, p_un varchar, p_hmac_password varchar,  p_userdata_password varchar )
		stmt := "q_auth_v1_register_un_pw ( $1, $2, $3, $4 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, "!e..", UserId, pp.Email, gCfg.EncryptionPassword, gCfg.UserdataPassword)
		if e0 != nil {
			return
		}

		dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)
		// var rvStatus RvStatusType
		var rvStatus StdErrorReturn
		err := json.Unmarshal([]byte(rv), &rvStatus)
		if err != nil || rvStatus.Status != "success" {
			rvStatus.LogUUID = GenUUID()
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus)) // xyzzy - Encrypted Log File Data
			c.JSON(http.StatusBadRequest, logJsonReturned(rvStatus)) // 400
			return
		}

		// xyzzy443 - send email about this

		out := ReturnSuccess{Status: "success"}
		c.JSON(http.StatusOK, logJsonReturned(out)) // 200
		return
	}
	out := StdErrorReturn{
		Status:   "error",
		Msg:      "401 not authorized",
		Location: dbgo.LF(),
	}
	c.JSON(http.StatusUnauthorized, logJsonReturned(out))
}

// -------------------------------------------------------------------------------------------------------------------------
// router.POST("/api/v1/auth/register-token", LoginRequiredClosure(authHandleRegisterToken))              //

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
// @Router /v1/auth/register-token [post]
func authHandleRegisterToken(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF)\n")

	UserId, AuthToken := GetAuthToken(c)

	if AuthToken != "" { // if user is logged in then logout - else - just ignore.

		// create or replace function q_auth_v1_register_token ( p_parent_user_id int,  p_hmac_password varchar,  p_userdata_password varchar )
		stmt := "q_auth_v1_delete_account ( $1, $2, $3 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, "!.", UserId, gCfg.EncryptionPassword)
		if e0 != nil {
			return
		}

		dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)
		// var rvStatus RvStatusType
		var rvStatus StdErrorReturn
		err := json.Unmarshal([]byte(rv), &rvStatus)
		if err != nil || rvStatus.Status != "success" {
			rvStatus.LogUUID = GenUUID()
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus)) // xyzzy - Encrypted Log File Data
			c.JSON(http.StatusBadRequest, logJsonReturned(rvStatus)) // 400
			return
		}

		// xyzzy - send email about this

		out := ReturnSuccess{Status: "success"}
		c.JSON(http.StatusOK, logJsonReturned(out)) // 200
		return
	}
	out := StdErrorReturn{
		Status:   "error",
		Msg:      "401 not authorized",
		Location: dbgo.LF(),
	}
	c.JSON(http.StatusUnauthorized, logJsonReturned(out))
}

// -------------------------------------------------------------------------------------------------------------------------
// router.POST("/api/v1/auth/change-email-address", LoginRequiredClosure(authHandleChangeEmailAddress))   //

type ApiAuthChangeEmail struct {
	NewEmail string `json:"new_email" form:"new_email"`
	OldEmail string `json:"old_email" form:"old_email"`
	Pw       string `json:"password" form:"password"`
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
// @Router /v1/auth/change-email-address [post]
func authHandleChangeEmailAddress(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF)\n")
	var pp ApiAuthChangeEmail
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}
	UserId, AuthToken := GetAuthToken(c)

	if AuthToken != "" { // if user is logged in then logout - else - just ignore.

		// create or replace function q_auth_v1_change_email_address ( p_old_email varchar, p_new_email varchar, p_pw varchar, p_hmac_password varchar, p_userdata_password varchar )
		stmt := "q_auth_v1_change_email_address ( $1, $2, $3, $4, $5, $6 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, "eee!..", pp.OldEmail, pp.NewEmail, pp.Pw, UserId, gCfg.EncryptionPassword, gCfg.UserdataPassword)
		if e0 != nil {
			return
		}

		dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)
		// var rvStatus RvStatusType
		var rvStatus StdErrorReturn
		err := json.Unmarshal([]byte(rv), &rvStatus)
		if err != nil || rvStatus.Status != "success" {
			rvStatus.LogUUID = GenUUID()
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus)) // xyzzy - Encrypted Log File Data
			c.JSON(http.StatusBadRequest, logJsonReturned(rvStatus)) // 400
			return
		}

		// xyzzy443 - TODO - send email that Email Address Changed (to both old and new address)

		out := ReturnSuccess{Status: "success"}
		c.JSON(http.StatusOK, logJsonReturned(out)) // 200
		return
	}
	out := StdErrorReturn{
		Status:   "error",
		Msg:      "401 not authorized",
		Location: dbgo.LF(),
	}
	c.JSON(http.StatusUnauthorized, logJsonReturned(out))
}

// -------------------------------------------------------------------------------------------------------------------------
// router.POST("/api/v1/auth/change-account-info", LoginRequiredClosure(authHandleChangeAccountInfo))     //

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
// @Router /v1/auth/change-account-info [post]
func authHandleChangeAccountInfo(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF)\n")
	var pp ApiEmail // TODO - data - add password to confirm
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}
	_, AuthToken := GetAuthToken(c)

	if AuthToken != "" { // if user is logged in then logout - else - just ignore.

		// TODO ---------------------------
		// create or replace function xyzzy ( p_un varchar, p_pw varchar, p_hmac_password varchar )
		stmt := "q_auth_v1_xyzzy ( $1, $2, $3 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, "e!.", pp.Email, AuthToken, gCfg.EncryptionPassword)
		if e0 != nil {
			return
		}

		dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)
		// var rvStatus RvStatusType
		var rvStatus StdErrorReturn
		err := json.Unmarshal([]byte(rv), &rvStatus)
		if err != nil || rvStatus.Status != "success" {
			rvStatus.LogUUID = GenUUID()
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus)) // xyzzy - Encrypted Log File Data
			c.JSON(http.StatusBadRequest, logJsonReturned(rvStatus)) // 400
			return
		}

		// xyzzy443 - send email about this

		out := ReturnSuccess{Status: "success"}
		c.JSON(http.StatusOK, logJsonReturned(out)) // 200
		return
	}
	out := StdErrorReturn{
		Status:   "error",
		Msg:      "401 not authorized",
		Location: dbgo.LF(),
	}
	c.JSON(http.StatusUnauthorized, logJsonReturned(out))

}

// -------------------------------------------------------------------------------------------------------------------------
// router.POST("/api/v1/auth/change-password-admin", LoginRequiredClosure(authHandleChangePasswordAdmin)) //

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
// @Router /v1/auth/change-password-admin [post]
func authHandleChangePasswordAdmin(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF)\n")
	var pp ApiEmail // TODO - I don't think that this works - you need what to change the password to.
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}
	_, AuthToken := GetAuthToken(c)

	if AuthToken != "" { // if user is logged in then logout - else - just ignore.

		// create or replace function q_auth_v1_change_password_admin ( p_admin_user_id int, p_un varchar, p_new_pw varchar, p_hmac_password varchar, p_userdata_password varchar )
		stmt := "q_auth_v1_change_password_admin ( $1, $2, $3, $4, $5 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, "e!.", pp.Email, AuthToken, gCfg.EncryptionPassword)
		if e0 != nil {
			return
		}

		dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)
		// var rvStatus RvStatusType
		var rvStatus StdErrorReturn
		err := json.Unmarshal([]byte(rv), &rvStatus)
		if err != nil || rvStatus.Status != "success" {
			rvStatus.LogUUID = GenUUID()
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus)) // xyzzy - Encrypted Log File Data
			c.JSON(http.StatusBadRequest, logJsonReturned(rvStatus)) // 400
			return
		}

		// xyzzy443 - send email about this

		out := ReturnSuccess{Status: "success"}
		c.JSON(http.StatusOK, logJsonReturned(out)) // 200
		return
	}
	out := StdErrorReturn{
		Status:   "error",
		Msg:      "401 not authorized",
		Location: dbgo.LF(),
	}
	c.JSON(http.StatusUnauthorized, logJsonReturned(out))

}

// -------------------------------------------------------------------------------------------------------------------------
// router.POST("/api/v1/auth/regen-otp", LoginRequiredClosure(authHandleRegenOTP))                        // regenerate list of One Time Passwords (OTP)

type RvRegenOTPType struct {
	StdErrorReturn
	Otp []string `json:"otp"`
}

type RegenOTPSuccess struct {
	Status string   `json:"status"`
	Otp    []string `json:"otp"`
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
// @Router /v1/auth/regen-otp [post]
func authHandleRegenOTP(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF)\n")
	var pp ApiAuthLogin
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}
	_, AuthToken := GetAuthToken(c)

	if AuthToken != "" { // if user is logged in then logout - else - just ignore.

		// TODO ---------------------------
		// create or replace function q_auth_v1_regen_otp ( p_un varchar, p_pw varchar, p_hmac_password varchar )
		stmt := "q_auth_v1_regen_otp ( $1, $2, $3 )"
		rv, e0 := CallDatabaseJSONFunction(c, stmt, "e!.", pp.Email, pp.Pw, gCfg.EncryptionPassword)
		if e0 != nil {
			return
		}

		dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)
		var rvStatus RvRegenOTPType
		err := json.Unmarshal([]byte(rv), &rvStatus)
		if err != nil || rvStatus.Status != "success" {
			rvStatus.LogUUID = GenUUID()
			dbgo.Fprintf(logFilePtr, "%(LF) email >%s< AuthToken >%s<\n", pp.Email, AuthToken)
			log_enc.LogStoredProcError(c, stmt, "e", SVar(rvStatus))                // xyzzy - Encrypted Log File Data
			c.JSON(http.StatusBadRequest, logJsonReturned(rvStatus.StdErrorReturn)) // 400
			return
		}

		// "If you have to swallow a frog don't stare at it too long." -- Mark Twain

		// xyzzy443 - send email about this
		out := RegenOTPSuccess{
			Status: "success",
			Otp:    rvStatus.Otp,
		}
		c.JSON(http.StatusOK, logJsonReturned(out))
		return
	}
	out := StdErrorReturn{
		Status:   "error",
		Msg:      "401 not authorized",
		Location: dbgo.LF(),
	}
	c.JSON(http.StatusUnauthorized, logJsonReturned(out))

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
// @Router /v1/auth/no-login-status [get]
func authHandleNoLoginStatus(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF)\n")
	out := ReturnStatusSuccess{
		Status: "success",
		Msg:    fmt.Sprintf("No Login Requried to Reach .../no-login-status %s\n", dbgo.LF()),
	}
	c.JSON(http.StatusOK, logJsonReturned(out))
}

// -------------------------------------------------------------------------------------------------------------------------
// router.POST("/api/v1/auth/login-status", LoginRequiredClosure(authHandleLoginStatus))                  //	Test of Login Required Stuff

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
// @Router /v1/auth/login-status [post]
func authHandleLoginStatus(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF)\n")
	out := ReturnStatusSuccess{
		Status: "success",
		Msg:    fmt.Sprintf("Login Requried to Reach .../login-status %s\n", dbgo.LF()),
	}
	c.JSON(http.StatusOK, logJsonReturned(out))
}

// -------------------------------------------------------------------------------------------------------------------------
// router.POST("/api/v1/auth/add-2fa-secret", LoginRequiredClosure(authHandleAdd2faSecret)) //
func authHandleAdd2faSecret(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF)\n")

	// xyzzy8888 -------------------------- TODO - add/remove 2fa secret
	// -------------------------- TODO
	// -------------------------- TODO
	// -------------------------- TODO
	// -------------------------- TODO

	c.JSON(http.StatusOK, gin.H{
		"status": "not-implemented-yet",
	})
}

// -------------------------------------------------------------------------------------------------------------------------
// router.POST("/api/v1/auth/remove-2fa-secret", LoginRequiredClosure(authHandleRemove2faSecret))         //
func authHandleRemove2faSecret(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF)\n")

	// xyzzy8888 -------------------------- TODO - add/remove 2fa secret
	// -------------------------- TODO
	// -------------------------- TODO
	// -------------------------- TODO
	// -------------------------- TODO

	c.JSON(http.StatusOK, gin.H{
		"status": "not-implemented-yet",
	})
}

// -------------------------------------------------------------------------------------------------------------------------
type SQLUserIdPrivsType struct {
	UserId     int    `json:"user_id,omitempty" db:"user_id"`
	Privileges string `json:"privileges,omitempty"`
}

func GetAuthToken(c *gin.Context) (UserId int, AuthToken string) {
	dbgo.Fprintf(logFilePtr, "    %(magenta)In GetAuthToken at:%(LF), gCfg.TokenHeaderVSCookie==%s\n", gCfg.TokenHeaderVSCookie)
	dbgo.Fprintf(os.Stderr, "    %(magenta)In GetAuthToken at:%(LF), gCfg.TokenHeaderVSCookie==%s\n", gCfg.TokenHeaderVSCookie)
	// Pull cookie - for X-Auth
	jwtTok, has := "", false
	if gCfg.TokenHeaderVSCookie == "cookie" || gCfg.TokenHeaderVSCookie == "both" {
		has, jwtTok = HasCookie("X-Authentication", c)
		dbgo.Fprintf(logFilePtr, "COOKIE: %(Green) has=%v val=%s for X-Authentication - %(LF)\n", has, jwtTok)
		dbgo.Fprintf(os.Stderr, "COOKIE: %(Green) has=%v val=%s for X-Authentication - %(LF)\n", has, jwtTok)
	}
	if !has && (gCfg.TokenHeaderVSCookie == "header" || gCfg.TokenHeaderVSCookie == "both") {
		// xyzzy1212 -  TokenHeaderVSCookie string `json:"token_header_vs_cookie" default:"cookie"` --  add in Berrer Token Check.
		// has, jwtTok = HasCookie("X-Authentication", www, req)
		// return { 'Authorization': 'Bearer ' + user.token };
		s := c.Request.Header.Get("Authorization")
		if s != "" {
			ss := strings.Split(s, " ")
			if len(ss) == 2 {
				if strings.ToLower(ss[0]) == "bearer" {
					has = true
					jwtTok = ss[1]
				}
			}
		}
		dbgo.Fprintf(logFilePtr, "AuthorizationBearer: %(Green) has=%v val=%s for Authorization - %(LF)\n", has, jwtTok)
		dbgo.Fprintf(os.Stderr, "AuthorizationBearer: %(Green) has=%v val=%s for Authorization - %(LF)\n", has, jwtTok)
	}

	if !has {
		dbgo.Fprintf(logFilePtr, "Authorization: %(red) has=%v -- false -- means not logged in. No Cookie, No Authorization: berrer <token>, %(LF), %s\n", has, dbgo.SVarI(c.Request))
		dbgo.Fprintf(os.Stderr, "Authorization: %(red) has=%v -- false -- means not logged in. No Cookie, No Authorization: berrer <token>, %(LF)\n", has)
		return
	} else {

		dbgo.Fprintf(logFilePtr, "    %(magenta)In GetAuthToken has is true at:%(LF)\n")
		dbgo.Fprintf(os.Stderr, "    %(magenta)In GetAuthToken has is true at:%(LF)\n")

		// Parse and Validate the JWT Berrer
		// Extract the auth_token
		// Validate in the d.b. that this is a valid auth_token
		// get the user_id  -- if have user_id, then ...
		// if valid - then reutrn it.

		// Initialize a new instance of `Claims`
		claims := &JwtClaims{}

		// Parse the JWT string and store the result in `claims`.
		// Note that we are passing the key in this method as well. This method will return an error
		// if the token is invalid (if it has expired according to the expiry time we set on sign in),
		// or if the signature does not match
		//
		// See: https://stackoverflow.com/questions/68481150/how-to-parse-a-jwt-token-with-rsa-in-jwt-go-parsewithclaims
		//		https://stackoverflow.com/questions/68568841/jwt-sign-and-parse-using-es256
		//		https://github.com/dgrijalva/jwt-go/blob/008eba19055c071829e8317937b39845a9d2019b/ecdsa.go#L70
		//		https://github.com/dgrijalva/jwt-go/blob/master/ecdsa_test.go
		//		https://pkg.go.dev/github.com/golang-jwt/jwt/v4#section-readme
		//		https://pkg.go.dev/github.com/golang-jwt/jwt#example-NewWithClaims-CustomClaimsType
		//		https://techdocs.akamai.com/iot-token-access-control/docs/generate-ecdsa-keys
		// Config Colums can be set to $ENV$ - to pull keys from env, or $FILE$ to read ./keys/ed25519-public.pem etc.
		//
		tkn, err := jwt.ParseWithClaims(jwtTok, claims, func(token *jwt.Token) (interface{}, error) {
			data, err := hex.DecodeString(gCfg.JwtKey)
			if err != nil {
				return []byte{}, err
			}
			return data, nil // return gCfg.JwtKey, nil
		})
		if err != nil {
			dbgo.Fprintf(logFilePtr, "X-Authentication - %(LF)\n")
			if err == jwt.ErrSignatureInvalid {
				dbgo.Fprintf(logFilePtr, "X-Authentication - %(LF)\n")
				dbgo.Fprintf(os.Stderr, "X-Authentication - Singature on ->%s<- is invalid %(LF)\n", jwtTok)
				// log
				c.Writer.WriteHeader(http.StatusUnauthorized) // 401
				return
			}
			dbgo.Fprintf(logFilePtr, "X-Authentication - %(LF) err:%s\n", err)
			dbgo.Fprintf(os.Stderr, "X-Authentication - %(LF) err:%s\n", err)
			// log
			c.Writer.WriteHeader(http.StatusBadRequest) // 406
			return
		}
		if !tkn.Valid {
			dbgo.Fprintf(logFilePtr, "X-Authentication - %(LF)\n")
			dbgo.Fprintf(os.Stderr, "X-Authentication - %(LF) - token not valid\n")
			// log
			c.Writer.WriteHeader(http.StatusUnauthorized) // 401
			return
		}

		AuthToken = claims.AuthToken
		dbgo.Fprintf(logFilePtr, "X-Authentication - AuthToken ->%s<- %(LF)\n", AuthToken)
		dbgo.Fprintf(os.Stderr, "X-Authentication - Have an auth_token - %(green)AuthToken ->%s<-%(reset) %(LF)\n", AuthToken)

		/*
			CREATE TABLE if not exists q_qr_auth_tokens (
				auth_token_id 	serial primary key not null,
				user_id 			int not null,
				token			 	uuid not null,
				expires 			timestamp not null
			);
		*/
		var v2 []*SQLUserIdPrivsType
		stmt := `
			select t1.user_id as "user_id", json_agg(t3.priv_name)::text as "privileges"
			from q_qr_users as t1
				join q_qr_auth_tokens as t2 on ( t1.user_id = t2.user_id )
				left join q_qr_user_to_priv as t3 on ( t1.user_id = t3.user_id )
			where t2.token = $1
		      and ( t1.start_date < current_timestamp or t1.start_date is null )
		      and ( t1.end_date > current_timestamp or t1.end_date is null )
			  and t1.email_verified = 'y'
		      and t1.setup_complete_2fa = 'y'
			  and t2.expires > current_timestamp
			group by t1.user_id
		`
		err = pgxscan.Select(ctx, conn, &v2, stmt, AuthToken)
		dbgo.Fprintf(logFilePtr, "Yep - should be a user_id and a set of privs >%s<- at:%(LF)\n", dbgo.SVarI(v2))
		if err != nil {
			log_enc.LogSQLError(c, stmt, err, "e", AuthToken)
			return
		}
		dbgo.Fprintf(logFilePtr, "X-Authentication - after select len(v2) = %d %(LF)\n", len(v2))
		dbgo.Fprintf(os.Stderr, "X-Authentication - after select len(v2) = %d %(LF)\n", len(v2))
		if len(v2) > 0 {
			UserId = v2[0].UserId
			dbgo.Fprintf(logFilePtr, "X-Authentication - %(LF)\n")
			dbgo.Fprintf(os.Stderr, "%(green)Is Authenticated! ----------------------- X-Authentication - %(LF)\n")
			c.Set("__is_logged_in__", "y")
			c.Set("__user_id__", fmt.Sprintf("%d", UserId))
			c.Set("__auth_token__", AuthToken)
			// c.Set("__privs__", ConvPrivs2(v2[0].Privileges))
			rv, mr := ConvPrivs2(v2[0].Privileges)
			c.Set("__privs__", rv)
			c.Set("__privs_map__", mr)
			c.Set("__email_hmac_password__", gCfg.EncryptionPassword)
			c.Set("__user_password__", gCfg.UserdataPassword)
		} else {
			dbgo.Fprintf(logFilePtr, "X-Authentication - %(LF) - did not find auth_token in database\n")
			dbgo.Fprintf(os.Stderr, "X-Authentication - %(LF) - %(red)did not find auth_token in database\n")
			UserId = 0
			AuthToken = ""
		}
		dbgo.Fprintf(logFilePtr, "X-Authentication - at:%(LF)\n")
		dbgo.Fprintf(os.Stderr, "X-Authentication - at:%(LF)\n")

	}
	dbgo.Fprintf(logFilePtr, "X-Authentication - at:%(LF)\n")
	dbgo.Fprintf(os.Stderr, "X-Authentication - at:%(LF)\n")
	return
}

// -------------------------------------------------------------------------------------------------------------------------
// new - modifified
//
// Use:
//	AuthJWTPublic            string `json:"auth_jwt_public_file" default:""`                                                     // Public Key File
//	AuthJWTPrivate           string `json:"auth_jwt_private_file" default:""`                                                    // Private Key File
//	AuthJWTKeyType           string `json:"auth_jwt_key_type" default:"ES" validate:"v.In(['ES256','RS256', 'ES512', 'RS512'])"` // Key type ES = ESDSA or RS = RSA
//	AuthJWTSource            string `json:"auth_jwt_source" default:"Authorization"`                                             // Valid forms for getting authorization

func CreateJWTSignedCookie(c *gin.Context, DBAuthToken string) (rv string) {
	if DBAuthToken != "" {
		// SET: Cookie("X-Authentication", www, req)
		jwtClaims := JwtClaims{
			AuthToken: DBAuthToken,
		}

		// "github.com/dgrijalva/jwt-go"
		//  https://www.sohamkamani.com/golang/jwt-authentication/
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)
		data, err := hex.DecodeString(gCfg.JwtKey)
		if err != nil {
			log_enc.LogMiscError(c, err, fmt.Sprintf("Unable to convert JWT key to []byte from hex ->%s<-", err))
			return
		}
		tokenString, err := token.SignedString(data)
		if err != nil {
			log_enc.LogMiscError(c, err, fmt.Sprintf("Unable to sign JWT token ->%s<- ->%x<-", gCfg.JwtKey, data))
			return
		}
		rv = tokenString

		// xyzzy1212-  TokenHeaderVSCookie string `json:"token_header_vs_cookie" default:"cookie"`
		// "Progressive improvement beats delayed perfection" -- Mark Twain
		if gCfg.TokenHeaderVSCookie == "header" || gCfg.TokenHeaderVSCookie == "both" {
			// return { 'Authorization': 'Bearer ' + user.token };
			c.Writer.Header().Set("Authorization", "Bearer "+tokenString)
		}
		if gCfg.TokenHeaderVSCookie == "cookie" || gCfg.TokenHeaderVSCookie == "both" {
			SetCookie("X-Authentication", tokenString, c) // Will be a secure http cookie on TLS.
			SetInsecureCookie("X-Is-Logged-In", "yes", c) // To let the JS code know that it is logged in.
		}
	}
	return
}

// -------------------------------------------------------------------------------------------------------------------------
func Confirm2faSetupAccount(c *gin.Context, UserId int) {
	// create or replace function q_auth_v1_setup_2fa ( p_user_id varchar )
	stmt := "q_auth_v1_setup_2fa_test ( $1 )"
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF): %s\n", stmt)
	rv, err := CallDatabaseJSONFunction(c, stmt, "!", UserId)
	if err != nil {
		return
	}
	dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)
	return
}

// -------------------------------------------------------------------------------------------------------------------------
func GenerateSecret() string {
	return htotp.RandomSecret(16)
}

// -------------------------------------------------------------------------------------------------------------------------
//  ConfirmEmailAccount uses the token to lookup a user and confirms that the email that received the token is real.
func ConfirmEmailAccount(c *gin.Context, EmailVerifyToken string) (rv, stmt string, err error) {
	// create or replace function q_auth_v1_email_verify ( p_email_verify_token varchar )
	stmt = "q_auth_v1_email_verify ( $1 )"
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF): %s\n", stmt)
	rv, err = CallDatabaseJSONFunction(c, stmt, "!", EmailVerifyToken)
	if err != nil {
		return
	}
	dbgo.Fprintf(logFilePtr, "%(cyan)%(LF): rv=%s\n", rv)
	return
}

// -------------------------------------------------------------------------------------------------------------------------
func SaveState(cookieValue string, UserId int, c *gin.Context) (err error) {
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
	stmt := "insert into q_qr_saved_state ( saved_state_id, user_id, data ) values ( $1, $2, $3 )"
	res, err := conn.Exec(ctx, stmt, cookieValue, UserId, stateData)
	if err != nil {
		dbgo.Fprintf(logFilePtr, "%(yellow) at %(LF)\n")
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
	s := c.GetString("__is_logged_in__")
	if s == "y" {
		ItIs = true
	} else {
		UserId, AuthToken := GetAuthToken(c)
		if AuthToken != "" {
			dbgo.Fprintf(logFilePtr, "%(green) %(LF)2nd part of authorization: user_id=%d auth_token=->%s<-\n", UserId, AuthToken)
			ItIs = true
		} else {
			dbgo.Fprintf(logFilePtr, "%(red) %(LF) ****not authoriazed ****2nd part of authorization: user_id=%d auth_token=->%s<-\n", UserId, AuthToken)
		}
	}
	return
}

// -------------------------------------------------------------------------------------------------------------------------
type SQLStringType struct {
	X string
}
type SQLIntType struct {
	X *int
}

func CallDatabaseJSONFunction(c *gin.Context, fCall string, encPat string, data ...interface{}) (rv string, err error) {
	var v2 []*SQLStringType
	stmt := "select " + fCall + " as \"x\""
	if conn == nil {
		dbgo.Fprintf(logFilePtr, "!!!!! %(red)connection is nil at:%(LF)\n")
		os.Exit(1)
	}
	dbgo.Fprintf(os.Stderr, "    %(yellow)Database Call:%(reset) ->%s<- data ->%s<- from/at:%s\n", stmt, dbgo.SVar(data), dbgo.LF(2))
	dbgo.Fprintf(logFilePtr, "    Database Call ->%s<- data ->%s<- from/at:%s\n", stmt, dbgo.SVar(data), dbgo.LF(2))
	start := time.Now()
	err = pgxscan.Select(ctx, conn, &v2, stmt, data...)
	elapsed := time.Since(start) // elapsed time.Duration
	if err != nil {
		if elapsed > (1 * time.Millisecond) {
			dbgo.Fprintf(os.Stderr, "    %(red)Error on select stmt ->%s<- data %s %(red)elapsed:%s%(reset) at:%s\n", stmt, dbgo.SVar(data), elapsed, dbgo.LF(-1))
		} else {
			dbgo.Fprintf(os.Stderr, "    %(red)Error on select stmt ->%s<- data %s elapsed:%s at:%s\n", stmt, dbgo.SVar(data), elapsed, dbgo.LF(-1))
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
	dbgo.Fprintf(os.Stderr, "    %(yellow)Call Empty Return%(reset) elapsed:%s at:%(LF)\n", elapsed)
	dbgo.Fprintf(logFilePtr, "    Call Empty Return elapsed:%s at:%(LF)\n", elapsed)
	return "{}", nil
}

// -------------------------------------------------------------------------------------------------------------------------
func SqlRunStmt(c *gin.Context, stmt string, encPat string, data ...interface{}) (rv []map[string]interface{}, err error) {
	// var v2 []*SQLStringType
	if conn == nil {
		dbgo.Fprintf(logFilePtr, "!!!!! %(red)connection is nil at:%(LF)\n")
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Database Stmt ->%s<- data ->%s<-\n", stmt, dbgo.SVar(data))
	fmt.Fprintf(logFilePtr, "Database Stmt ->%s<- data ->%s<-\n", stmt, dbgo.SVar(data))

	// res, err := conn.Exec(ctx, stmt, data...)
	err = pgxscan.Select(ctx, conn, &rv, stmt, data...)
	if err != nil {
		log_enc.LogSQLError(c, stmt, err, encPat, data...)
		return nil, fmt.Errorf("Sql error")
	}

	return nil, nil
}

// Input : [{"priv_name":"May Change Password"}, {"priv_name":"May Password"}]
// Outupt : {"May Change Password":true, "May Password":true}
func ConvPrivs(Privileges string) (rv string) {

	if Privileges == "" {
		return
	}
	type PrivDataType struct {
		PrivName string `json:"priv_name"`
	}
	var PrivData []PrivDataType
	mr := make(map[string]bool)
	err := json.Unmarshal([]byte(Privileges), &PrivData)
	if err != nil {
		dbgo.Fprintf(logFilePtr, "Invalid syntax ->%s<- %s at:%(LF)\n", Privileges, err)
		return ""
	}
	for _, vv := range PrivData {
		mr[vv.PrivName] = true
	}

	rv = SVarI(mr)
	return
}

// Input : ["May Change Password", "May Do Whatever"]
// Outupt : {"May Change Password":true, "May Do Whatever":true}
func ConvPrivs2(Privileges string) (rv string, mr map[string]bool) {

	if Privileges == "" {
		return
	}

	PrivData := make([]string, 0, 30)
	mr = make(map[string]bool)
	err := json.Unmarshal([]byte(Privileges), &PrivData)
	if err != nil {
		dbgo.Fprintf(logFilePtr, "Invalid syntax ->%s<- %s at:%(LF)\n", Privileges, err)
		return "", nil
	}
	for _, vv := range PrivData {
		mr[vv] = true
	}

	rv = SVarI(mr)
	return
}

func BindFormOrJSON(c *gin.Context, bindTo interface{}) (err error) {
	content_type := c.Request.Header.Get("Content-Type")
	content_type = strings.ToLower(content_type)
	method := c.Request.Method

	// dbgo.Printf("%(cyan)In BindFormOrJSON at:%(LF)\n")
	if method == "POST" || method == "PUT" {
		// dbgo.Printf("%(cyan)In BindFormOrJSON at:%(LF)\n")
		if strings.HasPrefix(content_type, "application/json") {
			// dbgo.Printf("%(cyan)In BindFormOrJSON at:%(LF)\n")
			if err = c.ShouldBindJSON(bindTo); err != nil {
				dbgo.Printf("%(red)In BindFormOrJSON at:%(LF) err=%s\n", err)
				// xyzzy - should be a log call - with a log_enc.LogInputValidationError... call...
				c.JSON(http.StatusNotAcceptable, logJsonReturned(gin.H{ // 406
					"status": "error",
					"msg":    fmt.Sprintf("Error: %s", err),
				}))
				return
			}
		} else {
			// dbgo.Printf("%(cyan)In BindFormOrJSON at:%(LF)\n")
			if err = c.ShouldBind(bindTo); err != nil {
				dbgo.Printf("%(red)In BindFormOrJSON at:%(LF) err=%s\n", err)
				c.JSON(http.StatusNotAcceptable, logJsonReturned(gin.H{ // 406
					"status": "error",
					"msg":    fmt.Sprintf("Error: %s", err),
				}))
				return
			}
		}
	} else {
		// dbgo.Printf("%(cyan)In BindFormOrJSON at:%(LF)\n")
		if err = c.ShouldBind(bindTo); err != nil {
			dbgo.Printf("%(red)In BindFormOrJSON at:%(LF) err=%s\n", err)
			c.JSON(http.StatusNotAcceptable, logJsonReturned(gin.H{ // 406
				"status": "error",
				"msg":    fmt.Sprintf("Error: %s", err),
			}))
			return
		}
	}
	dbgo.Printf("%(cyan)Parameters: %s at %s\n", dbgo.SVarI(bindTo), dbgo.LF(2))
	return
}

func BindFormOrJSONOptional(c *gin.Context, bindTo interface{}) (err error) {
	content_type := c.Request.Header.Get("Content-Type")
	content_type = strings.ToLower(content_type)
	method := c.Request.Method

	if method == "POST" || method == "PUT" {
		if strings.HasPrefix(content_type, "application/json") {
			if err = c.ShouldBindJSON(bindTo); err != nil {
				dbgo.Printf("# DataBbind: %(yellow)In BindFormOrJSON at:%(LF)   Binding error may mean missing data.  POST/PUT - JsonData  err=%s\n", err)
				dbgo.Fprintf(logFilePtr, "# DataBbind: %(yellow)In BindFormOrJSON at:%(LF)   Binding error may mean missing data.  POST/PUT - JsonData  err=%s\n", err)
				// xyzzy - should be a log call - with a log_enc.LogInputValidationError... call...
				return
			}
		} else {
			if err = c.ShouldBind(bindTo); err != nil {
				dbgo.Fprintf(os.Stdout, "#%(yellow)In BindFormOrJSON at:%(LF) FormBind x-url-encoded POST/PUT Form err=%s\n", err)
				dbgo.Fprintf(logFilePtr, "#%(yellow)In BindFormOrJSON at:%(LF) FormBind x-url-encoded POST/PUT Form err=%s\n", err)
				return
			}
		}
	} else {
		if err = c.ShouldBind(bindTo); err != nil {
			dbgo.Printf("%(yellow)In BindFormOrJSON at:%(LF) GET Query err=%s\n", err)
			dbgo.Fprintf(logFilePtr, "%(yellow)In BindFormOrJSON at:%(LF) GET Query err=%s\n", err)
			return
		}
	}
	dbgo.Printf("# BindData %(cyan)Parameters: %s at %s\n", dbgo.SVarI(bindTo), dbgo.LF(2))
	dbgo.Fprintf(logFilePtr, "# BindData: %(cyan)Parameters: %s at %s\n", dbgo.SVarI(bindTo), dbgo.LF(2))
	return
}

func logJsonReturned(x interface{}) interface{} {
	dbgo.Fprintf(os.Stdout, "%(cyan)Returns: %s at:%s\n", dbgo.SVarI(x), dbgo.LF(2))
	dbgo.Fprintf(logFilePtr, "Returns: %s at:%s\n", dbgo.SVarI(x), dbgo.LF(2))
	return x
}

/* vim: set noai ts=4 sw=4: */
