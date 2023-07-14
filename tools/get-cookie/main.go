package main

/*
1. Makefile:
	create_update_test_accounts:
		~/bin/get-cookie --set-pass --email "admin@client.com" --pass "<a-password>" --output-path "./x/bol-admin" --validation-server "http://localhost:9080/api/v1/auth/login-status"
*/

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pschlump/ReadConfig"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/filelib"
	"github.com/pschlump/gintools/data"
	"github.com/pschlump/gintools/email"
	"github.com/pschlump/gintools/jwt_auth"
	"github.com/pschlump/gintools/version"
	"github.com/pschlump/godebug"
	"github.com/pschlump/htotp"
	"github.com/pschlump/json"
	"github.com/pschlump/scany/pgxscan"
)

var Cfg = flag.String("cfg", "cfg.json", "config file for this call")
var DbFlagParam = flag.String("db_flag", "", "Additional Debug Flags")
var CdTo = flag.String("CdTo", "./", "Change directory to before running server.")
var Email = flag.String("email", "", "Login username (email).")
var Password = flag.String("pass", "abcdefghij", "Password")
var SetPass = flag.Bool("set-pass", false, "Set password to <Password>")
var VersionFlag = flag.Bool("version", false, "Report version of code and exit")
var Gen2fa = flag.Bool("gen-2fa", false, "Generate 2fa PIN/token")
var OutputPath = flag.String("output-path", "./x", "Path To Write To")
var ServerIPHost = flag.String("server-ip-host", "127.0.0.1:9080", "IP and Port of Server")
var ValidationServer = flag.String("validation-server", "", "URL to use to validate that cookie is valid")

var DbOn map[string]bool = make(map[string]bool)
var logFilePtr *os.File = os.Stderr
var gCfg data.GlobalConfigData
var em email.EmailSender
var emailLog *os.File = os.Stderr

// Database Context and Connection
var conn *pgxpool.Pool
var ctx context.Context

func main() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "gen-cookie: Usage: %s [flags]\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse() // Parse CLI arguments to this, --cfg <name>.json

	fns := flag.Args()
	if len(fns) != 0 {
		fmt.Printf("Extra arguments are not supported [%s]\n", fns)
		os.Exit(1)
	}

	version.SetVersion(Version, "gin-server", GitCommit, BuildDate)
	if *VersionFlag {
		version.PrintVersion()
		os.Exit(0)
	}

	if Cfg == nil {
		fmt.Printf("--cfg is a required parameter\n")
		os.Exit(1)
	}

	if *CdTo != "" {
		err := os.Chdir(*CdTo)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to chagne to %s directory, error:%s\n", *CdTo, err)
			os.Exit(1)
		}
	}

	// ------------------------------------------------------------------------------
	// Read in Configuration
	// ------------------------------------------------------------------------------
	err := ReadConfig.ReadFile(*Cfg, &gCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read confguration: %s error %s\n", *Cfg, err)
		os.Exit(1)
	}

	// ------------------------------------------------------------------------------
	// Debug Flag Processing
	// ------------------------------------------------------------------------------
	for _, x := range gCfg.DbFlags {
		DbOn[x] = true
	}
	DebugFlagProcess(DbFlagParam, DbOn, &(gCfg.BaseConfigType))

	// --------------------------------------------------------------------------------------
	// Connect to database - if we get to the defer then we have successfuly connected.
	// --------------------------------------------------------------------------------------
	ConnectToDb()
	defer DisConnectToDb()

	dbgo.SetDbFlag(DbOn)

	em = email.NewEmailSender("sendgrid", &(gCfg.BaseConfigType), DbOn, emailLog, conn, ctx, nil /*logger*/, nil /* /metrics */)
	if em == nil {
		fmt.Printf("Failed to get an email sender\n")
		os.Exit(1)
	}

	// jwt_auth.SetupConnectToJwtAuth(ctx, conn, &gCfg, logFilePtr, em, nil /*logger*/, nil /*metrics*/)
	jwt_auth.SetupConnectToJwtAuth(ctx, conn, &(gCfg.BaseConfigType), &(gCfg.AppConfig), &(gCfg.QRConfig), logFilePtr, em, nil /*logger*/, nil /*metrics*/)

	dbgo.Fprintf(os.Stderr, "%(green)Connected to DB\n")
	dbgo.Fprintf(os.Stderr, "%(yellow)Connected to DB\n")
	dbgo.Fprintf(os.Stderr, "%(magenta)Connected to DB\n")

	if err := jwt_auth.ValidatePasswords(); err != nil {
		dbgo.Fprintf(os.Stderr, "%(red)Not Setup Correctly - invalid passwords - early exit\n")
		os.Exit(1)
	}

	dbgo.Printf("%(green)Encyption passwords validated.\n")

	// if "set passwrod" then call SP to set it.
	if *SetPass {
		// create or replace function q_auth_v1_change_password_root_cli ( p_email varchar, p_new_pw varchar, p_hmac_password varchar, p_userdata_password varchar )
		stmt := "q_auth_v1_change_password_root_cli ( $1, $2, $3, $4 )"
		// rv, err := CallDatabaseJSONFunction(c, stmt, "..!!", newId, ref, gCfg.EncryptionPassword, gCfg.UserdataPassword)
		md, rv, err := CallDatabaseJSONFunction(stmt, *Email, *Password, gCfg.EncryptionPassword, gCfg.UserdataPassword)

		if err != nil {
			fmt.Fprintf(os.Stderr, "Stmt %s email=%s password=%s error:%s\n", stmt, *Email, *Password, err)
			os.Exit(1)
		}

		if DbOn["db1"] {
			fmt.Printf("Call to q_auth_v1_change_password_root_cli ( $1, $2, $3, $4 ) = %s\n\n", rv)
		}

		if !ChkStatusSuccess(md) {
			dbgo.Printf("%(red)Failed... at:%(LF)%s\n", dbgo.SVarI(md))
			os.Exit(1)
		}
		dbgo.Printf("\n%(green)Password Updated --------------------------------------------------------\n\n")
	}

	// =========================================================== ===========================================================
	// perform login
	// =========================================================== ===========================================================
	// 		1. wget --header="Referer: ${server}/home" -o xref.err -O xref.out "${server}/api/v1/auth/setup.js"
	// 			from: $tools/jwt_auth/clear_gif.go
	//				func authHandlerGetXsrfIdFile(c *gin.Context) {
	//					newId := GenUUID()
	//					ref := "http://localhost:9080/"
	//					stmt := "q_auth_v1_xsrf_setup ( $1, $2, $3, $4 )"
	//					rv, e0 := CallDatabaseJSONFunction(c, stmt, "..!!", newId, ref, gCfg.EncryptionPassword, gCfg.UserdataPassword)
	// 		2. create or replace function q_auth_v1_login ( p_email varchar, p_pw varchar, p_am_i_known varchar, p_hmac_password varchar, p_userdata_password varchar )
	//		3. Check that valid un/pw
	newId := GenUUID()
	ref := "http://localhost:9080/"
	stmt := "q_auth_v1_xsrf_setup ( $1, $2, $3, $4 )"
	md, rv, err := CallDatabaseJSONFunction(stmt, newId, ref, gCfg.EncryptionPassword, gCfg.UserdataPassword)
	_ = rv

	if err != nil {
		fmt.Fprintf(os.Stderr, "Stmt %s newId=%s ref=%s error:%s\n", stmt, newId, ref, err)
		os.Exit(1)
	}

	if !ChkStatusSuccess(md) {
		dbgo.Printf("%(red)Failed... at:%(LF)%s\n", dbgo.SVarI(md))
		os.Exit(1)
	}

	dbgo.Printf("\n%(green)Xref ID set\n\n")

	// ----------------------------------------------------------------

	//stmt = "function q_auth_v1_login ( p_email varchar, p_pw varchar, p_am_i_known varchar, p_hmac_password varchar, p_userdata_password varchar )
	stmt = "q_auth_v1_login ( $1, $2, $3, $4, $5, $6, $7, $8, $9 )"
	md, rv, err = CallDatabaseJSONFunction(stmt, *Email, *Password, newId, gCfg.EncryptionPassword, gCfg.UserdataPassword, "xyzzy8", "xyzzy8", "xyzzy8", "cf047ec4-38c1-4ad1-782e-dfb744bb92f6")
	_ = rv

	if err != nil {
		fmt.Fprintf(os.Stderr, "Stmt %s %s %s newId=%s error:%s\n", stmt, *Email, *Password, newId, err)
		os.Exit(1)
	}

	if !ChkStatusSuccess(md) {
		dbgo.Printf("%(red)Failed... at:%(LF)%s\n", dbgo.SVarI(md))
		os.Exit(1)
	}

	dbgo.Printf("\n%(green)Logged in\n\n")

	// =========================================================== ===========================================================
	// perform 2fa
	// =========================================================== ===========================================================
	//		0. get the 2fa secret
	// 		1. insert/update into ./cfg.acc.json
	// 		2. ~/bin/acc --gen2fa "/truckcoinswap.com:${email}" --output ,acc.out
	// 		3. wget -o validate-2fa-token.err -O validate-2fa-token --keep-session-cookies --save-cookies cookies.txt -S --post-data "email=${email}&x2fa_pin=$ACC&tmp_token=$TmpToken" "${server}/api/v1/auth/validate-2fa-token"
	//		4. Check that valid 2fa token

	if *Gen2fa {
		/*
		   --- Alternative Approach ---
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
		   		log_enc.LogStoredProcError(c, stmt, "e.", SVar(rvSecret), fmt.Sprintf("%s", err))
		   		c.JSON(http.StatusBadRequest, LogJsonReturned(rvSecret.StdErrorReturn)) // 400
		   		return
		   	}
		*/

		stmt = "select secret_2fa as \"x\" from q_qr_users where email_hmac = q_auth_v1_hmac_encode ( $1, $2 )"
		rv, err = RunSql(stmt, *Email, gCfg.EncryptionPassword)

		if err != nil {
			fmt.Fprintf(os.Stderr, "Stmt %s email=%s error:%s\n", stmt, *Email, err)
			os.Exit(1)
		}

		secret_2fa := rv

		dbgo.Printf("\n%(green)Got Secret ->%s<-\n\n", secret_2fa)

		// ----------------------------------------------------------------
		pin := Gen2faSecret(secret_2fa)

		dbgo.Printf("\n%(green)Pin ->%s<-\n\n", pin)
	}

	// ----------------------------------------------------------------
	// 		3. wget -o validate-2fa-token.err -O validate-2fa-token --keep-session-cookies --save-cookies cookies.txt -S --post-data "email=${email}&x2fa_pin=$ACC&tmp_token=$TmpToken" "${server}/api/v1/auth/validate-2fa-token"
	// See: 		/Users/philip/go/src/github.com/pschlump/gintools/jwt_auth/auth.go :1894
	// stmt = "q_auth_v1_validate_2fa_token ( $1, $2, $3, $4, $5 )" -- creates AuthToken
	// create or replace function q_auth_v1_create_auth_token ( p_email varchar, p_auth_token varchar, p_hmac_password varchar, p_userdata_password varchar )

	auth_token := GenUUID()

	stmt = "q_auth_v1_create_auth_token ( $1, $2, $3, $4 )"
	md, rv, err = CallDatabaseJSONFunction(stmt, *Email, auth_token, gCfg.EncryptionPassword, gCfg.UserdataPassword)
	_ = rv

	if err != nil {
		fmt.Fprintf(os.Stderr, "Stmt %s %s %s newId=%s error:%s\n", stmt, *Email, *Password, newId, err)
		os.Exit(1)
	}

	if !ChkStatusSuccess(md) {
		dbgo.Printf("Failed... at:%(LF)\n")
		os.Exit(1)
	}

	dbgo.Printf("\n%(green)auth_token ->%s<-\n\n", auth_token)

	// ----------------------------------------------------------------

	jwtToken, err := jwt_auth.CreateJWTSignedCookieNoErr(auth_token, *Email)
	if err != nil {
		dbgo.Printf("Failed... error:%s at:%(LF)\n", err)
		os.Exit(1)
	}

	dbgo.Printf("\n%(green)auth_token ->%s<- email ->%s<- jwt_token ->%(yellow)%s%(green)<-%(reset)\n\n", auth_token, *Email, jwtToken)

	// =========================================================== ===========================================================
	// Get JWT and save it using the templates.
	// =========================================================== ===========================================================
	// 		1. For templates, substiute and write.

	mdata := make(map[string]string)
	mdata["email"] = *Email
	mdata["email_url_encoded"] = url.QueryEscape(*Email)
	mdata["jwt_token"] = jwtToken
	mdata["auth_token"] = auth_token
	mdata["timestamp"] = time.Now().Format(time.RFC3339)
	mdata["file_name"] = "cookies"
	mdata["output_path"] = *OutputPath
	mdata["server_ip_host"] = *ServerIPHost
	// cookies.txt
	// cookies.jar.txt

	os.MkdirAll(*OutputPath, 0755)

	fn1 := filelib.Qt(WgetFn, mdata)
	err = ioutil.WriteFile(fn1, []byte(filelib.Qt(WgetTemplate, mdata)), 0600)
	if err != nil {
		dbgo.Printf("Unable to open %s for output: %s\n", fn1, err)
		os.Exit(1)
	}

	fn1 = filelib.Qt(CurlFn, mdata)
	err = ioutil.WriteFile(fn1, []byte(filelib.Qt(CurlTemplate, mdata)), 0600)
	if err != nil {
		dbgo.Printf("Unable to open %s for output: %s\n", fn1, err)
		os.Exit(1)
	}

	fn1 = filelib.Qt(JsonFn, mdata)
	err = ioutil.WriteFile(fn1, []byte(filelib.Qt(JsonTemplate, mdata)), 0600)
	if err != nil {
		dbgo.Printf("Unable to open %s for output: %s\n", fn1, err)
		os.Exit(1)
	}

	// =========================================================== ===========================================================
	// =========================================================== ===========================================================
	if *ValidationServer != "" {
		// status, rv := DoGetHeader(*ValidationServer, []HeaderType{{Name: "Authorization", Value: fmt.Sprintf("bearer %s", jwtToken)}})

		// has, jwtTok = HasCookie("X-Authentication", c)
		status, rv := DoGetHeader(*ValidationServer, []HeaderType{{Name: "Cookie", Value: fmt.Sprintf("X-Authentication=%s", jwtToken)}})
		if status != 200 {
			dbgo.Printf("\n%(red)Server did not return 200, %d returned\n", status)
			os.Exit(1)
		}

		// decode rv and look for "success"
		fmt.Fprintf(os.Stdout, "rv=%s\n", rv)

		if !ChkStatusSuccessString(rv) {
			dbgo.Printf("\n%(red)PASS - token not valid...\n")
			os.Exit(1)
		}

		dbgo.Printf("\n%(green)PASS - token valid for login...\n")
	}

	dbgo.Printf("\n%(green)PASS - so far so good...\n")
}

// -------------------------------------------------------------------------------------------------------------------------
type StatusRv struct {
	Status string `json:"status"`
}

func ChkStatusSuccessString(s string) bool {
	var rv StatusRv
	err := json.Unmarshal([]byte(s), &rv)
	if err != nil {
		return false
	}
	if rv.Status != "success" {
		return false
	}
	return true
}

func ChkStatusSuccess(md map[string]interface{}) bool {
	if v1, ok := md["status"]; ok {
		if v2, ok := v1.(string); ok {
			if v2 == "success" {
				return true
			}
		}
	}
	return false
}

func GetStrValue(md map[string]interface{}, name string) string {
	if v1, ok := md[name]; ok {
		if v2, ok := v1.(string); ok {
			return v2
		}
	}
	return ""
}

// -------------------------------------------------------------------------------------------------------------------------
type SQLStringType struct {
	X string
}

func CallDatabaseJSONFunction(fCall string, data ...interface{}) (md map[string]interface{}, rv string, err error) {
	md = make(map[string]interface{})
	var v2 []*SQLStringType
	stmt := "select " + fCall + " as \"x\""
	if conn == nil {
		dbgo.Fprintf(os.Stderr, "!!!!! %(red)connection is nil at:%(LF)\n")
		os.Exit(1)
	}
	dbgo.Fprintf(os.Stderr, "    %(yellow)Database Call:%(reset) ->%s<- data ->%s<- from/at:%s\n", stmt, dbgo.SVar(data), dbgo.LF(2))
	start := time.Now()
	err = pgxscan.Select(ctx, conn, &v2, stmt, data...)
	elapsed := time.Since(start) // elapsed time.Duration
	if err != nil {
		if elapsed > (1 * time.Millisecond) {
			dbgo.Fprintf(os.Stderr, "    %(red)Error on select stmt ->%s<- data %s %(red)elapsed:%s%(reset) at:%s\n", stmt, dbgo.SVar(data), elapsed, dbgo.LF(-1))
		} else {
			dbgo.Fprintf(os.Stderr, "    %(red)Error on select stmt ->%s<- data %s elapsed:%s at:%s\n", stmt, dbgo.SVar(data), elapsed, dbgo.LF(-1))
		}
		LogSQLErrorLoc(stmt, err, data...)
		return md, "", fmt.Errorf("Sql error")
	}
	if len(v2) > 0 {
		dbgo.Fprintf(os.Stderr, "    %(yellow)Call Returns:%(reset) %s elapsed:%s at:%(LF)\n", v2[0].X, elapsed)

		rv = v2[0].X
		err := json.Unmarshal([]byte(rv), &md)
		if err != nil {
			dbgo.Fprintf(os.Stderr, "    %(red)Parse error in return: ->%s<- error:%s\n", rv, err)
		}

		return md, rv, nil
	}
	dbgo.Fprintf(os.Stderr, "    %(yellow)Call Empty Return%(reset) elapsed:%s at:%(LF)\n", elapsed)
	return md, "{}", nil
}

func RunSql(stmt string, data ...interface{}) (rv string, err error) {
	var v2 []*SQLStringType
	if conn == nil {
		dbgo.Fprintf(os.Stderr, "!!!!! %(red)connection is nil at:%(LF)\n")
		os.Exit(1)
	}
	dbgo.Fprintf(os.Stderr, "    %(yellow)Database Call:%(reset) ->%s<- data ->%s<- from/at:%s\n", stmt, dbgo.SVar(data), dbgo.LF(2))
	start := time.Now()
	err = pgxscan.Select(ctx, conn, &v2, stmt, data...)
	elapsed := time.Since(start) // elapsed time.Duration
	if err != nil {
		if elapsed > (1 * time.Millisecond) {
			dbgo.Fprintf(os.Stderr, "    %(red)Error on select stmt ->%s<- data %s %(red)elapsed:%s%(reset) at:%s\n", stmt, dbgo.SVar(data), elapsed, dbgo.LF(-1))
		} else {
			dbgo.Fprintf(os.Stderr, "    %(red)Error on select stmt ->%s<- data %s elapsed:%s at:%s\n", stmt, dbgo.SVar(data), elapsed, dbgo.LF(-1))
		}
		LogSQLErrorLoc(stmt, err, data...)
		return "", fmt.Errorf("Sql error")
	}
	if len(v2) > 0 {
		dbgo.Fprintf(os.Stderr, "    %(yellow)Call Returns:%(reset) %s elapsed:%s at:%(LF)\n", v2[0].X, elapsed)

		rv = v2[0].X

		return rv, nil
	}
	dbgo.Fprintf(os.Stderr, "    %(yellow)Call Empty Return%(reset) elapsed:%s at:%(LF)\n", elapsed)
	return "{}", nil
}

func LogSQLErrorLoc(stmt string, err error, data ...interface{}) {
	LogIt("SQLError",
		"stmt", stmt,
		"error", fmt.Sprintf("%s", err),
		"data", dbgo.SVar(data),
		"AT", godebug.LF(-2),
	)
}

func LogIt(s string, x ...interface{}) {
	// dbgo.Fprintf(os.Stderr, "%(red)At:%(LF)\n")
	fmt.Fprintf(os.Stderr, "{ \"type\":%q", s)
	// dbgo.Fprintf(os.Stderr, "%(red)At:%(LF)\n")
	fmt.Fprintf(logFilePtr, "{ \"type\":%q", s)
	for i := 0; i < len(x); i += 2 {
		// dbgo.Fprintf(os.Stderr, "%(red)At:%(LF)\n")
		if i+1 < len(x) {
			// dbgo.Fprintf(os.Stderr, "%(red)At:%(LF)\n")
			fmt.Fprintf(os.Stderr, ", %q: %q", x[i], x[i+1])
			// dbgo.Fprintf(os.Stderr, "%(red)At:%(LF)\n")
			fmt.Fprintf(logFilePtr, ", %q: %q", x[i], x[i+1])
		}
	}
	// dbgo.Fprintf(os.Stderr, "%(red)At:%(LF)\n")
	fmt.Fprintf(os.Stderr, "}\n")
	// dbgo.Fprintf(os.Stderr, "%(red)At:%(LF)\n")
	fmt.Fprintf(logFilePtr, "}\n")
	// dbgo.Fprintf(os.Stderr, "%(red)At:%(LF)\n")
}

func Gen2faSecret(secret string) string {
	un := ""                                              // not used
	pin, tl := htotp.GenerateRfc6238TOTPKeyTL(un, secret) // generate TOTP key
	_ = tl
	fmt.Printf("pin= ->%s<-\n", pin)
	return pin
}

var WgetFn = `%{output_path%}/%{file_name%}.txt`

var WgetTemplate = `
# HTTP Cookie File
# Generated by gen-cookies for Wget on %{timestamp%}.
# Edit at your own risk.

%{server_ip_host%}	FALSE	/	FALSE	1986210338	X-Is-Logged-In	yes
%{server_ip_host%}	FALSE	/	FALSE	1986210338	X-Authentication-User	%{email_url_encoded%}
%{server_ip_host%}	FALSE	/	FALSE	1986210338	X-Authentication	%{jwt_token%}
`

var CurlFn = `%{output_path%}/%{file_name%}.jar.txt`

var CurlTemplate = `
# HTTP Cookie File
# Generated by gen-cookies for CURL on %{timestamp%}.
# Edit at your own risk.

127.0.0.1	FALSE	/	FALSE	1986210338	X-Authentication	%{jwt_token%}
127.0.0.1	FALSE	/	FALSE	1986210338	X-Authentication-User	%{email_url_encoded%}
127.0.0.1	FALSE	/	FALSE	1986210338	X-Is-Logged-In	yes
`

var JsonFn = `%{output_path%}/%{file_name%}.json`

var JsonTemplate = `{
	"__comment__":"JSON Cookie File: Generated by gen-cookies on %{timestamp%}."
	, "user_email": "%{email%}"
	, "jwt_token": "%{jwt_token%}"
}
`
