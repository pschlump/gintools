package table_rest

import (
	"fmt"
	"net/http"
	"os"

	"github.com/pschlump/dbgo"
)

func IsAuthorized(www http.ResponseWriter, req *http.Request) (err error) {
	if db4112 {
		fmt.Fprintf(os.Stderr, "%sIsAuthRequried True!\n    gCfg.AuthMehtod [%s] at:%s%s\n", dbgo.ColorRed, gCfg.AuthMethod, dbgo.LF(), dbgo.ColorReset)
	}
	// xyzzy9221
	return nil

	//x//	if gCfg.AuthMethod == "jwt" {
	//x//
	//x//		dbgo.DbFPrintf("IsAuthorized", os.Stderr, "AT: %s\n", dbgo.LF())
	//x//		// Get the jwt token
	//x//		TokToVerify := GetAuthToVerify(www, req)
	//x//		if TokToVerify == "" {
	//x//			dbgo.DbFPrintf("IsAuthorized", os.Stderr, "Error Exit 1 AT: %s\n", dbgo.LF())
	//x//			return fmt.Errorf("Error")
	//x//		}
	//x//		dbgo.DbFPrintf("IsAuthorized", os.Stderr, "AT: %s\n", dbgo.LF())
	//x//		dbgo.DbFprintf("CheckAuth", logFilePtr, "JWT token to verify [%s] at %s\n", TokToVerify, dbgo.LF())
	//x//		keyFile := gCfg.AuthJWTPublic
	//x//		// check to see if valid
	//x//		iat, err := jwtverif.VerifyToken([]byte(TokToVerify), keyFile, gCfg.AuthJWTKeyType)
	//x//		if err != nil {
	//x//			fmt.Fprintf(logFilePtr, "Verify Error: %s, token ->%s<- AT:%s\n", err, TokToVerify, dbgo.LF())
	//x//			www.WriteHeader(http.StatusUnauthorized) // 401
	//x//			fmt.Fprintf(www, "invalid jwt token for this service")
	//x//			dbgo.DbFPrintf("IsAuthorized", os.Stderr, "Error Exit 2 AT: %s\n", dbgo.LF())
	//x//			return fmt.Errorf("Error")
	//x//		}
	//x//		dbgo.DbFPrintf("IsAuthorized", os.Stderr, "AT: %s\n", dbgo.LF())
	//x//		dbgo.DbFprintf("CheckAuth", logFilePtr, "Verify Success: iat/auth_token=[%s] at %s\n", iat, dbgo.LF())
	//x//		user_id, err := GetUserId(iat)
	//x//		if err != nil {
	//x//			fmt.Fprintf(logFilePtr, "Unable to get user_id AutohorizeHeader (see prev line), AutorizationCookie, X-Header AT:%s\n", dbgo.LF())
	//x//			www.WriteHeader(http.StatusUnauthorized) // 401
	//x//			fmt.Fprintf(www, "Invalid jwt token - missing user_id for this service, %s.  This probably indicates a time-out for the authorization token.", dbgo.LF())
	//x//			dbgo.DbFPrintf("IsAuthorized", os.Stderr, "Error Exit 3 AT: %s\n", dbgo.LF())
	//x//			return fmt.Errorf("Error")
	//x//		}
	//x//		dbgo.DbFPrintf("IsAuthorized", os.Stderr, "AT: %s, user_id=%s auth_token=%s\n", dbgo.LF(), user_id, iat)
	//x//		dbgo.DbFprintf("CheckAuth", logFilePtr, "%sLogin Successful: Data set auth_token=[%s] user_id=[%s] at:%s%s\n", dbgo.ColorGreen, iat, user_id, dbgo.LF(), dbgo.ColorReset)
	//x//		dbgo.DbFprintf("CheckAuth", os.Stderr, "%sLogin Successful: Data set auth_token=[%s] user_id=[%s] at:%s%s\n", dbgo.ColorGreen, iat, user_id, dbgo.LF(), dbgo.ColorReset)
	//x//		dbgo.DbFPrintf("IsAuthorized", os.Stderr, "AT: %s\n", dbgo.LF())
	//x//		SetValue(www, req, "auth_token", iat) // This prevents passing in a auth_token or a user_id
	//x//		SetValue(www, req, "user_id", user_id)
	//x//
	//x//	} else {
	//x//		fmt.Fprintf(os.Stderr, "Fatal: Invalid format for auth (%s) should be 'jwt' or 'key' required.\n", gCfg.AuthMethod)
	//x//		fmt.Fprintf(logFilePtr, "Fatal: Invalid format for auth  (%s) should be 'jwt' or 'key'required. AT:%s\n", gCfg.AuthMethod, dbgo.LF())
	//x//		os.Exit(3)
	//x//	}
	return nil
}

// GetUserId queries the database to turn an `auth_token` into a `user_id'.
// Called from server layer and used to compare the passed user_id with the
// tokens user_id.
func GetUserId(auth_token string) (user_id string, err error) {
	stmt := `select user_id from q_qr_auth_tokens where token = $1`
	err = SQLQueryRow(stmt, auth_token).Scan(&user_id)
	return
}

var db4112 = false
