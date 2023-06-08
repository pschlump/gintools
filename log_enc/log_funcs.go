package log_enc

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/godebug"
)

// LogIt sends output to both the log file, logFilePtr, and to os.Stderr if we are running in
// dev mode (gCfg.LogMode == "dev")
func LogIt(s string, x ...interface{}) {
	// dbgo.Fprintf(os.Stderr, "%(red)At:%(LF)\n")
	if gCfg != nil && gCfg.LogMode == "dev" {
		fmt.Fprintf(os.Stderr, "{ \"type\":%q", s)
	}
	// dbgo.Fprintf(os.Stderr, "%(red)At:%(LF)\n")
	fmt.Fprintf(logFilePtr, "{ \"type\":%q", s)
	for i := 0; i < len(x); i += 2 {
		// dbgo.Fprintf(os.Stderr, "%(red)At:%(LF)\n")
		if i+1 < len(x) {
			// dbgo.Fprintf(os.Stderr, "%(red)At:%(LF)\n")
			if gCfg != nil && gCfg.LogMode == "dev" {
				fmt.Fprintf(os.Stderr, ", %q: %q", x[i], x[i+1])
			}
			// dbgo.Fprintf(os.Stderr, "%(red)At:%(LF)\n")
			fmt.Fprintf(logFilePtr, ", %q: %q", x[i], x[i+1])
		}
	}
	// dbgo.Fprintf(os.Stderr, "%(red)At:%(LF)\n")
	if gCfg != nil && gCfg.LogMode == "dev" {
		fmt.Fprintf(os.Stderr, "}\n")
	}
	// dbgo.Fprintf(os.Stderr, "%(red)At:%(LF)\n")
	fmt.Fprintf(logFilePtr, "}\n")
	// dbgo.Fprintf(os.Stderr, "%(red)At:%(LF)\n")
}

// Log in apache format (inside a string for zap)
func LogApacheReq(data string) {
	LogIt("ApacheLog",
		"apache", data,
	)
}

// func EncryptLogData(pat string, vars ...interface{}) string {

// Log a SQL error.
func LogSQLError(c *gin.Context, stmt string, err error, encPat string, data ...interface{}) {
	if c == nil {
		LogIt("SQLError",
			"stmt", stmt,
			"error", errToString(err),
			// "data", EncryptLogData(encPat, data...), // "data", dbgo.SVar(PreProcessData(data)), // "data", SVar(data),
			"data", dbgo.SVar(data),
			"AT", godebug.LF(-2),
		)
		return
	}
	// LogEncryptionPassword string `json:"log_encryption_password" default:"$ENV$QR_LOG_ENCRYPTION_PASSWORD"`
	requestId := c.GetString("__request_id__")
	LogIt("SQLError",
		"url", c.Request.RequestURI,
		"method", c.Request.Method,
		"stmt", stmt,
		"error", errToString(err),
		"request_id", requestId,
		// "data", EncryptLogData(encPat, data...), // "data", dbgo.SVar(PreProcessData(data)), // "data", SVar(data),
		"data", dbgo.SVar(data),
		"AT", godebug.LF(-2),
	)
	c.JSON(http.StatusBadRequest, gin.H{ // 400
		"status": "error",
		"msg":    "Database Error",
	})
}

func LogSQLErrorNoErr(c *gin.Context, stmt string, err error, encPat string, data ...interface{}) {
	// LogEncryptionPassword string `json:"log_encryption_password" default:"$ENV$QR_LOG_ENCRYPTION_PASSWORD"`
	requestId := c.GetString("__request_id__")
	LogIt("SQLError",
		"url", c.Request.RequestURI,
		"method", c.Request.Method,
		"stmt", stmt,
		"error", errToString(err),
		"request_id", requestId,
		// "data", EncryptLogData(encPat, data...), // "data", dbgo.SVar(PreProcessData(data)), // "data", SVar(data),
		"data", dbgo.SVar(data),
		"AT", godebug.LF(-2),
	)
}

// LogStoredProcError(www, req, stmt, SVar(RegisterResp), pp.Un, pp.Pw /*gCfg.EncryptionPassword,*/, pp.RealName /*, gCfg.UserdataPassword*/)
func LogStoredProcError(c *gin.Context, stmt string, encPat string, data ...interface{}) {
	if c == nil {
		LogIt("StoredProcError",
			"stmt", stmt,
			// "data", EncryptLogData(encPat, data...), // "data", dbgo.SVar(PreProcessData(data)), // "data", SVar(data),
			"data", dbgo.SVar(data),
			"AT", godebug.LF(-2),
		)
		return
	}
	requestId := c.GetString("__request_id__")
	LogIt("StoredProcError",
		"url", c.Request.RequestURI,
		"method", c.Request.Method,
		"stmt", stmt,
		// "data", EncryptLogData(encPat, data...), // "data", dbgo.SVar(PreProcessData(data)), // "data", SVar(data),
		"data", dbgo.SVar(data),
		"request_id", requestId,
		"AT", godebug.LF(-2),
	)
	SetJsonHdr(c)
	c.Writer.WriteHeader(http.StatusBadRequest) // 400
}

// Log a misc error.
func LogMiscError(c *gin.Context, err error, message string) {
	requestId := c.GetString("__request_id__")
	LogIt("MiscError",
		"url", c.Request.RequestURI,
		"method", c.Request.Method,
		"error", errToString(err),
		"message", message,
		"request_id", requestId,
		"AT", godebug.LF(-2),
	)
	c.JSON(http.StatusBadRequest, gin.H{ // 400
		"status": "error",
		"msg":    message,
	})
}

func LogS3Error(err error, message, RequestURI, Method, requestId string) {
	LogIt("S3Error",
		"url", RequestURI,
		"method", Method,
		"error", errToString(err),
		"message", message,
		"request_id", requestId,
		"AT", godebug.LF(-2),
	)
}

func LogAttentionError(c *gin.Context, err error, message string) {
	requestId := c.GetString("__request_id__")
	LogIt("AttentionError",
		"url", c.Request.RequestURI,
		"method", c.Request.Method,
		"error", errToString(err),
		"message", message,
		"request_id", requestId,
		"AT", godebug.LF(-2),
	)
}

// Log a internal misc error.
func LogInternalMiscError(c *gin.Context, err error, message string) {
	requestId := c.GetString("__request_id__")
	LogIt("InternalMiscError",
		"url", c.Request.RequestURI,
		"method", c.Request.Method,
		"error", errToString(err),
		"message", message,
		"request_id", requestId,
		"AT", godebug.LF(-2),
	)
	c.JSON(http.StatusInternalServerError, gin.H{ // 400
		"status": "error",
		"msg":    message,
	})
}

// Log a misc warning
func LogMiscWarn(c *gin.Context, err error, message string) {
	requestId := c.GetString("__request_id__")
	LogIt("MiscWarning",
		"url", c.Request.RequestURI,
		"method", c.Request.Method,
		"error", errToString(err),
		"message", message,
		"request_id", requestId,
		"AT", godebug.LF(-2),
	)
}

// Log an invalid parameter error.
func LogParamError(c *gin.Context, pn, msg string) {
	requestId := c.GetString("__request_id__")
	LogIt("InvalidParameter",
		"url", c.Request.RequestURI,
		"method", c.Request.Method,
		"param_name", pn,
		"msg", msg,
		"request_id", requestId,
		"AT", godebug.LF(-2),
	)
	c.JSON(http.StatusNotAcceptable, gin.H{ // 400
		"status": "error",
		"msg":    msg,
	})
}

// Log an invalid method.
func LogInvalidMethodError(c *gin.Context) {
	requestId := c.GetString("__request_id__")
	LogIt("InvalidMethod",
		"url", c.Request.RequestURI,
		"method", c.Request.Method,
		"request_id", requestId,
		"msg", "Invalid Method",
		"AT", godebug.LF(-2),
	)
	c.JSON(http.StatusMethodNotAllowed, gin.H{ // 400
		"status": "error",
		"msg":    "Invalid Method",
	})
}

// Log an missing privilege.
func LogPrivError(c *gin.Context, priv_missing, msg string) {
	requestId := c.GetString("__request_id__")
	LogIt("MissingPrivilege",
		"url", c.Request.RequestURI,
		"method", c.Request.Method,
		"missing_priv", priv_missing,
		"msg", msg,
		"request_id", requestId,
		"AT", dbgo.LF(-2),
	)
	c.JSON(http.StatusForbidden, gin.H{ // 403
		"status": "error",
		"msg":    msg,
	})
}

// log_enc.LogSQLPrivilage(c, aPriv, ".", user_id) // Don't need to encyprt user_id
func LogSQLPrivelage(c *gin.Context, priv_missing, encPat string, user_id string) {
	requestId := c.GetString("__request_id__")
	LogIt("MissingPrivilege",
		"url", c.Request.RequestURI,
		"method", c.Request.Method,
		"missing_priv", priv_missing,
		"request_id", requestId,
		"msg", "Misging Privelage",
		// "user_id", user_id,
		"user_id", EncryptLogData(encPat, user_id), // "data", dbgo.SVar(PreProcessData(data)), // "data", SVar(data),
		"AT", dbgo.LF(-2),
	)
	c.JSON(http.StatusForbidden, gin.H{ // 403
		"status": "error",
		"msg":    "Misging Privelage",
	})
}

func errToString(err error) (errstring string) {
	if err != nil {
		errstring = fmt.Sprintf("%s", err)
	}
	return
}

// SetJsonHdr will set a content-type header to "application/json; charset=utf-8"
func SetJsonHdr(c *gin.Context) {
	c.Writer.Header().Set("Content-Type", "application/json; charset=utf-8")

}

/* vim: set noai ts=4 sw=4: */
