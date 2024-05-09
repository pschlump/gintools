package jwt_auth

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/pschlump/HashStrings"
	"github.com/pschlump/dbgo"
)

func ValidateHmacAuthKey(c *gin.Context, AuthKey string) bool {

	// pw := os.Getenv("TEST_SEND_EMAIL_PASSWORD")
	pw := gCfg.TestSendEmailPassword
	if pw == "" {
		dbgo.DbFprintf("db.ValidateHmacAuthKey", os.Stderr, "%(red)Requires TEST_SEND_EMAIL_PASSWORD to be set %(LF)\n")
		dbgo.Fprintf(logFilePtr, "Requires TEST_SEND_EMAIL_PASSWORD to be set %(LF), %s\n", dbgo.LF(-2))
		if c != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"status":   "error",
				"msg":      "Must be have correct HMAC key/password.",
				"location": dbgo.LF(),
			})
		}
		return false
	}

	// To Generate the HMAC auth key, See: ../gen-email-key or $tools/tools/gen-email-key
	if HashStrings.HashStrings(pw+AuthKey) != "2572640f43d8b184d14c2b7f0d255a752fd4c3d674dba969046d5c611d47b8d5" {

		dbgo.DbFprintf("db.ValidateHmacAuthKey", os.Stderr, "%(red)Requires AuthKey to be valid %(LF) --\nSee ~/.secret/setup.sh or run generation tool ../gen-email-key/gen-email-key.go\n    ->%s<-\n    Desired HMAC is: ->%s<-\n", AuthKey, "2572640f43d8b184d14c2b7f0d255a752fd4c3d674dba969046d5c611d47b8d5")
		dbgo.Fprintf(logFilePtr, "Requires AuthKey to be valid %(LF), %s --\nSee ~/.secret/setup.sh or run generation tool ../gen-email-key/gen-email-key.go\n    ->%s<-\n    Desired HMAC is: ->%s<-\n", dbgo.LF(-2), AuthKey, "2572640f43d8b184d14c2b7f0d255a752fd4c3d674dba969046d5c611d47b8d5")
		if c != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"status":   "error",
				"msg":      "Must be have correct HMAC key to access set the SendTestEmailHandler interface.",
				"location": dbgo.LF(),
			})
		}
		return false
	}

	dbgo.DbFprintf("db.SendTestEmailHandler", os.Stderr, "%(green)Have valid AuthKey value (should have been authenticated also) %(LF)\n")

	return true
}

// xyzzyFailedToGptSvr -- in front end www/index.js
func ValidateHmacForError() bool {

	AuthKey := gCfg.ErrorPassword
	pw := gCfg.TestSendEmailPassword // pw := os.Getenv("TEST_SEND_EMAIL_PASSWORD")
	if pw == "" {
		dbgo.DbFprintf("db.ValidateHmacAuthKey", os.Stderr, "%(red)Requires TEST_SEND_EMAIL_PASSWORD to be set %(LF)\n")
		dbgo.Fprintf(logFilePtr, "Requires TEST_SEND_EMAIL_PASSWORD to be set %(LF), %s\n", dbgo.LF(-2))
		return false
	}

	// To Generate the HMAC auth key, See: ../gen-email-key or $tools/tools/gen-email-key
	if HashStrings.HashStrings(pw+AuthKey) != "2572640f43d8b184d14c2b7f0d255a752fd4c3d674dba969046d5c611d47b8d5" {

		dbgo.DbFprintf("db.ValidateHmacAuthKey", os.Stderr, "%(red)Requires AuthKey to be valid %(LF) --\nSee ~/.secret/setup.sh or run generation tool ../gen-email-key/gen-email-key.go\n    ->%s<-\n    Desired HMAC is: ->%s<-\n", AuthKey, "2572640f43d8b184d14c2b7f0d255a752fd4c3d674dba969046d5c611d47b8d5")
		dbgo.Fprintf(logFilePtr, "Requires AuthKey to be valid %(LF), %s --\nSee ~/.secret/setup.sh or run generation tool ../gen-email-key/gen-email-key.go\n    ->%s<-\n    Desired HMAC is: ->%s<-\n", dbgo.LF(-2), AuthKey, "2572640f43d8b184d14c2b7f0d255a752fd4c3d674dba969046d5c611d47b8d5")
		return false
	}

	dbgo.DbFprintf("db.SendTestEmailHandler", os.Stderr, "%(green)Have valid AuthKey value (should have been authenticated also) %(LF)\n")

	return true
}

/* vim: set noai ts=4 sw=4: */
