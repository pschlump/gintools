package jwt_auth

import (
	"github.com/gin-gonic/gin"
	"github.com/pschlump/dbgo"
)

// -------------------------------------------------------------------------------------------------------------------------
// router.GET("/api/v1/auth/set-pii", authHandleSetPii) // (TODO) // waits on websocket to get confirm.
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
// @Success 200 {object} jwt_auth.ApiAuthLogin
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /v1/auth/set-pii [post]
func authHandleSetPii(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF)\n")
}

// -------------------------------------------------------------------------------------------------------------------------
// router.GET("/api/v1/auth/get-pii", authHandleGetPii) // (TODO) // waits on websocket to get confirm.
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
// @Success 200 {object} jwt_auth.ApiAuthLogin
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /v1/auth/get-pii [post]
func authHandleGetPii(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF)\n")
}
