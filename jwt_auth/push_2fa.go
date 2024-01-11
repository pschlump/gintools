package jwt_auth

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"github.com/gin-gonic/gin"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/gintools/tf"
)

// xyzzyPush2faCode -- Send 2fa to Email/SMS (for login) - bad.

// -------------------------------------------------------------------------------------------------------------------------
// xyzzyPush2faCode
// router.GET("/api/v1/auth/push-2fa-code-to-email", authHandle2faCodeToEmail)         // (TODO) // send 2fa to mail for confirm
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
// @Router /api/v1/auth/push-2fa-code-to-email [post]
func authHandle2faCodeToEmail(c *gin.Context) {
	dbgo.Fprintf(logFilePtr, "In handler at %(LF)\n")
}

// -------------------------------------------------------------------------------------------------------------------------
// xyzzyPush2faCode
// router.GET("/api/v1/auth/push-2fa-client-app-confirm", authHandle2faClientAppConfirm) // (TODO) // waits on websocket to get confirm.
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
// @Router /api/v1/auth/pust-2fa-client-app-confirm [post]
func authHandle2faClientAppConfirm(c *gin.Context) {
	perReqLog := tf.GetLogFilePtr(c)
	dbgo.Fprintf(perReqLog, "In handler at %(LF)\n")
}

/* vim: set noai ts=4 sw=4: */
