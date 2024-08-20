package jwt_auth

// Copyright (c) Philip Schlump, 2016-2018.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/copier"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/gintools/log_enc"
	"github.com/pschlump/htotp"
	"github.com/pschlump/json"
)

// SIP : rfc8235 based
/*
	router.POST("/api/v1/auth/sip-login-pt0", authHandleSip0Login)                                               // Prover(client) -> Validator(server): Commitment
	router.POST("/api/v1/auth/sip-login-pt1", authHandleSip1Login)                                               // Validator(server) -> Prover(client): Challenge
	router.POST("/api/v1/auth/sip-login-pt2", authHandleSip2Login)                                               // Prover(client) -> Validator(server): responce(proof)
	router.POST("/api/v1/auth/sip-change-password", LoginRequired(authHandleSipChangePassword))                  // change passwword
	router.POST("/api/v1/auth/sip-change-password-admin", LoginRequired(authHandleSipChangePasswordAdmin))       //
	router.POST("/api/v1/auth/sip-recover-password-01-setup", authHandleRecoverSipPassword01Setup)               //
	router.POST("/api/v1/auth/sip-recover-password-02-fetch-info", authHandleSipRecoverPassword02FetchInfo)      //
	router.POST("/api/v1/auth/sip-recover-password-03-new-validator", authHandleSipRecoverPassword03SetPassword) // Change Password
*/

type ApiAuthSipRegister struct {
	Email     string `json:"email"      form:"email"       binding:"required,email"`
	FirstName string `json:"first_name" form:"first_name"  binding:"required"`
	LastName  string `json:"last_name"  form:"last_name"   binding:"required"`
	Validator string `json:"validator"  form:"validator"   binding:"required"`
}

// authHandleRegister godoc
// @Summary Register a user to use SIP (Schnor Idendenty Protocal) - Part 1 before 2FA pin and email validation.  Part 2 and 3 are the email conformation and the use of the 6 digit 2fa pin.
// @Schemes
// @Description Call will create a new user.
// @Tags auth
// @Accept json,x-www-form-urlencoded
// @Param   email       formData    string     true        "Email Address"
// @Param   first_name  formData    string     true        "First Name"
// @Param   last_name   formData    string     true        "Last Name"
// @Param   validator   formData    string     true        "Calcualted Validation Value"
// @Produce json
// @Success 200 {object} jwt_auth.RegisterSuccess
// @Failure 400 {object} jwt_auth.StdErrorReturn
// @Failure 401 {object} jwt_auth.StdErrorReturn
// @Failure 406 {object} jwt_auth.StdErrorReturn
// @Failure 500 {object} jwt_auth.StdErrorReturn
// @Router /api/v1/auth/sip-register [post]
func authHandleSipRegister(c *gin.Context) {
	var err error
	var pp ApiAuthSipRegister
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}
	// perReqLog := tf.GetLogFilePtr(c)

	secret := GenerateSecret()

	//                                                     1                2                    3                        4                     5                    6                            7
	// create or replace function q_auth_v1_sip_register ( p_email varchar, p_validator varchar, p_hmac_password varchar, p_first_name varchar, p_last_name varchar, p_userdata_password varchar, p_secret varchar )
	stmt := "q_auth_v1_sip_register ( $1, $2, $3, $4, $5, $6, $7 )"
	dbgo.Fprintf(logFilePtr, "In handler at %(LF): %s\n", stmt)
	//                                                      1            2          3                        4             5            6                      7
	rv, err := CallDatabaseJSONFunction(c, stmt, "ee.ee..", pp.Email, pp.Validator, aCfg.EncryptionPassword, pp.FirstName, pp.LastName, aCfg.UserdataPassword, secret)
	if err != nil {
		return
	}
	dbgo.Fprintf(logFilePtr, "%(LF): rv=%s\n", rv)
	var RegisterResp RvRegisterType
	err = json.Unmarshal([]byte(rv), &RegisterResp)
	if RegisterResp.Status != "success" {
		RegisterResp.LogUUID = GenUUID()
		log_enc.LogStoredProcError(c, stmt, "ee!ee!!", "xyzzyPerUserPw", SVar(RegisterResp), pp.Email, pp.Validator /*aCfg.EncryptionPassword,*/, pp.FirstName, pp.LastName /*, aCfg.UserdataPassword*/, secret) // xyzzy - Encrypted Log File Data
		c.JSON(http.StatusBadRequest, RegisterResp.StdErrorReturn)
		return
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
		"first_name", pp.FirstName,
		"last_name", pp.LastName,
		"token", RegisterResp.EmailVerifyToken,
		"user_id", RegisterResp.UserId,
		"server", gCfg.BaseServerURL,
		"application_name", gCfg.AuthApplicationName,
		"realm", gCfg.AuthRealm,
	)

	// ---------------------------------------------------------------------------------------------------------------------
	// setup the QR code and link for 2fa tool
	// ---------------------------------------------------------------------------------------------------------------------

	// 	if htotp.CheckRfc6238TOTPKeyWithSkew(username, pin2fa, RegisterResp.Secret2fa, 0, 1) {
	RegisterResp.TotpSecret = secret
	totp := htotp.NewDefaultTOTP(secret) // totp := htotp.NewDefaultTOTP(RegisterResp.Secret2fa)
	QRUrl := totp.ProvisioningUri(pp.Email /*username*/, gCfg.AuthRealm)
	RegisterResp.URLFor2faQR = MintQRPng(c, QRUrl)

	var out RegisterSuccess
	copier.Copy(&out, &RegisterResp)
	c.JSON(http.StatusOK, out)
}

// -------------------------------------------------------------------------------------------------------------------------
// Must return a "tmp_token" that has the "commitment" associated with it.

/*
CREATE TABLE if not exists q_qr_tmp_token (
	tmp_token_id 		serial primary key not null,
	user_id 			int not null,
	token			 	uuid not null,
	sip_x				text,
	expires 			timestamp not null
);
*/

type ApiAuthSipLogin0 struct {
	Email      string `json:"email"       form:"email"        binding:"required,email"`
	Commitment string `json:"commitment"  form:"commitment"   binding:"required"` // this is the 'x' value, the random from the client.
}

type SipLogin0Success struct {
	Status     string `json:"status"`
	TmpToken   string `json:"tmp_token,omitempty"`
	Challenge  string `json:"challenge,omitempty"`
	Require2fa string `json:"require_2fa,omitempty"`
	Privileges string `json:"privileges,omitempty"`
	FirstName  string `json:"first_name,omitempty"`
	LastName   string `json:"last_name,omitempty"`
}

func authHandleSip0Login(c *gin.Context) {
	// TODO
}

// -------------------------------------------------------------------------------------------------------------------------
type SipLogin1Success struct {
	Status    string `json:"status"`
	TmpToken  string `json:"tmp_token,omitempty"`
	Challenge string `json:"challenge,omitempty"`
}

func authHandleSip1Login(c *gin.Context) {
	// TODO
}

// -------------------------------------------------------------------------------------------------------------------------
type SipLogin22uccess struct {
	Status   string `json:"status"`
	TmpToken string `json:"tmp_token,omitempty"`
	Proof    string `json:"proof,omitempty"`
}

func authHandleSip2Login(c *gin.Context) {
	// TODO
}

/* vim: set noai ts=4 sw=4: */
