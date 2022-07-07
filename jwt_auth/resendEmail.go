package jwt_auth

import (
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/copier"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/gintools/email"
	"github.com/pschlump/gintools/log_enc"
	"github.com/pschlump/htotp"
	"github.com/pschlump/json"
)

type RvResendEmailRegisterType struct {
	StdErrorReturn
	UserId           *int   `json:"user_id,omitempty"`
	EmailVerifyToken string `json:"email_verify_token,omitempty"`
	Require2fa       string `json:"require_2fa,omitempty"`
	Secret2fa        string `json:"secret_2,omitempty"`
	URLFor2faQR      string `json:"url_for_2fa_qr"`
	TotpSecret       string `json:"totp_secret"`
	TmpToken         string `json:"tmp_token,omitempty"` // May be "" - used in 2fa part 1 / 2
}

// Input for api endpoint
type ApiAuthResendEmailRegister struct {
	Email     string `json:"email"      form:"email"       binding:"required,email"` // yes
	FirstName string `json:"first_name" form:"first_name"  binding:"required"`       // yes
	LastName  string `json:"last_name"  form:"last_name"   binding:"required"`       // yes
	Pw        string `json:"password"   form:"password"    binding:"required"`       // yes	-- used to validate resend of email?
}

type ResendEmailRegisterSuccess struct {
	Status      string `json:"status"`
	URLFor2faQR string `json:"url_for_2fa_qr"`
	TotpSecret  string `json:"totp_secret"`
	TmpToken    string `json:"tmp_token,omitempty"` // May be "" - used in 2fa part 1 / 2
}

func authHandleResendRegistrationEmail(c *gin.Context) {
	var err error
	var pp ApiAuthResendEmailRegister
	var RegisterResp RvResendEmailRegisterType
	if err := BindFormOrJSON(c, &pp); err != nil {
		return
	}

	var secret string
	secret = ""

	if IsXDBOn("authHandleRegister:error01") {
		RegisterResp.LogUUID = GenUUID()
		RegisterResp.Status = "error"
		RegisterResp.Msg = "Simulated Error"
		RegisterResp.Code = "0000"
		RegisterResp.Location = dbgo.LF()
		c.JSON(http.StatusBadRequest, logJsonReturned(RegisterResp.StdErrorReturn))
		return
	}

	//                                                 1             2             3                        4                     5                    6                            7
	// create or replace function q_auth_v1_resend_email_register ( p_email varchar, p_pw varchar, p_hmac_password varchar, p_first_name varchar, p_last_name varchar, p_userdata_password varchar, p_secret varchar )
	stmt := "q_auth_v1_resend_email_register ( $1, $2, $3, $4, $5, $6, $7 )"
	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF): %s\n", stmt)
	//                                                      1         2      3                        4             5            6                      7
	rv, err := CallDatabaseJSONFunction(c, stmt, "ee.ee..", pp.Email, pp.Pw, gCfg.EncryptionPassword, pp.FirstName, pp.LastName, gCfg.UserdataPassword, "")
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

	// ---------------------------------------------------------------------------------------------------------------------
	// send email with validation - using: RegisterResp.EmailVerifyToken
	// ---------------------------------------------------------------------------------------------------------------------
	// ConfirmEmailAccount(c, RegisterResp.EmailVerifyToken)

	email.SendEmail("welcome_registration", // Email Template
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

	RegisterResp.TotpSecret = secret                                     // 	if htotp.CheckRfc6238TOTPKeyWithSkew(username, pin2fa, RegisterResp.Secret2fa, 0, 1) {
	totp := htotp.NewDefaultTOTP(secret)                                 // totp := htotp.NewDefaultTOTP(RegisterResp.Secret2fa)
	QRUrl := totp.ProvisioningUri(pp.Email /*username*/, gCfg.AuthRealm) // otpauth://totp/issuerName:demoAccountName?secret=4S62BZNFXXSZLCRO&issuer=issuerName
	RegisterResp.URLFor2faQR = MintQRPng(c, QRUrl)

	var out ResendEmailRegisterSuccess
	copier.Copy(&out, &RegisterResp)
	c.JSON(http.StatusOK, logJsonReturned(out))
}
