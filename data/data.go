package data

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/pschlump/gintools/awss3v2"
	"github.com/pschlump/gintools/path_rewriter"
)

type QRConfig struct {
	QrBaseServerURL string `json:"qr_base_server_url" default:"http://localhost:8080/"`
	QrFilePath      string `json:"qr_file_path" default:"./www/qr/%{qr2%}/%{qrid10%}.%{qrext%}"`    // , "qr_file_path" : "./www/qr/%{ch2%}/%{qrid8%}.%{qrext%}"
	QrURLPath       string `json:"qr_url_path" default:"http://%{hostport%}/qr/%{qr2%}/%{qrid10%}"` // , "qr_url_path" : "./www/qr/%{ch2%}/%{qrid8%}"

	TemplateSearchPath       string `json:"template_search_path" default:"./tmpl/%{user_id%};./tmpl"`
	TemplateLocationHtmlTmpl string `json:"template_location_html_tmpl" default:"location.html.tmpl"`
}

type AppConfig struct {
	WWWStaticPath string   `json:"static_files" default:"./www"`
	HostPort      string   `json:"host_port" default:"http://127.0.0.1:2003"`
	DbFlags       []string `json:"db_flags"`

	EncryptionPassword     string `json:"encryption_password" default:"$ENV$QR_ENC_PASSWORD"`    // rv, err := SelectJson(stmt, pp.Un, pp.Pw, gCfg.EncryptionPassword)
	UserdataPassword       string `json:"userdata_password" default:"$ENV$QR_USERDATA_PASSWORD"` // rv, err := SelectJson(stmt, pp.Un, pp.Pw, gCfg.EncryptionPassword)
	LogEncryptionPassword  string `json:"log_encryption_password" default:"$ENV$QR_LOG_ENCRYPTION_PASSWORD"`
	FileEncryptionPassword string `json:"file_encryption_password" default:"$ENV$QR_UPLOAD_FILE_PASSWORD"`
	EtagPassword           string `json:"etag_password" default:"$ENV$QR_ETAG_PASSWORD"`
	PdfPassword            string `json:"pdf_password" default:"$ENV$PDF_ENC_PASSWORD"`

	UseLogEncryption string `json:"use_log_encryption" default:"dev-dummy"` // no, yes, dev-dummy, "b64-dummy"

	// AuthRealm          string `json:"auth_realm" default:"example.com"`					// in base class

	TokenHeaderVSCookie string `json:"token_header_vs_cookie" default:"both"` // cookie, both, header

	PdfCpu   string `json:"pdfcpu" default:"/Users/philip/bin/pdfcpu"` // path tp pdfcpu command.
	PdfToPPM string `json:"pdftoppm" default:"./cd-pdftoppm.sh"`       // path tp shell script that runs cd then, pdftoppm command.

	SimulatedErrorPassword string `json:"simulated_error_password" default:"$ENV$SIMULATED_ERROR_PASSWORD"`

	GitRevision string `json:"git_revision" default:"$ENV$GIT_AN_APP_SERVER_REVISION"`

	UseFingerprint   string `json:"UseFingerprint" default:"no"`   // , "UseFingerprint" :"yes"
	ExpireAuthTokens string `json:"ExpireAuthTokens" default:"30"` //
}

type ThumbnailType struct {
	ThumbnailPath    string `json:"thumbnail_path" default:"./www/thumb"`
	ThumbnailPathURL string `json:"thumbnail_path_url" default:"/thumb"`
	ImagePath        string `json:"image_path" default:"./www/files"` // same as upload path?
	ImagePathURL     string `json:"image_url" default:"/files"`       // same as url_upload_path
}

type PathRewrite struct {
	RewriteList map[string]string `json:"path_rewrite"`
}

type FontConfig struct {
	FontPathFile string `json:"font_path_file" default:"/Users/philip/go/src/github.com/golang/freetype/testdata/luxisr.ttf"`
}

type EthConfigData struct {
	URL_8545        string            `json:"geth_rpc_8545" default:"http://127.0.0.1:7545"`      // example: "http://192.168.0.200:8545".
	ContractAddress map[string]string `json:"ContractAddress"`                                    // Contract names to contract addresses map
	FromAddress     string            `json:"FromAddress"`                                        // Address of account to pull funds from - this is the signing account
	KeyFilePassword string            `json:"key_file_password" default:"$ENV$Key_File_Password"` // Password to access KeyFile
	KeyFile         string            `json:"key_file" default:"$ENV$Key_File"`                   // File name for pub/priv key for Address
	UseEth          string            `json:"UseEth" default:"yes"`                               // Direclty call contract 'yes'

	Client *ethclient.Client `json:"-"` // used in secalling contract

	AccountKey *keystore.Key `json:"-"`
}

type GlobalConfigData struct {
	BaseConfigType
	QRConfig
	AppConfig
	path_rewriter.PathRewriteType
	UploadConfig
	awss3v2.AwsS3Cfg
	PathRewrite
	FontConfig
	ThumbnailType
	EthConfigData

	ItemAppURI string `json:"item_app_uri" default:"item_app"`
}

type UploadConfig struct {
	UploadPath    string `json:"upload_path" default:"./www/files"`
	URLUploadPath string `json:"url_upload_path" default:"/files"`

	PushToAWS string `json:"push_to_aws" default:"yes"`

	S3Perms string `json:"s3_perms" defaulit:"private"`
}

// This file is BSD 3 Clause licensed.

//	AuthJWTSource            string `json:"auth_jwt_source" default:"Authorization"`                                             // Valid forms for getting authorization		--- DEPRICATED
// if len(gCfg.JwtKey) == 0 && jwtlib.IsHs(gCfg.AuthJWTKeyType) {
// change JwtKey to  AuthJWTKey

type BaseConfigType struct {
	LogMode     string `json:"log_mode" default:"dev"`         // dev or prod
	ReleaseMode string `json:"release_mode" default:"release"` // dev or release

	// do not change - do not edit next line.
	Status string `json:"status" default:"success"`

	// Redis Connection Info
	RedisConnectHost string `json:"redis_host" default:"$ENV$REDIS_HOST"`
	RedisConnectAuth string `json:"redis_auth" default:"$ENV$REDIS_AUTH"`
	RedisConnectPort string `json:"redis_port" default:"6379"`
	RedisUsePubSub   string `json:"redis_use_pub_sub" default:"no"`

	TickerSeconds int `json:"ticker_seconds" default:"30"` // Time Ticker Seconds

	// connect to Postgres Stuff (or other database) --------------------------------------------------------------------------------------------------------------------------------
	DBType          string `json:"db_type" default:"$ENV$DB_TYPE=postgresql"` // postgresql, sqlite3, mariadb, oracle, mysql
	DBHost          string `json:"db_host" default:"$ENV$PG_HOST=127.0.0.1"`
	DBPort          int    `json:"db_port" default:"$ENV$PG_PORT=5432"`
	DBUser          string `json:"db_user" default:"$ENV$PG_USER=pschlump"`
	DBPassword      string `json:"db_password" default:"$ENV$PG_AUTH"`
	DBName          string `json:"db_name" default:"$ENV$PG_DBNAME=pschlump"`
	DBSSLMode       string `json:"db_sslmode" default:"$ENV$PG_SSLMODE=disable"`
	DBConnectString string `json:"db_connect_string" default:"$ENV$POSTGRES_CONN"`
	// connect to SQLite3, the file name to use
	// connect to MariaDB/mySQL, full connect string
	// Full connect string instead of "above
	// DBConnectString string `json:"connect_to_database" default:"$ENV$ConnectToDatabase"`
	// End Connect Stuff -------------------------------------------------------------------------------------------------------------------------------------------------------------

	LogFileName        string `json:"log_file_name"`
	EmailLogFileName   string `json:"email_log_file_name" default:"./log/email-log.out"`
	EmailTickerSeconds int    `json:"email_ticker_seconds" default:"60"` // Time Ticker Seconds

	// Auth Related Stuff ------------------------------------------------------------------------------------------------------------------------------------------------------------
	AuthRealm                string `json:"auth_realm" default:"*" pgsave:"AuthRealm"`                                //
	AuthJWTPublic            string `json:"auth_jwt_public_file" default:""`                                          // Public Key File
	AuthJWTPrivate           string `json:"auth_jwt_private_file" default:""`                                         // Private Key File
	AuthJWTKeyType           string `json:"auth_jwt_key_type" default:"HS256"`                                        // Key type ES = ESDSA or RS = RSA
	AuthJWTKey               string `json:"jwt_key_password" default:"$ENV$QR_JWT_KEY"`                               //
	AuthApplicationName      string `json:"auth_application_name" default:"Simple Auth"`                              // Name of applicaiton for use in templates
	AuthPasswordRecoveryURI  string `json:"auth_password_recovery_uri" default:"forgotten-password/web-set-password"` // Path inside app to the form that changes a password
	AuthConfirmEmailURI      string `json:"auth_confirm_email_uri" default:"regPt2-confirm"`                          // Redirect to this URI for info on confirming email.
	AuthConfirmEmailErrorURI string `json:"auth_confirm_email_error_uri" default:"regPt2-error"`                      // Redirect to this URI for info on confirming email.
	AuthEmailToken           string `json:"auth_email_token" default:"uuid"`                                          // "uuid"|"n6" - if n6 then a 6 digit numer is used.

	// UseRegistrationToken string `json:"use_registration_token" default:"yes" pgsave:"UseRegistrationToken"` //
	// End Auth realted -------------------------------------------------------------------------------------------------------------------------------------------------------------

	// CORS Related Stuff -----------------------------------------------------------------------------------------------------------------------------------------------------------
	CORSTag               string `json:"CORS_tag" default:"<body>"`                    // Tag to replace in index.html
	CORSNDays             int    `json:"CORS_n_days" default:"365"`                    // How long to keep a CORS tag before invalidating it.
	CORSRedisStorageKey   string `json:"CORS_redis_storage_key" default:"csrf-token:"` // Prefix used in Redis for keys
	CSRFIndexHtmlFileName string `json:"CORS_index_file_name" default:"/index.html"`   // file to read/reaturn

	// End CORS Related Stuff -------------------------------------------------------------------------------------------------------------------------------------------------------

	RedirectEmailSendTo string   `json:"redirect_email_send_to"` // If set this sends all outgoing email to a test account.
	NoEmailSendList     []string `json:"no_email_send_list"`     // List to not send email to for testing purposes
	NoEmailSendListRe   []string `json:"no_email_send_list_re"`  // regular expresison List to not send email to for testing purposes

	// debug flags:	 Comma seperated values in the config file.
	DebugFlag string `json:"db_flag"`

	// Defauilt file for TLS setup (Shoud include path), both must be specified.
	// These can be over ridden on the command line.
	TLS_crt string `json:"tls_crt" default:""`
	TLS_key string `json:"tls_key" default:""`

	// S3 login/config options.
	// Also uses
	//		AWS_ACCESS_KEY_ID=AKIAJZ...........VWA		((example))
	//		AWS_SECRET_KEY=........
	S3_bucket string `json:"s3_bucket" default:"s3://documents"`
	S3_region string `json:"s3_region" default:"$ENV$AWS_REGION"`

	// Path where files are temporary uploaded to
	// Also where bulk load will pull input:__file_name__ from
	// Moved to ../UploadFile
	// UploadPath    string `json:"upload_path" default:"./www/files"`
	// URLUploadPath string `json:"url_upload_path" default:"/files"`
	// UploadTable   string `json:"upload_table" default:"document"`

	// Path for static files
	StaticPath string `json:"static_path" default:"www"`

	// JS/HTML can be templated to produce a configuration
	// var URLRegister = "http://127.0.0.1:9019/api/session/register_immediate";
	// var URLRegister = "http://www.simple-auth.com:9019/api/session/register_immediate";
	TemplateDir         string `default:"./tmpl"`
	TemplatedFiles      string `default:"/js/x-config.js"`
	URL__Auth__Register string `json:"URL__Auth__Register" default:"$ENV$URL__Auth__Register"`

	// Authentication configuration items
	// AppliationMainPage string `json:"main_uri" default:"/index.html"`
	EmailTmplDir     string `json:"email_template_dir" default:"./tmpl"`
	EmailFromName    string `json:"email_from_name" default:"Authentication"`
	EmailFromAddress string `json:"email_from_address" default:"pschlump@gmail.com"`
	EmailSender      string `json:"email_sender" default:"sendgrid"`

	UseRolePriv string `json:"use_role_priv" default:"yes"`

	CachForPwned string `json:"cache_for_pwned" default:"./pwned_cache"`

	BaseServerURL string `json:"base_server_url" default:"http://www.erc777.com/"`

	// BusinessAuthToken string `json:"business_auth_token" default:"no"` // Not implemented yet - jsut read in.  Requires a "auth-token" for user to register.

	EmailRegistrationToken string `json:"email_registration_token" default:"no"`

	// xyzzy TODO - encrypt IsSecret values into log file using following key
	LogFileEncryptionKey string `json:"log_file_encryption_key" default:"$ENV$LOG_ENCRYPTION_KEY"`

	DB_Enc_Key string `json:"DB_Enc_Key" default:"$ENV$DB_ENC_KEY"`
	DB_IV_Data string `json:"DB_IV_Data" default:"$ENV$DB_ENC_IV_DATA"`

	CSRF_Token string `json:"CSRF_Token" default:"X-CSRF-Token"`

	CORS_Allowed    bool `json:"CORS_Allowed" default:"true"`     // see set_header.go
	CORS_CheckTable bool `json:"CORS_CheckTable" default:"false"` // if false then all CORS are allowed. -- See set_header.go

}

type GlobalDataScopeType struct {
	Bob string
	Id  uint64
}

type ParsedInputType struct {
	StateVars      map[string]string // Per connection state vars, __user_id__ etc. -- Per LOGIN/Browser
	SavedStateVars map[string]string // uses cookie on client to save a set of state vars to d.b. -> g_quth_saved_state table -- Per USER STATE!
}
