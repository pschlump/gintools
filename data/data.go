package data

import (
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
	JwtKey                 string `json:"jwt_key_password" default:"$ENV$QR_JWT_KEY"`
	LogEncryptionPassword  string `json:"log_encryption_password" default:"$ENV$QR_LOG_ENCRYPTION_PASSWORD"`
	FileEncryptionPassword string `json:"file_encryption_password" default:"$ENV$QR_UPLOAD_FILE_PASSWORD"`
	EtagPassword           string `json:"etag_password" default:"$ENV$QR_ETAG_PASSWORD"`
	PdfPassword            string `json:"pdf_password" default:"$ENV$PDF_ENC_PASSWORD"`

	UseLogEncryption string `json:"use_log_encryption" default:"dev-dummy"` // no, yes, dev-dummy, "b64-dummy"

	// AuthRealm          string `json:"auth_realm" default:"example.com"`					// in base class

	NoEmailSendList     []string `json:"no_email_send_list"`                    // List to not send email to for testing purposes
	TokenHeaderVSCookie string   `json:"token_header_vs_cookie" default:"both"` // cookie, both, header

	PdfCpu string `json:"pdfcpu" default:"/Users/philip/bin/pdfcpu"` // path tp pdfcpu command.

	SimulatedErrorPassword string `json:"simulated_error_password" default:"$ENV$SIMULATED_ERROR_PASSWORD"`

	GitRevision string `json:"git_revision" default:"$ENV$GIT_TCS_APP_SERVER_REVISION"`
}

type PathRewrite struct {
	RewriteList map[string]string `json:"path_rewrite"`
}

type GlobalConfigData struct {
	BaseConfigType
	QRConfig
	AppConfig
	path_rewriter.PathRewriteType
	UploadConfig
	awss3v2.AwsS3Cfg
	PathRewrite
}

type UploadConfig struct {
	UploadPath    string `json:"upload_path" default:"./www/files"`
	URLUploadPath string `json:"url_upload_path" default:"/files"`

	PushToAWS string `json:"push_to_aws" default:"yes"`

	S3Perms string `json:"s3_perms" defaulit:"private"`
}

// This file is BSD 3 Clause licensed.

type BaseConfigType struct {
	Mode string `json:"mode" default:"prod"`

	// do not change - do not edit next line.
	Status string `json:"status" default:"success"`

	// Add in Redis stuff
	RedisConnectHost string `json:"redis_host" default:"$ENV$REDIS_HOST"`
	RedisConnectAuth string `json:"redis_auth" default:"$ENV$REDIS_AUTH"`
	RedisConnectPort string `json:"redis_port" default:"6379"`

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

	LogFileName      string `json:"log_file_name"`
	EmailLogFileName string `json:"email_log_file_name" default:"./log/email-log.out"`

	// Auth Related Stuff ------------------------------------------------------------------------------------------------------------------------------------------------------------
	AuthRealm                string `json:"auth_realm" default:"*" pgsave:"AuthRealm"`                                           //
	Auth2faEnabled           string `json:"auth_2fa_enabled" default:"no" pgsave:"Auth2faEnabled"`                               //
	UseEmailConfirm          string `json:"use_email_confirm" default:"no" pgsave:"UseEmailConfirm"`                             //
	AuthLoginOnRegister      string `json:"auth_login_on_register" default:"no" pgsave:"AuthLoginOnRegister"`                    //
	UseRegistrationToken     string `json:"use_registration_token" default:"yes" pgsave:"UseRegistrationToken"`                  //
	UseTOTPSkew              int    `json:"use_totp_skew" default:"1" pgsave:"UseTOTPSkew"`                                      //
	AuthMethod               string `json:"auth_method" default:"key" validate:"v.In(['key','jwt'])" pgsave:"AuthMethod"`        // key or jwt for the moment
	AuthKey                  string `json:"auth_key" default:""`                                                                 //
	AuthJWTPublic            string `json:"auth_jwt_public_file" default:""`                                                     // Public Key File
	AuthJWTPrivate           string `json:"auth_jwt_private_file" default:""`                                                    // Private Key File
	AuthJWTKeyType           string `json:"auth_jwt_key_type" default:"ES" validate:"v.In(['ES256','RS256', 'ES512', 'RS512'])"` // Key type ES = ESDSA or RS = RSA
	AuthJWTSource            string `json:"auth_jwt_source" default:"Authorization"`                                             // Valid forms for getting authorization
	AuthTokenValidate        string `json:"auto_token_validate" default:"no"`                                                    //
	AuthTokenURI             string `json:"auth_token_uRI" default:"http://127.0.0.1:9019/api/admin/validate-token"`             //
	AuthTokenLifetime        int    `json:"auth_token_lifetime" default:"3640" pgsave:"AuthTokenLifetime"`                       // Lifetime is in seconds - this is under 1 hour (3600 is hour)
	AuthEmailConfirm         string `json:"auth_email_confirm" default:"yes" pgsave:"AuthEmailConfirm"`                          //
	Auth2faSetupApp          string `json:"auth_2fa_setup_app" default:"http://2fa.simple-auth.com/setup.html"`                  // xyzzy - should be 192.154.97.75 2fa.simple-auth.com			// {{.base_server_url}}/setup.html
	Auth2faAppNoEmail        string `json:"auth_2fa_app_no_email" default:"http://2fa.simple-auth.com/app.html"`                 // xyzzy - should be 192.154.97.75 2fa.simple-auth.com			// {{.base_server_url}}/index.html
	AuthSelfURL              string `json:"auth_self_url" default:"http://2fa.simple-auth.com"`                                  // where to call to get info on this user.						// {{.base_server_url}}
	AuthQrURL                string `json:"auth_qr_url" default:"{{.BaseServerUrl}}"`                                            // where to call to QR images painted
	AuthApplicationName      string `json:"auth_application_name" default:"Simple Auth"`                                         // Name of applicaiton for use in templates
	AuthRedirect2faSetupPage string `json:"auth_redirect_2fa_setup_page" default:"/2fa-setup-page.html"`                         // page to redirect to when 2fa setup is used.
	// End Auth realted -------------------------------------------------------------------------------------------------------------------------------------------------------------

	// CORS Related Stuff ------------------------------------------------------------------------------------------------------------------------------------------------------------
	CORSTag               string `json:"CORS_tag" default:"<body>"`                    // Tag to replace in index.html
	CORSNDays             int    `json:"CORS_n_days" default:"365"`                    // How long to keep a CORS tag before invalidating it.
	CORSRedisStorageKey   string `json:"CORS_redis_storage_key" default:"csrf-token:"` // Prefix used in Redis for keys
	CSRFIndexHtmlFileName string `json:"CORS_index_file_name" default:"/index.html"`   // file to read/reaturn

	// End CORS Related Stuff ------------------------------------------------------------------------------------------------------------------------------------------------------------

	// debug flags:	 Comma seperated values in the config file.
	// 	 test-http-end-points			Turn on extra end-points for testing code.   Tests are in Makefile.
	//	 dump-db-flag				  	Print out the db flags that are set.
	//   GetVal							Echo variables that are fetched.
	//   RedisClient					Report on connedtion to Redis
	//   Cli.Where						Dump out where the writes to the output http buffer occure.
	//   Cli.Write
	//   cli
	//   test-print-command-success
	// From MonAliveLib
	// 		MonAliveLib.report-config	Reprot if defauilt config is used.
	DebugFlag string `json:"db_flag"`

	// xyzzy - Demo Mode - xyzzy
	// URL := "http://www.2c-why.com/Ran/RandomValue"
	RandomOracleURL string `json:"random_oracle_url" default:"http://www.2c-why.com/Ran/RandomValue"`

	// 1. template(s) for ./desc.html -> ./tmpl/desc.html.tmpl
	DescHtmlTemplate string `json:"desc_html_tmpl" default:"./tmpl/desc.html.tmpl"`
	DocMdFile        string `json:"doc_md" default:"./tmpl/api-doc.md"`

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

	// Remote validation of "auth_token" from JWT Token.
	RemoteAuthServer       string `json:"remote_auth_server" default:"http://www.simple-auth.com:9019"`
	RemoteAuthGetTokenInfo string `json:"remote_auth_server" default:"http://www.simple-auth.com:9019/api/v1/get-token-info"`
	RemoteAuthTTL          int    `json:"remote_auth_ttl" default:"120"`                  // In seconds
	RemoteAuthKey          string `json:"remote_auth_ttl" default:"$ENV$SIMPLE_AUTH_KEY"` // In seconds

	// JS/HTML can be templated to produce a configuration
	// var URLRegister = "http://127.0.0.1:9019/api/session/register_immediate";
	// var URLRegister = "http://www.simple-auth.com:9019/api/session/register_immediate";
	TemplateDir         string `default:"./tmpl"`
	TemplatedFiles      string `default:"/js/x-config.js"`
	URL__Auth__Register string `json:"URL__Auth__Register" default:"$ENV$URL__Auth__Register"`

	JWTUsed            bool
	URL__JWT__Validate string `json:"URL__JWT__Validate" default:"$ENV$URL__JWT__Validate"`
	JWT_KeyFile        string `json:"jwt_key_file_dir" default:"./test-key"`
	JWT_Ecdsa          string `json:"jwt_ecdsa" default:"no"` // using RSA until figure out how to sign ecdsa for test
	JWT_RSA            string `json:"jwt_rsa" default:"yes"`

	// Authentication configuration items
	PasswordResetPage string `json:"password_reset_uri" default:"/password_reset.html?token={{.token}}"`

	// Authentication configuration items
	AppliationMainPage       string `json:"main_uri" default:"/index.html"`
	ImmediateLoginOnRegister string `json:"immediate_login_on_register" default:"yes"`
	EmailTmplDir             string `json:"email_template_dir" default:"./tmpl"`
	EmailFromName            string `json:"email_from_name" default:"Authentication"`
	EmailFromAddress         string `json:"email_from_address" default:"pschlump@gmail.com"`
	RFC6238_2fa_on           string `json:"rfc_6238_2fa_on" default:"no"`
	RFC6238_2fa_NDigits      int    `json:"rfc_6238_2fa_n_digits" default:"6"`
	RFC6238_RedisKey         string `json:"rfc_6238_redi_key" default:"qr2fa:"`
	RFC6238_QR_TTL           int    `json:"rfc_6238_ttl" default:"172800"` // 2 days = 24 * 60 * 60 * 2
	Use14DayCookie           string `json:"use_14_day_cookie" default:"yes"`
	// see also: insert into "t_ymux_config" ( "name", "ty", "value", "i_value" ) values ( 'rfc_6238_n_digits', 'i', '6', 6 );
	// TableAuthToken           string `json:"table_auth_token" default:"t_auth_token"`
	// TableUser                string `json:"table_user" default:"t_user"`

	UseRolePriv string `json:"use_role_priv" default:"yes"`

	CachForPwned string `json:"cache_for_pwned" default:"./pwned_cache"`

	BaseServerUrl string `json:"base_server_url" default:"http://www.2c-why.com"` // urlBase := "http://www.q8s.com"

	// xyzzy - Demo Mode - xyzzy
	DemoFlag       string `json:"demo_flag" default:"no"` // if "yes" then in demo mode. CSV value, yes,RandomOracle,2FA,Login,QRCode,Geth
	demoProcessed  bool
	demoFlag       bool
	demoComponents map[string]bool

	BusinessAuthToken string `json:"business_auth_token" default:"no"` // Not implemented yet - jsut read in.  Requires a "auth-token" for user to register.

	EmailRegistrationToken string `json:"email_registration_token" default:"no"`

	// xyzzy TODO - encrypte IsSecret values into log file using following key
	LogFileEncryptionKey string `json:"log_file_encryption_key" default:"$ENV$LOG_ENCRYPTION_KEY"`

	DB_Enc_Key string `json:"DB_Enc_Key" default:"$ENV$DB_ENC_KEY"`
	DB_IV_Data string `json:"DB_IV_Data" default:"$ENV$DB_ENC_IV_DATA"`

	CSRF_Token string `json:"CSRF_Token" default:"X-CSRF-Token"`

	CORS_Allowed    bool `json:"CORS_Allowed" default:"true"`     // see set_header.go
	CORS_CheckTable bool `json:"CORS_CheckTable" default:"false"` // if false then all CORS are allowed. -- See set_header.go

	LogMode string `json:"log_mode" default:"dev"` // dev or prod
}

type GlobalDataScopeType struct {
	Bob string
	Id  uint64
}

type ParsedInputType struct {
	StateVars      map[string]string // Per connection state vars, __user_id__ etc. -- Per LOGIN/Browser
	SavedStateVars map[string]string // uses cookie on client to save a set of state vars to d.b. -> g_quth_saved_state table -- Per USER STATE!
}
