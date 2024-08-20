package jwt_auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/copier"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/gintools/callme"
	"github.com/pschlump/gintools/data"
	"github.com/pschlump/gintools/log_enc"
	"github.com/pschlump/gintools/tf"
	"github.com/pschlump/names"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/oauth2"
)

// return an HTTP client which trusts the provided root CAs.
func httpClientForRootCAs(rootCAs string) (*http.Client, error) {
	tlsConfig := tls.Config{RootCAs: x509.NewCertPool()}
	rootCABytes, err := os.ReadFile(rootCAs)
	if err != nil {
		return nil, fmt.Errorf("failed to read root-ca: %v", err)
	}
	if !tlsConfig.RootCAs.AppendCertsFromPEM(rootCABytes) {
		return nil, fmt.Errorf("no certs found in root CA file %q", rootCAs)
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tlsConfig,
			Proxy:           http.ProxyFromEnvironment,
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}, nil
}

type debugTransport struct {
	t http.RoundTripper
}

func (d debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, err
	}
	log.Printf("%s", reqDump)

	resp, err := d.t.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	log.Printf("%s", respDump)
	return resp, nil
}

type SsoAppConfigType struct {
	clientID     string // --client-id
	clientSecret string // --client-secret
	redirectURI  string // --redirect-uri

	verifier *oidc.IDTokenVerifier
	provider *oidc.Provider

	RedirectURIParsed *url.URL
	exampleAppState   string

	// Does the provider use "offline_access" scope to request a refresh token
	// or does it use "access_type=offline" (e.g. Google)?
	offlineAsScope bool

	client *http.Client
}

func NewSSO(ssoCfg *data.SsoConfigType, rootCAs string, debug bool, issuerURL string, clientId, clientSecret string) (app *SsoAppConfigType, err error) {

	xx := SsoAppConfigType{
		redirectURI:     ssoCfg.RedirectURI,
		exampleAppState: "337eb9f5-95b0-4894-7ac7-2427daad8e22",
		clientID:        clientId,
		clientSecret:    clientSecret,
	}
	app = &xx

	redirectURIParsed, err := url.Parse(ssoCfg.RedirectURI)
	if err != nil {
		return nil, fmt.Errorf("parse redirect-uri: %v", err)
	}
	xx.RedirectURIParsed = redirectURIParsed

	//listenURL, err := url.Parse(listen)
	//if err != nil {
	//	return nil, fmt.Errorf("parse listen address: %v", err)
	//}

	if rootCAs != "" {
		client, err := httpClientForRootCAs(rootCAs)
		if err != nil {
			return nil, err
		}
		xx.client = client
	}

	if debug {
		if xx.client == nil {
			xx.client = &http.Client{
				Transport: debugTransport{http.DefaultTransport},
			}
		} else {
			xx.client.Transport = debugTransport{xx.client.Transport}
		}
	}

	if xx.client == nil {
		xx.client = http.DefaultClient
	}

	ctx := oidc.ClientContext(context.Background(), xx.client)
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to query provider %q: %v", issuerURL, err)
	}

	var s struct {
		// What scopes does app provider support?
		//
		// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
		ScopesSupported []string `json:"scopes_supported"`
	}
	if err := provider.Claims(&s); err != nil {
		return nil, fmt.Errorf("failed to parse provider scopes_supported: %v", err)
	}

	if len(s.ScopesSupported) == 0 {
		// scopes_supported is a "RECOMMENDED" discovery claim, not a required
		// one. If missing, assume that the provider follows the spec and has
		// an "offline_access" scope.
		xx.offlineAsScope = true
	} else {
		// See if scopes_supported has the "offline_access" scope.
		xx.offlineAsScope = func() bool {
			for _, scope := range s.ScopesSupported {
				if scope == oidc.ScopeOfflineAccess {
					return true
				}
			}
			return false
		}() // call the func at this point.
	}

	// dbgo.Printf("%(red)app=%x\n", app)
	// dbgo.Printf("%(red)provider=%x, app.clientID=%s\n", provider, xx.clientID)
	xx.provider = provider
	xx.verifier = provider.Verifier(&oidc.Config{ClientID: xx.clientID})

	return &xx, nil

}

func (app *SsoAppConfigType) SetupSSORoutes(router *gin.Engine) {
	router.POST("/api/v1/sso-login", app.handleSsoLogin)
	router.GET(app.RedirectURIParsed.Path, app.handleCallbackGet)   // /callback
	router.POST(app.RedirectURIParsed.Path, app.handleCallbackPost) // /callback
	router.POST("/api/v1/sso-token", app.handleSsoToken)
}

/*
func cmd() *cobra.Command {
	var (
		app       SsoAppConfigType
		issuerURL string // --issuer-url
		listen    string // --listen		default:    http://127.0.0.1:5555
		tlsCert   string // --tls-cert <file>
		tlsKey    string // --tls-key <file>
		rootCAs   string
		debug     bool
	)
	c := cobra.Command{
		Use:   "example-app",
		Short: "An example OpenID Connect client",
		Long:  "",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return errors.New("surplus arguments provided")
			}

			redirectURIParsed, err := url.Parse(app.redirectURI)
			if err != nil {
				return fmt.Errorf("parse redirect-uri: %v", err)
			}
			listenURL, err := url.Parse(listen)
			if err != nil {
				return fmt.Errorf("parse listen address: %v", err)
			}

			if rootCAs != "" {
				client, err := httpClientForRootCAs(rootCAs)
				if err != nil {
					return err
				}
				app.client = client
			}

			if debug {
				if app.client == nil {
					app.client = &http.Client{
						Transport: debugTransport{http.DefaultTransport},
					}
				} else {
					app.client.Transport = debugTransport{app.client.Transport}
				}
			}

			if app.client == nil {
				app.client = http.DefaultClient
			}

			// TODO(ericchiang): Retry with backoff
			ctx := oidc.ClientContext(context.Background(), app.client)
			provider, err := oidc.NewProvider(ctx, issuerURL)
			if err != nil {
				return fmt.Errorf("failed to query provider %q: %v", issuerURL, err)
			}

			var s struct {
				// What scopes does app provider support?
				//
				// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
				ScopesSupported []string `json:"scopes_supported"`
			}
			if err := provider.Claims(&s); err != nil {
				return fmt.Errorf("failed to parse provider scopes_supported: %v", err)
			}

			if len(s.ScopesSupported) == 0 {
				// scopes_supported is a "RECOMMENDED" discovery claim, not a required
				// one. If missing, assume that the provider follows the spec and has
				// an "offline_access" scope.
				app.offlineAsScope = true
			} else {
				// See if scopes_supported has the "offline_access" scope.
				app.offlineAsScope = func() bool {
					for _, scope := range s.ScopesSupported {
						if scope == oidc.ScopeOfflineAccess {
							return true
						}
					}
					return false
				}()
			}

			app.provider = provider
			app.verifier = provider.Verifier(&oidc.Config{ClientID: app.clientID})

			gin.ForceConsoleColor()
			router := gin.Default()
			router.MaxMultipartMemory = 20 << 20 // 20 MiB

			router.Use(gin.Recovery())

			router.GET("/status", statusHandler)
			router.GET("/api/v1/status", statusHandler)

			router.GET("/", app.handleIndex)

			router.POST("/login", app.handleSsoLogin)
			router.POST("/api/v1/sso-login", app.handleSsoLogin)
			router.GET(redirectURIParsed.Path, app.handleCallbackGet)   // /callback
			router.POST(redirectURIParsed.Path, app.handleCallbackPost) // /callback

			// ---------------------------------------------------------------------------------------------------------
			// server
			// ---------------------------------------------------------------------------------------------------------
			if db8 {
				dbgo.Printf("%(yellow)listenURL.Host = ->%s<- listenURL.Port = %s\n", listenURL.Host, listenURL.Port())
			}

			HostPort := listenURL.Host
			switch listenURL.Scheme {
			case "http":
				log.Printf("listening on %s", listen)
				// return http.ListenAndServe(listenURL.Host, nil)
				isTls = false
				return router.Run(HostPort)
			case "https":
				log.Printf("listening on %s", listen)
				// return http.ListenAndServeTLS(listenURL.Host, tlsCert, tlsKey, nil)
				isTls = true
				return router.Run(HostPort, tlsCert, tlsKey)
			default:
				return fmt.Errorf("listen address %q is not using http or https", listen)
			}
		},
	}
	c.Flags().StringVar(&app.clientID, "client-id", "example-app", "OAuth2 client ID of this application.")
	c.Flags().StringVar(&app.clientSecret, "client-secret", "ZXhhbXBsZS1hcHAtc2VjcmV0", "OAuth2 client secret of this application.")
	// c.Flags().StringVar(&app.redirectURI, "redirect-uri", "http://127.0.0.1:5555/callback", "Callback URL for OAuth2 responses.")
	c.Flags().StringVar(&app.redirectURI, "redirect-uri", "http://127.0.0.1:5555/api/v1/callback", "Callback URL for OAuth2 responses.")

	c.Flags().StringVar(&issuerURL, "issuer", "http://127.0.0.1:5556/dex", "URL of the OpenID Connect issuer.")
	c.Flags().StringVar(&listen, "listen", "http://127.0.0.1:5555", "HTTP(S) address to listen at.")
	c.Flags().StringVar(&tlsCert, "tls-cert", "", "X509 cert file to present when serving HTTPS.")
	c.Flags().StringVar(&tlsKey, "tls-key", "", "Private key for the HTTPS cert.")
	c.Flags().StringVar(&rootCAs, "issuer-root-ca", "", "Root certificate authorities for the issuer. Defaults to host certs.")

	c.Flags().BoolVar(&debug, "debug", false, "Print all request and responses from the OpenID Connect issuer.")
	return &c
}

func handleGetWebsocketConnectionId(c *gin.Context) {
}

func main() {
	if err := cmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
}

// func (app *SsoAppConfigType) handleIndex(w http.ResponseWriter, r *http.Request) {
func (app *SsoAppConfigType) handleIndex(c *gin.Context) {
	renderIndex(c.Writer)
}
*/

// ---------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------
func (app *SsoAppConfigType) oauth2Config(scopes []string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     app.clientID,
		ClientSecret: app.clientSecret,
		Endpoint:     app.provider.Endpoint(),
		Scopes:       scopes,
		RedirectURL:  app.redirectURI,
	}
}

// Input for handleSsoToken
type ApiSsoToken struct {
	TmpToken string `json:"tmp_token"  form:"tmp_token"       binding:"required"`
	AmIKnown string `json:"am_i_known" form:"am_i_known"` // -- not yet -- (from `/api/v1/id.json`)
	XsrfId   string `json:"xsrf_id"    form:"xsrf_id"`    //     binding:"required"`
	FPData   string `json:"fp_data"    form:"fp_data"`    // -- not yet --  fingerprint data
	ScID     string `json:"scid"       form:"scid"`       // 	 y_id - local storage ID
}

// Output returned
type SsoLoginSuccess struct {
	Status     string            `json:"status"`
	TmpToken   string            `json:"tmp_token,omitempty"` // May be "" - used in 2fa part 1 / 2
	Token      string            `json:"token,omitempty"`     // the JWT Token???
	FirstName  string            `json:"first_name,omitempty"`
	LastName   string            `json:"last_name,omitempty"`
	AcctState  string            `json:"acct_state,omitempty"`
	UserConfig map[string]string `json:"user_config,omitempty"`
	Email      string            `json:"email,omitempty"`
}

// ---------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------
func (app *SsoAppConfigType) handleSsoToken(c *gin.Context) {
	var err error
	var pp ApiSsoToken
	if err := BindFormOrJSON(c, &pp); err != nil {
		md.AddCounter("jwt_auth_failed_login_attempts", 1)
		return
	}

	if err := ValidateXsrfId(c, pp.XsrfId); err != nil {
		md.AddCounter("jwt_auth_failed_login_attempts", 1)
		return
	}

	hashOfHeaders := HeaderFingerprint(c)
	perReqLog := tf.GetLogFilePtr(c)

	rvStatus, err := callme.CallAuthIdpSsoToken(c, pp.TmpToken, pp.XsrfId, pp.FPData, hashOfHeaders, pp.ScID)
	if err != nil {
		md.AddCounter("jwt_auth_failed_login_attempts", 1)
		return
	}

	/*
	   func CallAuthIdpSsoToken(c *gin.Context, tmpToken string, xsrfId string, fpData string, hashOfHeaders string, scId string) (rv RvAuthIdpSsoToken, err error) {
	*/
	stmt := "q_auth_v1_idp_sso_token (  $1, $2, $3, $4, $5, $6, $7 )"
	if rvStatus.Status != "success" {

		md.AddCounter("jwt_auth_failed_login_attempts", 1)
		rvStatus.LogUUID = GenUUID()

		if logger != nil {
			fields := []zapcore.Field{
				zap.String("message", "Stored Procedure (q_auth_v1_idp_login_or_register) error return"),
				zap.String("go_location", dbgo.LF()),
			}
			fields = AppendStructToZapLog(fields, rvStatus)
			logger.Error("failed-to-login", fields...)
			log_enc.LogStoredProcError(c, stmt, "e", "xyzzyPerUserPw", SVar(rvStatus))
		} else {
			log_enc.LogStoredProcError(c, stmt, "e", "xyzzyPerUserPw", SVar(rvStatus))
		}
		var out LoginError1
		copier.Copy(&out, &rvStatus)
		out.Email = rvStatus.Email
		// c.JSON(http.StatusUnauthorized, LogJsonReturned(perReqLog, rvStatus.StdErrorReturn)) // 401
		c.JSON(http.StatusUnauthorized, LogJsonReturned(perReqLog, out)) // 401
		return
	}

	//  TokenHeaderVSCookie string `json:"token_header_vs_cookie" default:"cookie"`
	if rvStatus.AuthToken != "" {

		theJwtToken, err := CreateJWTSignedCookie(c, rvStatus.AuthToken, rvStatus.Email, CookieUsed) // this creates the cookie!
		if err != nil {
			return
		}
		dbgo.Fprintf(perReqLog, "%(green)!! Creating COOKIE Token, Logged In !!  at:%(LF): AuthToken=%s jwtCookieToken=%s email=%s\n", rvStatus.AuthToken, theJwtToken, rvStatus.Email)

		c.Set("__is_logged_in__", "y")
		c.Set("__user_id__", rvStatus.UserId)
		c.Set("__auth_token__", rvStatus.AuthToken)
		rv, mr := ConvPrivs2(perReqLog, rvStatus.Privileges)
		c.Set("__privs__", rv)
		c.Set("__privs_map__", mr)
		c.Set("__email_hmac_password__", aCfg.EncryptionPassword)
		c.Set("__user_password__", aCfg.UserdataPassword) // __userdata_password__
		c.Set("__client_id__", rvStatus.ClientId)

		md.AddCounter("jwt_sso_auth_success_login", 1)

		if theJwtToken != "" {
			// "Progressive improvement beats delayed perfection" -- Mark Twain
			if aCfg.TokenHeaderVSCookie == "cookie" {
				rvStatus.Token = ""
				c.Set("__jwt_token__", "")
				c.Set("__jwt_cookie_only__", "yes")
			} else { // header or both
				rvStatus.Token = theJwtToken
				c.Set("__jwt_token__", theJwtToken)
			}
		}

		// xyzzyRedisUsePubSub gCfg.RedisUsePubSub   string `json:"redis_use_pub_sub" default:"no"`
		if gCfg.RedisUsePubSub == "yes" {
			RedisBrodcast(rvStatus.AuthToken, fmt.Sprintf(`{"cmd":"/auth/login","auth_token":%q,"user_id":%q}`, rvStatus.AuthToken, rvStatus.UserId))
		}
	}

	var out SsoLoginSuccess
	copier.Copy(&out, &rvStatus)
	c.JSON(http.StatusOK, LogJsonReturned(perReqLog, out))

}

// ---------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------
func (app *SsoAppConfigType) handleSsoLogin(c *gin.Context) {
	var scopes []string
	if extraScopes := c.Request.FormValue("extra_scopes"); extraScopes != "" {
		scopes = strings.Split(extraScopes, " ")
	}
	var clients []string
	if crossClients := c.Request.FormValue("cross_client"); crossClients != "" {
		clients = strings.Split(crossClients, " ")
	}
	for _, client := range clients {
		scopes = append(scopes, "audience:server:client_id:"+client)
	}
	connectorID := ""
	if id := c.Request.FormValue("connector_id"); id != "" {
		connectorID = id
	}

	authCodeURL := ""
	scopes = append(scopes, "openid", "profile", "email")
	if c.Request.FormValue("offline_access") != "yes" {
		authCodeURL = app.oauth2Config(scopes).AuthCodeURL(app.exampleAppState)
	} else if app.offlineAsScope {
		scopes = append(scopes, "offline_access")
		authCodeURL = app.oauth2Config(scopes).AuthCodeURL(app.exampleAppState)
	} else {
		authCodeURL = app.oauth2Config(scopes).AuthCodeURL(app.exampleAppState, oauth2.AccessTypeOffline)
	}
	if connectorID != "" {
		authCodeURL = authCodeURL + "&connector_id=" + connectorID
	}

	http.Redirect(c.Writer, c.Request, authCodeURL, http.StatusSeeOther)
}

// ---------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------
// func (app *SsoAppConfigType) handleCallback(w http.ResponseWriter, r *http.Request) {
func (app *SsoAppConfigType) handleCallbackGet(c *gin.Context) {
	var err error
	var token *oauth2.Token

	perReqLog := tf.GetLogFilePtr(c)
	_ = perReqLog

	ctx := oidc.ClientContext(c.Request.Context(), app.client)
	oauth2Config := app.oauth2Config(nil)

	dbgo.Printf("%(yellow)AT:%(LF)\n")
	// Authorization redirect callback from OAuth2 auth flow.
	if errMsg := c.Request.FormValue("error"); errMsg != "" {
		http.Error(c.Writer, errMsg+": "+c.Request.FormValue("error_description"), http.StatusBadRequest)
		return
	}
	code := c.Request.FormValue("code")
	if code == "" {
		http.Error(c.Writer, fmt.Sprintf("no code in request: %q", c.Request.Form), http.StatusBadRequest)
		return
	}
	if state := c.Request.FormValue("state"); state != app.exampleAppState {
		http.Error(c.Writer, fmt.Sprintf("expected state %q got %q", app.exampleAppState, state), http.StatusBadRequest)
		return
	}

	dbgo.Printf("%(yellow)AT:%(LF)\n")
	token, err = oauth2Config.Exchange(ctx, code)
	if err != nil {
		http.Error(c.Writer, fmt.Sprintf("failed to get token: %v", err), http.StatusInternalServerError)
		return
	}

	dbgo.Printf("%(yellow)AT:%(LF)\n")
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(c.Writer, "no id_token in token response", http.StatusInternalServerError)
		return
	}

	dbgo.Printf("%(yellow)AT:%(LF)\n")
	idToken, err := app.verifier.Verify(c.Request.Context(), rawIDToken)
	if err != nil {
		http.Error(c.Writer, fmt.Sprintf("failed to verify ID token: %v", err), http.StatusInternalServerError)
		return
	}

	dbgo.Printf("%(yellow)AT:%(LF)\n")
	accessToken, ok := token.Extra("access_token").(string)
	if !ok {
		http.Error(c.Writer, "no access_token in token response", http.StatusInternalServerError)
		return
	}

	dbgo.Printf("%(yellow)AT:%(LF)\n")
	var claims json.RawMessage
	if err := idToken.Claims(&claims); err != nil {
		http.Error(c.Writer, fmt.Sprintf("error decoding ID token claims: %v", err), http.StatusInternalServerError)
		return
	}

	dbgo.Printf("%(yellow)AT:%(LF)\n")
	// the "claims" as a JSON data.
	claimsAsJSONString := new(bytes.Buffer)
	if err := json.Indent(claimsAsJSONString, []byte(claims), "", "  "); err != nil {
		http.Error(c.Writer, fmt.Sprintf("error indenting ID token claims: %v", err), http.StatusInternalServerError)
		return
	}

	dbgo.Printf("%(yellow)AT:%(LF)\n")
	dbgo.Printf("%(cyan)AT:%(LF) - GET - rawIDToken = %s, accessTOken = %s, refreshToken=%s\n", rawIDToken, accessToken, token.RefreshToken)

	dbgo.Printf("%(yellow)AT:%(LF)\n")
	SetCookie("idToken", rawIDToken, c)
	SetCookie("accessToken", accessToken, c)

	dbgo.Printf("%(yellow)AT:%(LF)\n")
	// renderToken(c.Writer, app.redirectURI, rawIDToken, accessToken, token.RefreshToken, claimsAsJSONString.String())
	tt := IdpLoginRegister(c, app.redirectURI, rawIDToken, accessToken, "", claimsAsJSONString.String(), []byte(claims))

	dbgo.Printf("%(yellow)AT:%(LF)\n")
	// dbgo.Printf("\n=========== %(red)just before set cookie ==========\n\n")
	// SetCookie("X_X_GET_idToken", rawIDToken, c) // SetCookie("accessToken", accessToken, c)

	c.Writer.Header().Set("Content-Type", "text/html")
	c.String(http.StatusOK, fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">

<script src="/js/jquery-3.7.0.js"></script>
</head>
<body>
<h1> GET TmpToken: %s </h1>
<script>
// var base_url = 'https://app.write-it-right.ai';
let tt = %q;
console.log ( "TmpToken = ", tt );

function sendMessageToParent ( msg ) {
	let msgStr = JSON.stringify (msg);
	console.warn ( "sendMessageToParent: msg=", msgStr );
	if ( window.parent ) {
		console.log ( "will post message to parent.", msgStr );
		window.parent.postMessage( msgStr, "*" );
	} else {
		console.error ( "parent not found, message ignored", msgStr );
	}
}

function ShowMsg ( title, msg, msgType ) {
	console.error ( title, msg, msgType ) ;
	sendMessageToParent ( { "cmd":"ShowMsg", "title":title, "msg":msg, "msgType":msgType } );
}

$(document).ready(function() {
	// base_url = window.location.origin;
	// if ( ! base_url ) {			
	// 	base_url = window.location.protocol + "//" + window.location.host;
	// }
	ShowMsg ( "Successful Login", "Successful Login", "success" );
	sendMessageToParent ( { "cmd":"SSOLoginSuccess", "tmp_token": tt } );
});

</script>
</body>
</html>
`, tt, tt))
	return

	// c.JSON(http.StatusOK, LogJsonReturned(perReqLog, gin.H{ // 200
	//	"status":    "success",
	//	"tmp_token": tt,
	// }))
	// return

}

// ---------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------
// func (app *SsoAppConfigType) handleCallback(w http.ResponseWriter, r *http.Request) {
func (app *SsoAppConfigType) handleCallbackPost(c *gin.Context) {
	var err error
	var token *oauth2.Token

	perReqLog := tf.GetLogFilePtr(c)
	_ = perReqLog

	ctx := oidc.ClientContext(c.Request.Context(), app.client)
	oauth2Config := app.oauth2Config(nil)

	dbgo.Printf("%(cyan)AT:%(LF)\n")
	// Form request from frontend to refresh a token.
	refresh := c.Request.FormValue("refresh_token")
	if refresh == "" {
		http.Error(c.Writer, fmt.Sprintf("no refresh_token in request: %q", c.Request.Form), http.StatusBadRequest)
		return
	}
	t := &oauth2.Token{
		RefreshToken: refresh,
		Expiry:       time.Now().Add(-time.Hour),
	}
	token, err = oauth2Config.TokenSource(ctx, t).Token()
	if err != nil {
		http.Error(c.Writer, fmt.Sprintf("failed to get token: %v", err), http.StatusInternalServerError)
		return
	}

	dbgo.Printf("%(cyan)AT:%(LF)\n")
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(c.Writer, "no id_token in token response", http.StatusInternalServerError)
		return
	}

	dbgo.Printf("%(cyan)AT:%(LF)\n")
	idToken, err := app.verifier.Verify(c.Request.Context(), rawIDToken)
	if err != nil {
		http.Error(c.Writer, fmt.Sprintf("failed to verify ID token: %v", err), http.StatusInternalServerError)
		return
	}

	dbgo.Printf("%(cyan)AT:%(LF)\n")
	accessToken, ok := token.Extra("access_token").(string)
	if !ok {
		http.Error(c.Writer, "no access_token in token response", http.StatusInternalServerError)
		return
	}

	dbgo.Printf("%(cyan)AT:%(LF)\n")
	var claims json.RawMessage
	if err := idToken.Claims(&claims); err != nil {
		http.Error(c.Writer, fmt.Sprintf("error decoding ID token claims: %v", err), http.StatusInternalServerError)
		return
	}

	dbgo.Printf("%(cyan)AT:%(LF)\n")
	claimsAsJSONString := new(bytes.Buffer)
	if err := json.Indent(claimsAsJSONString, []byte(claims), "", "  "); err != nil {
		http.Error(c.Writer, fmt.Sprintf("error indenting ID token claims: %v", err), http.StatusInternalServerError)
		return
	}

	dbgo.Printf("%(cyan)AT:%(LF)\n")
	dbgo.Printf("%(cyan)AT:%(LF) - POST - rawIDToken = %s, accessTOken = %s, refreshToken=%s\n", rawIDToken, accessToken, token.RefreshToken)

	// renderToken(c.Writer, app.redirectURI, rawIDToken, accessToken, token.RefreshToken, claimsAsJSONString.String())
	// func IdpLoginRegister(c *gin.Context, redirectURI string, rawIDToken string, accessToken string, RefreshToken string, claimsAsJSONString string, claims []byte, verified string) {
	tt := IdpLoginRegister(c, app.redirectURI, rawIDToken, accessToken, refresh, claimsAsJSONString.String(), []byte(claims))

	c.Writer.Header().Set("Content-Type", "text/html")
	c.String(http.StatusOK, fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">

<script src="/js/jquery-3.7.0.js"></script>
</head>
<body>
<h1> POST TmpToken: %s </h1>
<script>
// var base_url = 'https://app.write-it-right.ai';
let tt = %q;
console.log ( "TmpToken = ", tt );

function sendMessageToParent ( msg ) {
	let msgStr = JSON.stringify (msg);
	console.warn ( "sendMessageToParent: msg=", msgStr );
	if ( window.parent ) {
		console.log ( "will post message to parent.", msgStr );
		window.parent.postMessage( msgStr, "*" );
	} else {
		console.error ( "parent not found, message ignored", msgStr );
	}
}

function ShowMsg ( title, msg, msgType ) {
	console.error ( title, msg, msgType ) ;
	sendMessageToParent ( { "cmd":"ShowMsg", "title":title, "msg":msg, "msgType":msgType } );
}

$(document).ready(function() {
	// base_url = window.location.origin;
	// if ( ! base_url ) {			
	// 	base_url = window.location.protocol + "//" + window.location.host;
	// }
	ShowMsg ( "Successful Login", "Successful Login", "success" );
	sendMessageToParent ( { "cmd":"SSOLoginSuccess", "tmp_token": tt } );
});

</script>
</body>
</html>
`, tt, tt))
	return

	//c.JSON(http.StatusOK, LogJsonReturned(perReqLog, gin.H{ // 200
	//	"status":    "success",
	//	"tmp_token": tt,
	//}))
	//return

	// dbgo.Printf("%(cyan)AT:%(LF)\n")
	// SetCookie("X_X_POST_idToken", rawIDToken, c) // SetCookie("accessToken", accessToken, c)
	// h := c.Writer.Header()
	// h.Set("Content-Type", "text/html")
	// c.String(http.StatusOK, fmt.Sprintf(`<h1> POST TmpToken: %s </h1>`, tt))

}

/*
ID Token:

eyJhbGciOiJSUzI1NiIsImtpZCI6ImE3OGJmNTkwMGM0MzBjNWYxMzVkNzlmYjdlNzAxMTA2Y2ViYzk3YzAifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjU1NTYvZGV4Iiwic3ViIjoiQ2cwd0xUTTROUzB5T0RBNE9TMHdFZ1J0YjJOciIsImF1ZCI6ImV4YW1wbGUtYXBwIiwiZXhwIjoxNzIxMTczOTkxLCJpYXQiOjE3MjEwODc1OTEsImF0X2hhc2giOiJtNFBraVRkUlpqaVRhQVNJQ3pzNzJnIiwiY19oYXNoIjoiWGVyenEtQTZLbnhWYzdDN0VrRnVvUSIsImVtYWlsIjoia2lsZ29yZUBraWxnb3JlLnRyb3V0IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJLaWxnb3JlIFRyb3V0In0.GQCzlVVOY_U9yNU1YvSyD-d1zRib1ZrWn6h8HJhExQrrQhFXlq54kWeOk-lmAhuznOZdBy8umv1wVmFB2hE9JtcSz1nQtLxOPHjgFbPxGb0ShYbQHvIN3so70qAAHdoIxstJSkuHufM99fasyJdJE-x9HqXcTIcE9jbEnvxhYDGkX1j_kvjwukQ2PJWfkj7dbXQLDdgEnR0PsGXMlUEXCb90CqQC98Pc8F3E2qbD1WtfAucgRHfD0U_XpVCCQX210rEkMJE-3KyVZv9fZ7VxRJjDMAu_ex1DU7ly8xL4RFH36peucp94FUF-XChc9ozh8FjHat7EDaqw2qSNp2-KjQ
Access Token:

eyJhbGciOiJSUzI1NiIsImtpZCI6ImE3OGJmNTkwMGM0MzBjNWYxMzVkNzlmYjdlNzAxMTA2Y2ViYzk3YzAifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjU1NTYvZGV4Iiwic3ViIjoiQ2cwd0xUTTROUzB5T0RBNE9TMHdFZ1J0YjJOciIsImF1ZCI6ImV4YW1wbGUtYXBwIiwiZXhwIjoxNzIxMTczOTkxLCJpYXQiOjE3MjEwODc1OTEsImF0X2hhc2giOiJ0TndYUE1NWDlyZ0dfMzVZU1ZtQVlnIiwiZW1haWwiOiJraWxnb3JlQGtpbGdvcmUudHJvdXQiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IktpbGdvcmUgVHJvdXQifQ.jHVABk-6CCi6m4s9R4MjBmHhNGGY0zxgh6YS_qkKI0r2oJK-u5uRHqZiqNHloKHuvPEzxDd3Ob7juoo8-qW8UJPaOhdofuAD2aGmAXKOgXXZGzIF9VWNOt7kqqlGOjBrpaMm7h6tUHpUb9GU8w_0CjKG5pA_ZK5uC4q6V4kF6vWOG_S1sspqcv2F-UvtzGKj6Y2VzgSb2A4eKApbdVGTZjRrCogQ0rWR_RXSnzCxmnHLDhLnarkVgEZyM936Zqp_Mjl0RrchyczI95rMwMh3FsXtPl4JG35bGDP3dNP7SFGxS2Gb2TxLqn4grfBpl-3kkD2vJuWkGq17Q9ODHu00Sg
Claims:

{
  "iss": "http://127.0.0.1:5556/dex",
  "sub": "Cg0wLTM4NS0yODA4OS0wEgRtb2Nr",
  "aud": "example-app",
  "exp": 1721173991,
  "iat": 1721087591,
  "at_hash": "m4PkiTdRZjiTaASICzs72g",
  "c_hash": "Xerzq-A6KnxVc7C7EkFuoQ",
  "email": "kilgore@kilgore.trout",
  "email_verified": true,
  "name": "Kilgore Trout"
}

Refresh Token:

Chlib2JldWg3Ym54bWZrd2k2ZWlzMjVtNXVlEhlodnV6anN3d2k2cmV3NW52bGs2eWdhazNi
*/

type ClaimsType struct {
	Validator     string `json:"iss"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"verified_email"`
	Name          string `json:"name"`
}

func IdpLoginRegister(c *gin.Context, redirectURI string, rawIDToken string, accessToken string, RefreshToken string, claimsAsJSONString string, claims []byte) (TmpToken string) {

	/*
		type RvAuthIdpLoginOrRegister struct {
			jwt_auth.StdErrorReturn
			UserId           string `json:"user_id,omitempty"`
			AuthToken        string `json:"auth_token,omitempty"`
			TmpToken         string `json:"tmp_token,omitempty"`
			Require2Fa       string `json:"require_2fa,omitempty"`
			AccountType      string `json:"account_type,omitempty"`
			Privileges       string `json:"privileges,omitempty"`
			UserConfig       string `json:"user_config,omitempty"`
			ClientUserConfig string `json:"client_user_config,omitempty"`
			FirstName        string `json:"first_name,omitempty"`
			LastName         string `json:"last_name,omitempty"`
			ClientId         string `json:"client_id,omitempty"`
			AcctState        string `json:"acct_state,omitempty"`
		}
	*/
	perReqLog := tf.GetLogFilePtr(c)

	var vt ClaimsType
	err := json.Unmarshal([]byte(claimsAsJSONString), &vt)

	hashOfHeaders := HeaderFingerprint(c)
	emailVerified := "n"
	if vt.EmailVerified {
		emailVerified = "y"
	}

	firstName, lastName := "?", "?"
	if vt.Name != "" {
		got := names.ParseFullName(vt.Name)
		firstName, lastName = got.First, got.Last
	}

	ScId := "337eb9f5-95b0-4894-7ac7-2427daad8e22"

	// func CallAuthIdpLoginOrRegister(c *gin.Context, email string, validator string, claims string, idToken string, accessToken string, refreshToken string, hashOfHeaders string, emailVerified string, firstName string, lastName string) (rv RvAuthIdpLoginOrRegister, err error) {
	rvStatus, err := callme.CallAuthIdpLoginOrRegister(c, vt.Email, vt.Validator, string(claims), rawIDToken, accessToken, RefreshToken, hashOfHeaders, emailVerified, firstName, lastName, ScId)
	if err != nil {
		md.AddCounter("jwt_auth_failed_login_attempts", 1)
		return
	}

	stmt := "q_auth_v1_idp_login_or_register (  $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12 )"
	if rvStatus.Status != "success" {

		md.AddCounter("jwt_auth_failed_login_attempts", 1)
		rvStatus.LogUUID = GenUUID()

		if logger != nil {
			fields := []zapcore.Field{
				zap.String("message", "Stored Procedure (q_auth_v1_idp_login_or_register) error return"),
				zap.String("go_location", dbgo.LF()),
			}
			fields = AppendStructToZapLog(fields, rvStatus)
			logger.Error("failed-to-login", fields...)
			log_enc.LogStoredProcError(c, stmt, "e", "xyzzyPerUserPw", SVar(rvStatus))
		} else {
			log_enc.LogStoredProcError(c, stmt, "e", "xyzzyPerUserPw", SVar(rvStatus))
		}
		var out LoginError1
		copier.Copy(&out, &rvStatus)
		out.Email = vt.Email
		// c.JSON(http.StatusUnauthorized, LogJsonReturned(perReqLog, rvStatus.StdErrorReturn)) // 401
		c.JSON(http.StatusUnauthorized, LogJsonReturned(perReqLog, out)) // 401
		return
	}

	//  TokenHeaderVSCookie string `json:"token_header_vs_cookie" default:"cookie"`
	if rvStatus.AuthToken != "" {

		theJwtToken, err := CreateJWTSignedCookie(c, rvStatus.AuthToken, vt.Email, CookieUsed) // this creates the cookie!
		if err != nil {
			return
		}
		dbgo.Fprintf(perReqLog, "%(green)!! Creating COOKIE Token, Logged In !!  at:%(LF): AuthToken=%s jwtCookieToken=%s email=%s\n", rvStatus.AuthToken, theJwtToken, vt.Email)

		c.Set("__is_logged_in__", "y")
		c.Set("__user_id__", rvStatus.UserId)
		c.Set("__auth_token__", rvStatus.AuthToken)
		rv, mr := ConvPrivs2(perReqLog, rvStatus.Privileges)
		c.Set("__privs__", rv)
		c.Set("__privs_map__", mr)
		c.Set("__email_hmac_password__", aCfg.EncryptionPassword)
		c.Set("__user_password__", aCfg.UserdataPassword) // __userdata_password__
		c.Set("__client_id__", rvStatus.ClientId)

		md.AddCounter("jwt_pt1_auth_success_login", 1)

		if theJwtToken != "" {
			// "Progressive improvement beats delayed perfection" -- Mark Twain
			if aCfg.TokenHeaderVSCookie == "cookie" {
				rvStatus.Token = ""
				c.Set("__jwt_token__", "")
				c.Set("__jwt_cookie_only__", "yes")
			} else { // header or both
				rvStatus.Token = theJwtToken
				c.Set("__jwt_token__", theJwtToken)
			}
		}

		// xyzzyRedisUsePubSub gCfg.RedisUsePubSub   string `json:"redis_use_pub_sub" default:"no"`
		if gCfg.RedisUsePubSub == "yes" {
			RedisBrodcast(rvStatus.AuthToken, fmt.Sprintf(`{"cmd":"/auth/login","auth_token":%q,"user_id":%q}`, rvStatus.AuthToken, rvStatus.UserId))
		}
	}

	return rvStatus.TmpToken
}

// const db8 = false
type OAuth20ClaimsType struct {
	Id            string `json:"id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"verified_email"`
	Picture       string `json:"picture"`
}

/*
	UserInfo: {
	  "id": "101983930229230661870",
	  "email": "pschlump@gmail.com",
	  "verified_email": true,
	  "picture": "https://lh3.googleusercontent.com/a-/ALV-UjW5r2574-arc8H1FICKlkS4JdeuVgw5MtyTadJ7xxt-raNy7mlU=s96-c"
	}
*/
type SsoLoginError struct {
	StdErrorReturn
}

func OAuth2LoginRegister(c *gin.Context, authority, redirectURI string, rawIDToken string, accessToken string, RefreshToken string, userData string) (err error) {

	/*
		type RvAuthIdpLoginOrRegister struct {
			jwt_auth.StdErrorReturn
			UserId           string `json:"user_id,omitempty"`
			AuthToken        string `json:"auth_token,omitempty"`
			TmpToken         string `json:"tmp_token,omitempty"`
			Require2Fa       string `json:"require_2fa,omitempty"`
			AccountType      string `json:"account_type,omitempty"`
			Privileges       string `json:"privileges,omitempty"`
			UserConfig       string `json:"user_config,omitempty"`
			ClientUserConfig string `json:"client_user_config,omitempty"`
			FirstName        string `json:"first_name,omitempty"`
			LastName         string `json:"last_name,omitempty"`
			ClientId         string `json:"client_id,omitempty"`
			AcctState        string `json:"acct_state,omitempty"`
		}
	*/
	perReqLog := tf.GetLogFilePtr(c)
	err = nil

	var vt OAuth20ClaimsType
	err = json.Unmarshal([]byte(userData), &vt)
	if err != nil {
		// Blow out - Error -
		var Resp SsoLoginError
		Resp.Status = "error"
		Resp.Msg = "Failed to authenticate"
		Resp.LogUUID = GenUUID()
		c.JSON(http.StatusBadRequest, LogJsonReturned(perReqLog, Resp.StdErrorReturn))
		return fmt.Errorf("Sign On Authority (%s) returned a garbled or unreadable responce: %s", authority, err)
	}

	hashOfHeaders := HeaderFingerprint(c)
	emailVerified := "n"
	if vt.EmailVerified {
		emailVerified = "y"
	}

	if emailVerified == "n" {
		// Blow out - can not accept a non-verified email address
		var Resp SsoLoginError
		Resp.Status = "error"
		Resp.Msg = "Email must be verified"
		Resp.LogUUID = GenUUID()
		dbgo.Printf("AT:%(LF) data ->%s<- parsed ->%s<-\n", userData, dbgo.SVarI(vt))
		c.JSON(http.StatusUnauthorized, LogJsonReturned(perReqLog, Resp.StdErrorReturn))
		return fmt.Errorf("Email Not Verified at %s, can not be used for login until verified.", authority)
	}

	dbgo.Printf("%(greenw)AT: %(yellow)%(LF)\n")
	for name, values := range c.Request.Header {
		// Loop over all values for the name.
		for _, value := range values {
			dbgo.Printf("     %(red)Header: ->%s<- Value ->%s<-\n", name, value)
		}
	}

	firstName, lastName := "?", "?"
	// if vt.Name != "" {
	// 	got := names.ParseFullName(vt.Name)
	// 	firstName, lastName = got.First, got.Last
	// }

	// X-WebScoket-Connection-ID=7f4ac098-73b0-47eb-9322-4dfcb9918e44
	// ScId := "337eb9f5-95b0-4894-7ac7-2427daad8e22"
	ScId, err := c.Cookie("X-WebScoket-Connection-ID")
	if err != nil || ScId == "" {
		ScId = "337eb9f5-95b0-4894-7ac7-2427daad8e22"
		// xyzzy - Blow out - Must have this to mark device
	}

	// func CallAuthIdpLoginOrRegister(c *gin.Context, email string, validator string, claims string, idToken string, accessToken string, refreshToken string, hashOfHeaders string, emailVerified string, firstName string, lastName string) (rv RvAuthIdpLoginOrRegister, err error) {
	rvStatus, err := callme.CallAuthIdpLoginOrRegister(c, vt.Email, authority, userData, vt.Id, vt.Id, "", hashOfHeaders, emailVerified, firstName, lastName, ScId)
	if err != nil {
		md.AddCounter("jwt_auth_failed_login_attempts", 1)
		return fmt.Errorf("Database error occured")
	}

	stmt := "q_auth_v1_idp_login_or_register (  $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12 )"
	if rvStatus.Status != "success" {

		md.AddCounter("jwt_auth_failed_login_attempts", 1)
		rvStatus.LogUUID = GenUUID()

		if logger != nil {
			fields := []zapcore.Field{
				zap.String("message", "Stored Procedure (q_auth_v1_idp_login_or_register) error return"),
				zap.String("go_location", dbgo.LF()),
			}
			fields = AppendStructToZapLog(fields, rvStatus)
			logger.Error("failed-to-login", fields...)
			log_enc.LogStoredProcError(c, stmt, "e", "xyzzyPerUserPw", SVar(rvStatus))
		} else {
			log_enc.LogStoredProcError(c, stmt, "e", "xyzzyPerUserPw", SVar(rvStatus))
		}
		var out LoginError1
		copier.Copy(&out, &rvStatus)
		out.Email = vt.Email
		// c.JSON(http.StatusUnauthorized, LogJsonReturned(perReqLog, rvStatus.StdErrorReturn)) // 401
		c.JSON(http.StatusUnauthorized, LogJsonReturned(perReqLog, out)) // 401
		return fmt.Errorf("Not Authorized")
	}

	//  TokenHeaderVSCookie string `json:"token_header_vs_cookie" default:"cookie"`
	if rvStatus.AuthToken != "" {

		theJwtToken, e1 := CreateJWTSignedCookie(c, rvStatus.AuthToken, vt.Email, CookieUsed) // this creates the cookie!
		if err != nil {
			return e1
		}
		dbgo.Fprintf(perReqLog, "%(green)!! Creating COOKIE Token, Logged In !!  at:%(LF): AuthToken=%s jwtCookieToken=%s email=%s\n", rvStatus.AuthToken, theJwtToken, vt.Email)

		c.Set("__is_logged_in__", "y")
		c.Set("__user_id__", rvStatus.UserId)
		c.Set("__auth_token__", rvStatus.AuthToken)
		rv, mr := ConvPrivs2(perReqLog, rvStatus.Privileges)
		c.Set("__privs__", rv)
		c.Set("__privs_map__", mr)
		c.Set("__email_hmac_password__", aCfg.EncryptionPassword)
		c.Set("__user_password__", aCfg.UserdataPassword) // __userdata_password__
		c.Set("__client_id__", rvStatus.ClientId)

		md.AddCounter("jwt_pt1_auth_success_login", 1)

		if theJwtToken != "" {
			// "Progressive improvement beats delayed perfection" -- Mark Twain
			if aCfg.TokenHeaderVSCookie == "cookie" {
				rvStatus.Token = ""
				c.Set("__jwt_token__", "")
				c.Set("__jwt_cookie_only__", "yes")
			} else { // header or both
				rvStatus.Token = theJwtToken
				c.Set("__jwt_token__", theJwtToken)
			}
		}

		// xyzzyRedisUsePubSub gCfg.RedisUsePubSub   string `json:"redis_use_pub_sub" default:"no"`
		if gCfg.RedisUsePubSub == "yes" {
			RedisBrodcast(rvStatus.AuthToken, fmt.Sprintf(`{"cmd":"/auth/login","auth_token":%q,"user_id":%q}`, rvStatus.AuthToken, rvStatus.UserId))
		}
	}

	return nil
}

// const db8 = false
