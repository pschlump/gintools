package jwt_auth

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

// This is based on examples of Gin middleware in the article:
// From: https://sosedoff.com/2014/12/21/gin-middleware.html
// To Use: router.Use(TokenAuthMiddleware())
// No code is direclty copied, just informaiotn from the artile.

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/pschlump/dbgo"
)

func respondWithError(c *gin.Context, code int, message interface{}) {
	c.AbortWithStatusJSON(code, gin.H{"status": "error", "msg": message})
}

func TokenAuthMiddleware() gin.HandlerFunc {
	requiredToken := os.Getenv("API_TOKEN")

	// We want to make sure the token is set, bail if not
	if requiredToken == "" {
		log.Fatal("Please set API_TOKEN environment variable")
	}

	return func(c *gin.Context) {
		token := c.Request.FormValue("api_token")

		if token == "" {
			respondWithError(c, 401, "API token required")
			return
		}

		if token != requiredToken {
			respondWithError(c, 401, "Invalid API token")
			return
		}

		c.Next()
	}
}

/*

// Code from top of auth.go
// ===============================================================

var GinLoginTable = []GinLoginType{

type GinLoginType struct {
	Path     string
	Method   string
	Fx       func(c *gin.Context)
	UseLogin int // 0 required - or not found in table, 1 not required, 2 optional
}

const (
	LoginRequired = 1
	PublicApiCall = 0
	LoginOptional = 2
)

*/

func CookieHeaderAuthMiddleware(ginSetupTable []GinLoginType) gin.HandlerFunc {

	findInTable := func(path, method string) *GinLoginType {
		// dbgo.Printf("%(magenta)Looking for %s:%s\n", method, path)
		for _, vv := range ginSetupTable {
			// dbgo.Printf("%(magenta)   compare to %s:%s\n", vv.Method, vv.Path)
			if vv.Path == path && vv.Method == method {
				return &vv
			}
		}
		// dbgo.Printf("%(magenta)!!!!!!%(red)Nope.... did not fined it\n")
		return nil
	}

	return func(c *gin.Context) {
		x := findInTable(c.Request.URL.Path, c.Request.Method)
		if x == nil { // Assume that if we do not find it we need to login. ((TODO - bad assumption))
			IsLoggedIn(c)
			//if !IsLoggedIn(c) {
			//	dbgo.Fprintf(logFilePtr, "In handler at %(LF) - Not Authorized 401\n")
			//	respondWithError(c, http.StatusUnauthorized, "Not Authorized") // 401
			//	return
			//}
			c.Next()
			return
		}
		switch x.UseLogin {
		case LoginRequired:
			if !IsLoggedIn(c) {
				dbgo.Fprintf(logFilePtr, "In handler at %(LF) - Not Authorized 401\n")
				respondWithError(c, http.StatusUnauthorized, "Not Authorized") // 401
				//c.JSON(http.StatusUnauthorized, gin.H{ // 401
				//	"status": "error",
				//	"msg":    "401 not authorized",
				//})
				return
			}
		case LoginOptional:
			IsLoggedIn(c)
		case PublicApiCall:
		}
		c.Next()
	}
}

// -------------------------------------------------------------------------------------------------------------------------
func AppendToSecurityTable(x ...GinLoginType) {
	GinSetupTable = append(GinSetupTable, x...)
}

func AppendOneToSecurityTable(method, path string, fx func(c *gin.Context), useLogin LoginType) {
	GinSetupTable = append(GinSetupTable, GinLoginType{
		Path:     path,
		Method:   method,
		Fx:       fx,
		UseLogin: useLogin,
	})
}

/* vim: set noai ts=4 sw=4: */
