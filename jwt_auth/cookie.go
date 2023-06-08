package jwt_auth

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"github.com/gin-gonic/gin"
)

// -------------------------------------------------------------------------------------------------------------------------------------
// Cookie processing.
// -------------------------------------------------------------------------------------------------------------------------------------

// HasCookie returns true, `has` and a value if the cookie exists.  If not then it returns false.
func HasCookie(cookieName string, c *gin.Context) (has bool, val string) {
	// cookie, err := c.Request.Cookie(cookieName)
	cookie, err := c.Cookie(cookieName)
	if err != nil {
		return
	}
	//	if cookie.Value == "" {
	//		return
	//	}
	//	return true, cookie.Value
	return true, cookie
}

// SetCookie sets the header to create a cookie.  If using TLS then this will be a secure HTTP-Only cookie.
func SetCookie(cookieName, cookieValue string, c *gin.Context) {
	// Expires := "Mon, 05-Jan-2032 15:04:05 MST"
	Domain := ""
	MaxAge := 10 * 366 * 24 * 60 * 60
	// theCookie := GenCookie(cookieName, cookieValue, "/", Domain, Expires, MaxAge, IsTLS(c), IsTLS(c))
	// http.SetCookie(c.Writer, theCookie)
	// func (c *Context) SetCookie(name, value string, maxAge int, path, domain string, secure, httpOnly bool) {
	c.SetCookie(cookieName, cookieValue, MaxAge, "/", Domain, IsTLS(c), IsTLS(c))
}

func SetInsecureCookie(cookieName, cookieValue string, c *gin.Context) {
	// Expires := "Mon, 05-Jan-2032 15:04:05 MST"
	Domain := ""
	MaxAge := 10 * 366 * 24 * 60 * 60
	// theCookie := GenCookie(cookieName, cookieValue, "/", Domain, Expires, MaxAge, false, false)
	// http.SetCookie(c.Writer, theCookie)
	// func (c *Context) SetCookie(name, value string, maxAge int, path, domain string, secure, httpOnly bool) {
	c.SetCookie(cookieName, cookieValue, MaxAge, "/", Domain, false, false)
}

/*
	http.SetCookie(www, hdlr.GenCookie())

// --------------------------------------------------------------------------------------------------------------------------

type CookieHandlerType struct {
	Next       http.Handler
	Paths      []string
	Name       string // if Name starts with "-" then delete existing header before creating new one.
	Value      string // if Value is "" then do not set header.
	CookiePath string //
	Domain     string //
	Expires    string // (time)		// Xyzzy - need a time type
	MaxAge     int    //
	Secure     bool   //
	HttpOnly   bool   //
	LineNo     int
	// theCookie  http.Cookie
}

*/
//func GenCookie(Name, Value, CookiePath, Domain, Expires string, MaxAge int, Secure, HttpOnly bool) (theCookie *http.Cookie) {
//	theCookie = &http.Cookie{}
//	theCookie.Name = Name
//	theCookie.Value = Value
//	theCookie.Path = CookiePath
//	theCookie.Domain = Domain
//	exptime, err := time.Parse(time.RFC1123, Expires)
//	if err != nil {
//		exptime, err = time.Parse("Mon, 02-Jan-2006 15:04:05 MST", Expires)
//		if err != nil {
//			theCookie.Expires = time.Time{}
//			goto skip
//		}
//	}
//	theCookie.Expires = exptime.UTC()
//skip:
//	theCookie.MaxAge = MaxAge
//	theCookie.Secure = Secure
//	theCookie.HttpOnly = HttpOnly
//	return
//}

func IsTLS(c *gin.Context) bool {
	if c.Request.TLS == nil {
		return false
	}
	return true
}

/* vim: set noai ts=4 sw=4: */
