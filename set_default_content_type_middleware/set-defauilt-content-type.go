package set_default_content_type_middleware

// Copyright (C) Philip Schlump 2015-2018, 2022
// MIT Licensed
// Source pulled from piserver Demo Server

import (
	"github.com/gin-gonic/gin"
)

// SetContentType is middleware for Gin that will set a default content type.
// If the "Content-Type" header is not set, this will default it to
//
//	c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
func SetContentType(c *gin.Context) {

	method := c.Request.Method
	content_type := c.Request.Header.Get("Content-Type")

	if method == "POST" || method == "PUT" {
		if content_type == "" {
			// dbgo.Printf("%(red)------------ Setting Conent Type ---------------\n")
			c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	c.Next()

}

/* vim: set noai ts=4 sw=4: */
