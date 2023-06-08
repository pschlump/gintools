package ethProc

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import "github.com/gin-gonic/gin"

func SetupMux(router *gin.Engine) {

	//	// ----------------------------------------------------------------------------------------------------------------------------------------------
	//	// Key Management
	//	// ----------------------------------------------------------------------------------------------------------------------------------------------
	//	//api/key/privatekey/ send private key - generate a keyfile using privatekey - store with user.
	//	//api/key/keyfile/ send private key - generate a keyfile using privatekey - store with user.
	//	/*
	//		mux.Handle("/api/key/PrivateKey", http.HandlerFunc(HandlePrivateKey)).AuthRequired().DocTag("<h2>/api/key/PrivateKey").Method("GET", "POST").Inputs([]*ymux.MuxInput{
	//			{Name: "title", Required: true, Label: "Unique title for this key", MinLen: 1, Type: "s"},
	//			{Name: "username", Required: true, Label: "Username", MinLen: 1, Type: "s"},
	//			{Name: "password", Required: true, Label: "Password", MinLen: 1, Type: "s"},
	//			{Name: "public_key", Required: true, Label: "Public Key", MinLen: 1, Type: "s"},
	//			{Name: "private_key", Required: true, Label: "Private Key", MinLen: 1, Type: "s"},
	//			{Name: "network", Required: true, Label: "Network", MinLen: 1, Type: "s"},
	//		})
	//		mux.Handle("/api/key/KeyFile", http.HandlerFunc(HandleKeyFile)).AuthRequired().DocTag("<h2>/api/key/KeyFile").Method("GET", "POST").Inputs([]*ymux.MuxInput{
	//			{Name: "title", Required: true, Label: "Unique title for this key", MinLen: 1, Type: "s"},
	//			{Name: "username", Required: true, Label: "Username", MinLen: 1, Type: "s"},
	//			{Name: "password", Required: true, Label: "Password For Login", MinLen: 1, Type: "s"},
	//			{Name: "keyfile_password", Required: true, Label: "Password For Keyfile", MinLen: 1, Type: "s"},
	//			{Name: "account", Required: true, Label: "Account", MinLen: 1, Type: "s"},
	//			{Name: "json_keyfile", Required: true, Label: "JSON Data", MinLen: 1, Type: "s"},
	//			{Name: "network", Required: true, Label: "Network", MinLen: 1, Type: "s"},
	//		})
	//		mux.Handle("/api/key/DeleteKey", http.HandlerFunc(HandleDeleteKey)).AuthRequired().DocTag("<h2>/api/key/DeleteKey").Method("GET", "POST").Inputs([]*ymux.MuxInput{
	//			{Name: "title", Required: true, Label: "Unique title for this key", MinLen: 1, Type: "s"},
	//			{Name: "username", Required: true, Label: "Username", MinLen: 1, Type: "s"},
	//			{Name: "password", Required: true, Label: "Password", MinLen: 1, Type: "s"},
	//		})
	//		mux.Handle("/api/key/ValidateKey", http.HandlerFunc(HandleValidateKey)).AuthRequired().DocTag("<h2>/api/key/ValidateKey").Method("GET").Inputs([]*ymux.MuxInput{
	//			{Name: "title", Required: true, Label: "Unique title for this key", MinLen: 1, Type: "s"},
	//			{Name: "username", Required: true, Label: "Username", MinLen: 1, Type: "s"},
	//			{Name: "password", Required: true, Label: "Password", MinLen: 1, Type: "s"},
	//			{Name: "password_keyfile", Required: true, Label: "Password For Keyfile", MinLen: 1, Type: "s"},
	//			{Name: "account", Required: true, Label: "Account", MinLen: 1, Type: "s"},
	//		})
	//	*/

	//	// router.POST("/api/v1/eth/PrivateKey", vv.Fx)

	router.POST("/api/v1/SendTokens", SendTokensHandler)
}

func SendTokensHandler(c *gin.Context) {
}
