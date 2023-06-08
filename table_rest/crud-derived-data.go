package table_rest

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import "net/http"

// Crud Output Filters

// Examples of Output Filters
// 1. create new column under new name
// 2. rename a column, go from "id" to "User ID"
// 3. Genrate a QR code URL, using data
// 4. Filter data - base45
// 5. Encrypte data
// 6. Sign Data
// 7.
// 8. use cookie to save modified "state"
// 9. Convert data type to correct representation (table data -> JSON, XML, CSV etc) -- Set headers
// 10. Set Cross-Site-Origin headers

// Examples of Input Filters
// 1. Check Auth
// 2. use cookie to get "state"
// 3. removal of input variables __user_id__ for example
// 4. Add input values __IsLoggedIn__, __AuthGroup__
// 5. Pick out X-Auth-Berer for example.

type RowOrColumn int

const (
	IsSingleColumn RowOrColumn = 1
	IsEntireRow    RowOrColumn = 2
)

type FilterFunctionType func(www http.ResponseWriter, req *http.Request, pp PrePostFlag, cfgData, inData string) (outData string, status StatusType, err error)

type CrudOutputFilter struct {
	FilterName     string // Used on front end to pick "defined" filters
	InputType      RowOrColumn
	FilterFunction FilterFunctionType
	// creates new column
	// removes old column
}

/*

type PrePostFlag int

const (
	PreFlag  PrePostFlag = 1
	PostFlag PrePostFlag = 2
)

type PrePostFx func(www http.ResponseWriter, req *http.Request, pp PrePostFlag, cfgData, inData string) (outData string, status StatusType, err error)

// see: pre-post.go

// see: https://www.twilio.com/blog/node-js-proxy-server

*/
