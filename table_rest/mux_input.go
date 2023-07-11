package table_rest

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

type MuxInput struct {
	Name                string      `json:"Name"`                           //	Field Name
	AltName             []string    `json:"AltName,omitempty"`              // Alternate names list - if ReqVar is not there then pull each of these and set as ReqVar
	Label               string      `json:"Label,omitempty"`                //	Used for auto-generation of forms - this is the printed label for input.
	Default             string      `json:"Dflt,omitempty"`                 //	Default if not specified in input
	Type                string      `json:"Ty"`                             //	Type { 's', 'i', 'f', 'u' }
	MinLen              int         `json:"MinLen"`                         //	If > 0 then the minimum length - not checked if 0
	MaxLen              int         `json:"MaxLen"`                         //	If > 0 then the maximum length - not checked if 0
	Required            bool        `json:"Required"`                       //	If true then this is a required value.
	Validate            string      `json:"Val,omitempty"`                  //	A named validation like "email" or "us_zip" can be extended with calls to AddValidationFunction
	ValidationData      interface{} `json:"ValData"`                        //	Set of Data
	ListCaseInsenstivie bool        `json:"ListCaseInsenstitive,omitempty"` // if true then convert to lower case before lookup ('s' type only)
	ListValues          []string    `json:"ListValues,omitempty"`           //	A named validation like "email" or "us_zip" can be extended with calls to AddValidationFunction
	IsSecret            bool        `json:"IsSecret"`                       // xyzzy TODO - do not log secret values (value replace with encrypted entry)
	LineFile            string      `json:"-"`                              //	What line was it called from
	MinVal              int64       `json:"MinVal"`                         //	Integer Value Range Inclusive
	MaxVal              int64       `json:"MaxValLen"`                      //	Integer Value Range Inclusive
	UseMinVal           bool        `json:"UseMinVal"`                      //	Integer Value Range Inclusive
	UseMaxVal           bool        `json:"UseMaxVal"`                      //	Integer Value Range Inclusive
	BindToName          string      `json:"BindToName,omitempty"`           // New - bind to this name in a struct. xyzzy TODO
	ReMatch             string      `json:"ReMatch,omitempty"`              // A regular expression that the input must match (strings)
	Comment             string      `json:"Comment,omitempty"`              //	A User Comment
	Schema              string      `json:"Schema,omitempty"`               // A JSON Schema for validation
}

/* vim: set noai ts=4 sw=4: */
