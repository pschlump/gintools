package table_rest

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/uuid"
	"github.com/pschlump/verhoeff_algorithm"
	"github.com/xeipuuv/gojsonschema"
)

// Input              []*MuxInput    `json:"Input"`              //
func ValidateValidationTypeAtCompileData(Input []*MuxInput, ns int) (err error) {
	for _, vv := range Input {
		switch vv.Type {
		case "n/a":
		case "i", "int":
		case "ds": // digit string
		case "c", "card":
		case "u", "uuid":
		case "f", "float":
		case "b", "bool", "boolean":
		case "", "s", "str", "string", "file", "dt", "date", "date-time", "csv":
		case "j", "json":
		default:
			err = fmt.Errorf("Invalid validation type: [%s], expected one of {i,ds,c,u,f,b,s} called from: %s at:%s", vv.Type, vv.LineFile, dbgo.LF(ns))
			return
		}
	}
	return
}

// ValidateInputParameters checks input values for type and value.  Also processing of AltNames and Defaults.
// ORIG: func (mux *ServeMux) ValidateInputParameters(c *gin.Context, kInOrd int) (err error) {
func ValidateInputParameters(c *gin.Context, Input []*MuxInput) (pname string, err error) {

	// Look in InOrd for paramters a postion kInOrd - validate all the required stuff.
	// mux.InOrd[kInOrd].Input
	/*
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
			BindToName          string      `json:"BindToName"`                     // New - bind to this name in a struct. xyzzy TODO
			ReMatch             string      `json:"ReMatch,omitempty"`              // A regular expression that the input must match (strings)
		}
	*/

	// Interface to names/values
	// allNames := GetNameList(www, c.Request)			GetKeysFromMap()
	// found, val := GetVar(name, www, c.Request)
	// SetValue(www, c.Request, name, val)
	/*
		return ValidationFunction ( www, c.Request,
			mux.InOrd[kInOrd].NoValidate,
			mux.InOrd[kInOrd].Input,
			-2,			 							// depth in call
			func ( ) {								// list of names
				return GetNameList (www, c.Request)
			},
			func ( name ) string, bool {			// get value for data
				a, b := GetVar( name, www, c.Request )
				return b, a
			},
			func ( name string, val string ) {		// set value back into data
				SetValue(www, c.Request, name, val)
			},
		)
		return ValidationFunction ( www, c.Request,
			CrudData.NoValidate,	// ??? - from CrudBaseConfig -- we have it.
			CrudData.Input,			// ??? - from CrudBaseConfig -- we have it. -- which .Input?
			-2,			 							// depth in call
			func ( ) {								// list of names
				return GetKeysFromMap (dMa)
			},
			func ( name ) string, bool {			// get value for data
				a, b := dMa[name]
				return a, b
			},
			func ( name string, val string ) {		// set value back into data
				dMa[name] = val
			},
		)
		??
		GET_InputList    []*MuxInput          // Validation of inputs for htis call, if len(0) then no validation takes place.
		PUT_InputList    []*MuxInput          // Validation of inputs for htis call, if len(0) then no validation takes place.
		POST_InputList   []*MuxInput          // Validation of inputs for htis call, if len(0) then no validation takes place.
		DELETE_InputList []*MuxInput          // Validation of inputs for htis call, if len(0) then no validation takes place.
		InputList        []*MuxInput          // Validation of inputs for htis call, if len(0) then no validation takes place. -- This is for "All" and excludes use of per-method stuff

	*/
	// ORIG: fmt.Fprintf(os.Stderr, "Mux Input Validation: %s atat: %s\n", dbgo.SVarI(mux.InOrd[kInOrd].Input), dbgo.LF())
	return ValidationFunctionCommon(c,
		// ORIG: mux.InOrd[kInOrd].NoValidate,
		false,
		-2,
		/*FxGetNameList*/ func() []string {
			// dbgo.Printf("%(yellow) at:%(LF) GetNameList\n")
			return GetNameList(c)
		},
		/*FxGetDataValue*/ func(name string) (string, bool) {
			// dbgo.Printf("%(yellow) at:%(LF) GetVar\n")
			a, b := GetVar(name, c)
			return b, a
		},
		/*FxSetDataValue*/ func(name, val string) {
			// dbgo.Printf("%(yellow) at:%(LF) SetValue !!!!!!!!!!!!!!!!!!!!!\n")
			SetValue(c, name, val)
		},
		// OIG: mux.InOrd[kInOrd].Input, // Input []*MuxInput,
		Input, // Input []*MuxInput,
		gCfg.LogFileEncryptionKey,
	)

}

// ValidationFunction checks input values for type and value.  Also processing of AltNames and Defaults.
func ValidationFunctionCommon(c *gin.Context, NoValidate bool, depth int,
	FxGetNameList func() []string,
	FxGetDataValue func(name string) (string, bool),
	FxSetDataValue func(name, val string),
	Input []*MuxInput,
	LogFileEncryptionKey string,
) (pname string, err error) {

	// Look in InOrd for paramters a postion kInOrd - validate all the required stuff.
	// mux.InOrd[kInOrd].Input
	/*
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
			BindToName          string      `json:"BindToName"`                     // New - bind to this name in a struct. xyzzy TODO
			ReMatch             string      `json:"ReMatch,omitempty"`              // A regular expression that the input must match (strings)
		}
	*/

	if NoValidate {
		fmt.Fprintf(os.Stderr, "%sValidation Intentionally Skipped URI=[%s%s%s] --??Static File?? -- No validation requested. AT: %s%s\n", dbgo.ColorGreen, dbgo.ColorReset, c.Request.URL, dbgo.ColorGreen, dbgo.LF(), dbgo.ColorReset)
		fmt.Fprintf(logFilePtr, "Validation Intentionally Skipped URI=[%s] -- ??Static File?? --No validation requested. AT: %s\n", c.Request.URL, dbgo.LF())
		return
	} else {
		fmt.Fprintf(os.Stderr, "%sValidation On URI=[%s%s%s] AT: %s%s\n", dbgo.ColorGreen, dbgo.ColorReset, c.Request.URL, dbgo.ColorGreen, dbgo.LF(), dbgo.ColorReset)
		fmt.Fprintf(logFilePtr, "Validation ON URI=[%s] AT: %s\n", c.Request.URL, dbgo.LF())
	}

	var LookupIsSecret = func(name string) (isSecret bool) {
		for _, vv := range Input {
			if vv.Name == name {
				return vv.IsSecret
			}
		}
		return false
	}

	var EncIfSecret = func(name, val string) (rv string) {
		rv = val
		if rv != "" {
			isSecret := LookupIsSecret(name)
			if isSecret {
				rv = EncryptTextToB64([]byte(LogFileEncryptionKey), []byte(val))
			}
		}
		return
	}

	// fmt.Fprintf(os.Stderr, "%sURL (%s) -- Validation Start AT: %s%s\n", dbgo.ColorCyan, c.Request.URL, dbgo.LF(), dbgo.ColorReset)
	fmt.Fprintf(logFilePtr, "URL (%s) -- Validation Start AT: %s\n", c.Request.URL, dbgo.LF())
	// allNames := GetNameList(www, c.Request)
	allNames := FxGetNameList()
	for _, name := range allNames {
		val, found := FxGetDataValue(name)
		if !found {
			val = ""
		}
		// fmt.Fprintf(os.Stderr, "%s   name[%s] initial value [%s]%s\n", dbgo.ColorCyan, name, EncIfSecret(name, val), dbgo.ColorReset)
		fmt.Fprintf(logFilePtr, "   name[%s] initial value [%s]\n", name, EncIfSecret(name, val))
	}

	empty_input := true
	for _, vv := range Input {
		empty_input = false
		name := vv.Name
		pname = vv.Name
		// fmt.Fprintf(os.Stderr, "%s   Validation of name [%s] AT: %s%s\n", dbgo.ColorCyan, name, dbgo.LF(), dbgo.ColorReset)
		// fmt.Fprintf(logFilePtr, "%s   Validation of name [%s] AT: %s%s\n", dbgo.ColorCyan, name, dbgo.LF(), dbgo.ColorReset)

		// func GetVar(name string, c *gin.Context) (found bool, value string) {
		val, found := FxGetDataValue(name)

		if !found || val == "" && len(vv.AltName) > 0 {
			if db400 {
				fmt.Fprintf(os.Stderr, "%s -------------------------- AltName Activated For %s => %s ---------------------------------\n at %s %s\n", dbgo.ColorYellow, name, dbgo.SVar(vv.AltName), dbgo.LF(), dbgo.ColorReset)
			}
			fmt.Fprintf(os.Stderr, "%s -------------------------- AltName Activated For %s => %s ---------------------------------\n at %s %s\n", dbgo.ColorYellow, name, dbgo.SVar(vv.AltName), dbgo.LF(), dbgo.ColorReset)
			for _, an := range vv.AltName {
				if db400 {
					fmt.Fprintf(os.Stderr, "%s Search For: %s %s\n", dbgo.ColorYellow, an, dbgo.ColorReset)
				}
				val, found = FxGetDataValue(an)
				if found {
					if db400 {
						fmt.Fprintf(os.Stderr, "%s Found : %s with value [%s] %s\n", dbgo.ColorYellow, an, EncIfSecret(an, val), dbgo.ColorReset)
					}
					FxSetDataValue(name, val)
					break
				}
			}
		}

		if !found {
			// fmt.Fprintf(os.Stderr, "%sAT: %s%s\n", dbgo.ColorCyan, dbgo.LF(), dbgo.ColorReset)
			if vv.Default != "" {
				dbgo.DbPrintf("MuxRewriteRequest.01", "Using vv.Default [%s]\n", vv.Default)
				FxSetDataValue(name, vv.Default)
				val = vv.Default
			} else if vv.Required {
				err = fmt.Errorf("Missing [%s] - Required Parameter", name)
				// fmt.Fprintf(os.Stderr, "%s   Validation Failed name=[%s] missing value is required AT: %s%s\n", dbgo.ColorCyan, name, dbgo.LF(), dbgo.ColorReset)
				// fmt.Fprintf(logFilePtr, "   Validation Failed name=[%s] missing value is required AT: %s\n", name, dbgo.LF())
				return
			}
			if db405 {
				fmt.Fprintf(os.Stderr, "%sAT: %s%s\n", dbgo.ColorCyan, dbgo.LF(), dbgo.ColorReset)
			}
		}

		// Changes to this switch requires corresponding changes above!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		// fmt.Fprintf(os.Stderr, "%sAT: %s%s\n", dbgo.ColorCyan, dbgo.LF(), dbgo.ColorReset)
		switch vv.Type {
		case "n/a":
			// Ignore type.
		case "j", "json":
			//
			schemaLoader := gojsonschema.NewStringLoader(vv.Schema)
			documentLoader := gojsonschema.NewStringLoader(val)

			result, e09 := gojsonschema.Validate(schemaLoader, documentLoader)
			if e09 != nil {
				err = e09
				err = fmt.Errorf("Parameter [%s] - Invalid JSON Schema Value [%s]", name, err)
				fmt.Fprintf(os.Stderr, "%s    JSON schema failed to valiate name=[%s] error=[%s]%s\n", dbgo.ColorRed, name, err, dbgo.ColorReset)
				fmt.Fprintf(logFilePtr, "    JSON schema failed to valiate name=[%s] error=[%s]\n", name, err)
				return
			}

			if !result.Valid() {
				// fmt.Fprintf(logFilePtr, "%s is invalid.\nErrors:\n", *Data)
				for _, desc := range result.Errors() {
					fmt.Fprintf(logFilePtr, "- %s\n", desc)
				}
				err = fmt.Errorf("Parameter [%s] - Invalid JSON Data Value [%s]", name, err)
				fmt.Fprintf(os.Stderr, "%s    JSON Data failed to valiate name=[%s] error=[%s]%s\n", dbgo.ColorRed, name, err, dbgo.ColorReset)
				fmt.Fprintf(logFilePtr, "    JSON Data failed to valiate name=[%s] error=[%s]\n", name, err)
				return
			}
		case "b", "bool", "boolean":
			if !vv.Required && val == "" {
			} else {
				ok := IsBool(val)
				if !ok {
					err = fmt.Errorf("Parameter [%s] - Invalid Boolean Value [%s] - Try Yes/No", name, EncIfSecret(name, val))
					fmt.Fprintf(os.Stderr, "%s    boolean failed to valiate name=[%s] value=[%s]%s\n", dbgo.ColorRed, name, EncIfSecret(name, val), dbgo.ColorReset)
					fmt.Fprintf(logFilePtr, "    boolean failed to valiate name=[%s] value=[%s]\n", name, EncIfSecret(name, val))
					return
				}
			}
		case "i", "int":
			if !vv.Required && val == "" {
			} else {
				_, err = strconv.ParseInt(val, 10, 64)
				if err != nil {
					err = fmt.Errorf("Parameter [%s] - Invalid Integer Value [%s] - error [%s]", name, EncIfSecret(name, val), err)
					fmt.Fprintf(os.Stderr, "%s    integer failed to valiate name=[%s] value=[%s]%s\n", dbgo.ColorRed, name, EncIfSecret(name, val), dbgo.ColorReset)
					fmt.Fprintf(logFilePtr, "    integer failed to valiate name=[%s] value=[%s]\n", name, EncIfSecret(name, val))
					return
				}
				var nv int64
				nv, err = strconv.ParseInt(val, 10, 64)
				if vv.UseMinVal {
					if len(val) == 0 && !vv.Required {
					} else if nv < vv.MinVal {
						err = fmt.Errorf("Parameter [%s] - Invalid value %d less than minimum %d", name, nv, vv.MinVal)
						fmt.Fprintf(os.Stderr, "%s    Too small(%d) valiate name=[%s] value=[%s]%s\n", dbgo.ColorRed, vv.MinVal, name, EncIfSecret(name, val), dbgo.ColorReset)
						fmt.Fprintf(logFilePtr, "    Too small(%d) name=[%s] value=[%s]\n", vv.MinVal, name, EncIfSecret(name, val))
						return
					}
				}
				if vv.UseMaxVal {
					if nv > vv.MaxVal {
						err = fmt.Errorf("Parameter [%s] - Invalid value %d exceeds maximum %d", name, nv, vv.MaxVal)
						fmt.Fprintf(os.Stderr, "%s    Too large(%d) valiate name=[%s] value=[%s]%s\n", dbgo.ColorRed, vv.MaxVal, name, EncIfSecret(name, val), dbgo.ColorReset)
						fmt.Fprintf(logFilePtr, "    Too large(%d) name=[%s] value=[%s]\n", vv.MaxVal, name, EncIfSecret(name, val))
						return
					}
				}
				if len(vv.ListValues) > 0 {
					if !InArray(val, vv.ListValues) {
						err = fmt.Errorf("Parameter [%s] - value [%s] not in list of valid values %s", name, val, dbgo.SVar(vv.ListValues))
						fmt.Fprintf(os.Stderr, "%s    Parameter [%s] - value [%s] not in list of valid values %s%s\n", dbgo.ColorRed, name, val, dbgo.SVar(vv.ListValues), dbgo.ColorReset)
						fmt.Fprintf(logFilePtr, "    Parameter [%s] - value [%s] not in list of valid values %s\n", name, val, dbgo.SVar(vv.ListValues))
						return
					}
				}
			}
		case "ds": // Digit strings can be long/larger than an INT - but composed of 0...9 only.
			if !vv.Required && val == "" {
			} else {
				if !verhoeff_algorithm.IsInt(val) {
					err = fmt.Errorf("Parameter [%s] - Invalid String of Digits Value [%s]", name, val)
					fmt.Fprintf(os.Stderr, "%s    string(verhoeff) failed to valiate name=[%s] value=[%s]%s\n", dbgo.ColorRed, name, EncIfSecret(name, val), dbgo.ColorReset)
					fmt.Fprintf(logFilePtr, "    string(verhoeff) failed to valiate name=[%s] value=[%s]\n", name, EncIfSecret(name, val))
					return
				}
				if vv.MinLen > 0 {
					if len(val) == 0 && !vv.Required {
					} else if len(val) < vv.MinLen {
						err = fmt.Errorf("Parameter [%s] - Invalid Length %d less than minimum %d", name, len(val), vv.MinLen)
						fmt.Fprintf(os.Stderr, "%s    Too short(%d) valiate name=[%s] value=[%s]%s\n", dbgo.ColorRed, vv.MinLen, name, EncIfSecret(name, val), dbgo.ColorReset)
						fmt.Fprintf(logFilePtr, "    Too short(%d) name=[%s] value=[%s]\n", vv.MinLen, name, EncIfSecret(name, val))
						return
					}
				}
				if vv.MaxLen > 0 {
					if len(val) > vv.MaxLen {
						err = fmt.Errorf("Parameter [%s] - Invalid Length %d exceeds maximum %d", name, len(val), vv.MaxLen)
						fmt.Fprintf(os.Stderr, "%s    Too long(%d) valiate name=[%s] value=[%s]%s\n", dbgo.ColorRed, vv.MaxLen, name, EncIfSecret(name, val), dbgo.ColorReset)
						fmt.Fprintf(logFilePtr, "    Too long(%d) name=[%s] value=[%s]\n", vv.MaxLen, name, EncIfSecret(name, val))
						return
					}
				}
				if len(vv.ListValues) > 0 {
					if !InArray(val, vv.ListValues) {
						err = fmt.Errorf("Parameter [%s] - value [%s] not in list of valid values %s", name, val, dbgo.SVar(vv.ListValues))
						fmt.Fprintf(os.Stderr, "%s    Parameter [%s] - value [%s] not in list of valid values %s%s\n", dbgo.ColorRed, name, val, dbgo.SVar(vv.ListValues), dbgo.ColorReset)
						fmt.Fprintf(logFilePtr, "    Parameter [%s] - value [%s] not in list of valid values %s\n", name, val, dbgo.SVar(vv.ListValues))
						return
					}
				}
			}
		case "c", "card":
			fmt.Fprintf(os.Stderr, "AT:%s ->%s<- %v\n", dbgo.LF(), val, vv.Required)
			if !vv.Required && val == "" {
				fmt.Fprintf(os.Stderr, "AT:%s\n", dbgo.LF())
			} else {
				fmt.Fprintf(os.Stderr, "AT:%s\n", dbgo.LF())
				var nv int64
				nv, err = strconv.ParseInt(val, 10, 64)
				if err != nil {
					err = fmt.Errorf("Parameter [%s] - Invalid Integer Value [%s] - error [%s]", name, EncIfSecret(name, val), err)
					fmt.Fprintf(os.Stderr, "%s    Integer failed to valiate name=[%s] value=[%s]%s\n", dbgo.ColorRed, name, EncIfSecret(name, val), dbgo.ColorReset)
					fmt.Fprintf(logFilePtr, "    Integer failed to valiate name=[%s] value=[%s]\n", name, EncIfSecret(name, val))
					return
				}
				if nv < 0 {
					err = fmt.Errorf("Parameter [%s] - Invalid Integer Value [%s] - must be positive - error [%s]", name, EncIfSecret(name, val), err)
					fmt.Fprintf(os.Stderr, "%s    Cardinal failed to valiate name=[%s] value=[%s]%s\n", dbgo.ColorRed, name, EncIfSecret(name, val), dbgo.ColorReset)
					fmt.Fprintf(logFilePtr, "    Cardinal failed to valiate name=[%s] value=[%s]\n", name, EncIfSecret(name, val))
					return
				}
				if len(vv.ListValues) > 0 {
					if !InArray(val, vv.ListValues) {
						err = fmt.Errorf("Parameter [%s] - value [%s] not in list of valid values %s", name, val, dbgo.SVar(vv.ListValues))
						fmt.Fprintf(os.Stderr, "%s    Parameter [%s] - value [%s] not in list of valid values %s%s\n", dbgo.ColorRed, name, val, dbgo.SVar(vv.ListValues), dbgo.ColorReset)
						fmt.Fprintf(logFilePtr, "    Parameter [%s] - value [%s] not in list of valid values %s\n", name, val, dbgo.SVar(vv.ListValues))
						return
					}
				}
			}
		case "u", "uuid":
			if !vv.Required && val == "" {
			} else {
				if !uuid.IsUUID(val) {
					err = fmt.Errorf("Parameter [%s] - Invalid UUID [%s]", name, EncIfSecret(name, val))
					fmt.Fprintf(os.Stderr, "%s    UUID failed to valiate name=[%s] value=[%s]%s\n", dbgo.ColorRed, name, EncIfSecret(name, val), dbgo.ColorReset)
					fmt.Fprintf(logFilePtr, "    UUID failed to valiate name=[%s] value=[%s]\n", name, EncIfSecret(name, val))
					return
				}
			}
		case "f", "float":
			if !vv.Required && val == "" {
			} else {
				_, err = strconv.ParseFloat(val, 10)
				if err != nil {
					err = fmt.Errorf("Parameter [%s] - Invalid Float Value [%s] - error [%s]", name, EncIfSecret(name, val), err)
					fmt.Fprintf(os.Stderr, "%s    Float failed to valiate name=[%s] value=[%s]%s\n", dbgo.ColorRed, name, EncIfSecret(name, val), dbgo.ColorReset)
					fmt.Fprintf(logFilePtr, "    Float failed to valiate name=[%s] value=[%s]\n", name, EncIfSecret(name, val))
					return
				}
			}
		case "s", "str", "string", "file", "dt", "date", "date-time", "csv":
			// xyzzy444 - TODO - add regexp check for strings
			// fmt.Fprintf(os.Stderr, "%sname [%s] val ->%s<- len=%d vv.Required=%v, at:%s%s\n", dbgo.ColorCyan, name, EncIfSecret(name, val), len(val), vv.Required, dbgo.LF(), dbgo.ColorReset)
			// PJS new Tue Oct 19 05:44:46 MDT 2021
			if vv.Type == "csv" {
				ss := strings.Split(val, ",") // TODO : Should be a CSV split w/ embeded quote marks. (and trim of blanks? )
				for _, vx := range ss {
					if vv.ReMatch != "" {
						re, err := regexp.Compile(vv.ReMatch)
						if err != nil {
							err = fmt.Errorf("Parameter [%s] - Invalid Regular Expression [%s] error: %s", name, vv.ReMatch, err)
							fmt.Fprintf(os.Stderr, "%s    Parameter [%s] - Invalid Regular Expression [%s] error: %s %s\n", dbgo.ColorRed, name, vv.ReMatch, err, dbgo.ColorReset)
							fmt.Fprintf(logFilePtr, "    Parameter [%s] - Invalid Regular Expression [%s] error: %s\n", name, vv.ReMatch, err)
							return pname, err
						}
						if !re.MatchString(vx) {
							err = fmt.Errorf("Parameter [%s] - Failed to match [%s] data [%s]", name, vv.ReMatch, vx)
							fmt.Fprintf(os.Stderr, "%s    Parameter [%s] - Failed to match [%s] data [%s] %s\n", dbgo.ColorRed, name, vv.ReMatch, vx, dbgo.ColorReset)
							fmt.Fprintf(logFilePtr, "    Parameter [%s] - Failed to match [%s] data [%s]\n", name, vv.ReMatch, vx)
							return pname, err
						}
					}

					// check min/max length
					if len(vx) == 0 && !vv.Required {
					} else if vv.MinLen > 0 {
						if len(vx) < vv.MinLen {
							err = fmt.Errorf("Parameter [%s] - Invalid Length %d less than minimum %d", name, len(vx), vv.MinLen)
							fmt.Fprintf(os.Stderr, "%s    Too short(%d) valiate name=[%s] value=[%s]%s\n", dbgo.ColorRed, vv.MinLen, name, EncIfSecret(name, vx), dbgo.ColorReset)
							fmt.Fprintf(logFilePtr, "    Too short(%d) name=[%s] value=[%s]\n", vv.MinLen, name, EncIfSecret(name, vx))
							return
						}
					}
					if vv.MaxLen > 0 {
						if len(vx) >= vv.MaxLen {
							err = fmt.Errorf("Parameter [%s] - Invalid Length %d exceeds maximum %d", name, len(vx), vv.MaxLen)
							fmt.Fprintf(os.Stderr, "%s    Too long(%d) valiate name=[%s] value=[%s]%s\n", dbgo.ColorRed, vv.MaxLen, name, EncIfSecret(name, vx), dbgo.ColorReset)
							fmt.Fprintf(logFilePtr, "    Too long(%d) name=[%s] value=[%s]\n", vv.MaxLen, name, EncIfSecret(name, vx))
							return
						}
					}
					if len(vv.ListValues) > 0 {
						valTmp := vx
						if vv.ListCaseInsenstivie {
							valTmp = strings.ToLower(vx)
						}
						if !InArray(valTmp, vv.ListValues) {
							err = fmt.Errorf("Parameter [%s] - value [%s] not in list of valid values %s", name, valTmp, dbgo.SVar(vv.ListValues))
							fmt.Fprintf(os.Stderr, "%s    Parameter [%s] - value [%s] not in list of valid values %s%s\n", dbgo.ColorRed, name, valTmp, dbgo.SVar(vv.ListValues), dbgo.ColorReset)
							fmt.Fprintf(logFilePtr, "    Parameter [%s] - value [%s] not in list of valid values %s\n", name, valTmp, dbgo.SVar(vv.ListValues))
							return
						}
					}
				}
			} else {
				if vv.ReMatch != "" {
					re, err := regexp.Compile(vv.ReMatch)
					if err != nil {
						err = fmt.Errorf("Parameter [%s] - Invalid Regular Expression [%s] error: %s", name, vv.ReMatch, err)
						fmt.Fprintf(os.Stderr, "%s    Parameter [%s] - Invalid Regular Expression [%s] error: %s %s\n", dbgo.ColorRed, name, vv.ReMatch, err, dbgo.ColorReset)
						fmt.Fprintf(logFilePtr, "    Parameter [%s] - Invalid Regular Expression [%s] error: %s\n", name, vv.ReMatch, err)
						return pname, err
					}
					if !re.MatchString(val) {
						err = fmt.Errorf("Parameter [%s] - Failed to match [%s] data [%s]", name, vv.ReMatch, val)
						fmt.Fprintf(os.Stderr, "%s    Parameter [%s] - Failed to match [%s] data [%s] %s\n", dbgo.ColorRed, name, vv.ReMatch, val, dbgo.ColorReset)
						fmt.Fprintf(logFilePtr, "    Parameter [%s] - Failed to match [%s] data [%s]\n", name, vv.ReMatch, val)
						return pname, err
					}
				}

				// check min/max length
				if len(val) == 0 && !vv.Required {
				} else if vv.MinLen > 0 {
					if len(val) < vv.MinLen {
						err = fmt.Errorf("Parameter [%s] - Invalid Length %d less than minimum %d", name, len(val), vv.MinLen)
						fmt.Fprintf(os.Stderr, "%s    Too short(%d) valiate name=[%s] value=[%s]%s\n", dbgo.ColorRed, vv.MinLen, name, EncIfSecret(name, val), dbgo.ColorReset)
						fmt.Fprintf(logFilePtr, "    Too short(%d) name=[%s] value=[%s]\n", vv.MinLen, name, EncIfSecret(name, val))
						return
					}
				}
				if vv.MaxLen > 0 {
					if len(val) > vv.MaxLen {
						err = fmt.Errorf("Parameter [%s] - Invalid Length %d exceeds maximum %d", name, len(val), vv.MaxLen)
						fmt.Fprintf(os.Stderr, "%s    Too long(%d) valiate name=[%s] value=[%s]%s\n", dbgo.ColorRed, vv.MaxLen, name, EncIfSecret(name, val), dbgo.ColorReset)
						fmt.Fprintf(logFilePtr, "    Too long(%d) name=[%s] value=[%s]\n", vv.MaxLen, name, EncIfSecret(name, val))
						return
					}
				}
				// PJS New Mon Sep 27 11:48:22 MDT 2021
				if len(vv.ListValues) > 0 {
					// 	ListCaseInsenstivie bool        `json:"ListCaseInsenstitive,omitempty"` // if true then convert to lower case before lookup ('s' type only)
					valTmp := val
					if vv.ListCaseInsenstivie {
						valTmp = strings.ToLower(val)
					}
					if !InArray(valTmp, vv.ListValues) {
						err = fmt.Errorf("Parameter [%s] - value [%s] not in list of valid values %s", name, valTmp, dbgo.SVar(vv.ListValues))
						fmt.Fprintf(os.Stderr, "%s    Parameter [%s] - value [%s] not in list of valid values %s%s\n", dbgo.ColorRed, name, valTmp, dbgo.SVar(vv.ListValues), dbgo.ColorReset)
						fmt.Fprintf(logFilePtr, "    Parameter [%s] - value [%s] not in list of valid values %s\n", name, valTmp, dbgo.SVar(vv.ListValues))
						return
					}
				}
			}
		case "none": // no validation type
		case "":
			// xyzzy - fix - TODO
			// err = fmt.Errorf("Parameter [%s] - value [%s] invalid validation type %s", name, valTmp, dbgo.SVar(vv.ListValues))
			// fmt.Fprintf(os.Stderr, "%s    Parameter [%s] - value [%s] invalid validation type values %s%s\n", dbgo.ColorRed, name, valTmp, dbgo.SVar(vv.ListValues), dbgo.ColorReset)
			// fmt.Fprintf(logFilePtr, "    Parameter [%s] - value [%s] invalid validation type %s\n", name, valTmp, dbgo.SVar(vv.ListValues))
		default:
			// xyzzy - fix - TODO
			// err = fmt.Errorf("Parameter [%s] - value [%s] invalid validation type %s", name, valTmp, dbgo.SVar(vv.ListValues))
			// fmt.Fprintf(os.Stderr, "%s    Parameter [%s] - value [%s] invalid validation type values %s%s\n", dbgo.ColorRed, name, valTmp, dbgo.SVar(vv.ListValues), dbgo.ColorReset)
			// fmt.Fprintf(logFilePtr, "    Parameter [%s] - value [%s] invalid validation type %s\n", name, valTmp, dbgo.SVar(vv.ListValues))
			// panic(fmt.Sprintf("invalid validation type: [%s] at %s", vv.Type, dbgo.LF(-2)))
		}
		if vv.Validate != "" {
			validationLock.RLock()
			fx, ok := namedChecks[vv.Validate]
			defer validationLock.RUnlock()
			if ok {
				if !fx(val, vv.ValidationData, vv.ListValues) {
					err = fmt.Errorf("Parameter [%s] - Invalid [%s] value [%s]", name, vv.Validate, EncIfSecret(name, val))
					return
				}
			} else {
				err = fmt.Errorf("Parameter [%s] - invalid named check [%s]", name, vv.Validate)
				return
			}
		}
	}

	if empty_input {
		// fmt.Fprintf(os.Stderr, "%sURL (%s) -- No fields to validate. AT: %s%s\n", dbgo.ColorYellow, c.Request.URL, dbgo.LF(), dbgo.ColorReset)
		fmt.Fprintf(logFilePtr, "URL (%s) -- No fields to validate. AT: %s\n", c.Request.URL, dbgo.LF())
	} else {
		// fmt.Fprintf(os.Stderr, "%sURL (%s) -- Fields Validated AT: %s%s\n", dbgo.ColorCyan, c.Request.URL, dbgo.LF(), dbgo.ColorReset)
		fmt.Fprintf(logFilePtr, "URL (%s) -- Fields Validated AT: %s\n", c.Request.URL, dbgo.LF())
		for _, vv := range Input {
			name := vv.Name
			value, found := FxGetDataValue(name)
			if !found {
				value = ""
			}
			// fmt.Fprintf(os.Stderr, "%s    name [%s] value [%s]%s\n", dbgo.ColorCyan, name, EncIfSecret(name, value), dbgo.ColorReset)
			fmt.Fprintf(logFilePtr, "    name [%s] value [%s]\n", name, EncIfSecret(name, value))
		}
	}

	return

}

var validationLock sync.RWMutex //

var reEmail, reUSZip *regexp.Regexp

type ValidationFunction func(s string, data interface{}, data2 []string) bool

func init() {
	validationLock = sync.RWMutex{}
	reEmail = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	reUSZip = regexp.MustCompile("^\\d{5}(?:[-\\s]\\d{4})?$")
}

func ValidEmailAddress(em string, data interface{}, data2 []string) bool {
	return reEmail.MatchString(em)
}

func ValidUSZip(em string, data interface{}, data2 []string) bool {
	return reUSZip.MatchString(em)
}

func ValidInList(em string, data interface{}, data2 []string) bool {
	var sList []string
	var ok bool
	sList, ok = data.([]string)
	if !ok {
		panic(fmt.Sprintf("Invalid data type for a Validation List passed to validInList (validation: in_list) of %T, should be []string, at %s", data, dbgo.LF(-3)))
	}
	return InArrayStr(em, sList)
}

// "list":     ValidList,
func ValidList(em string, data interface{}, data2 []string) bool {
	return InArrayStr(em, data2)
}

// "list_case_insensitive":     ValidListInsensitive,
func ValidListInsensitive(em string, data interface{}, data2 []string) bool {
	sList := make([]string, 0, len(data2))
	for _, dd := range data2 {
		sList = append(sList, strings.ToLower(dd))
	}
	return InArrayStr(strings.ToLower(em), sList)
}

var inListLock sync.RWMutex //
var inListQryData map[string][]string

func init() {
	inListLock = sync.RWMutex{}
	inListQryData = make(map[string][]string)
}

func ValidInListQry(em string, data interface{}, dataX []string) bool {
	stmt, ok := data.(string)
	if !ok {
		panic(fmt.Sprintf("Invalid data type for a Validation List passed to validInList (validation: in_list_qry) of %T, should be string (SQL Select Statment), at %s", data, dbgo.LF(-3)))
	}
	inListLock.RLock()
	if data2, ok := inListQryData[stmt]; ok {
		inListLock.RUnlock()
		return ValidInList(em, data2, dataX)
	}
	inListLock.RUnlock()

	data2 := []string{}
	rows, err := SQLQuery(stmt)
	if err != nil {
		panic(fmt.Sprintf("Invalid query - in validation [%s] error [%s]\n", stmt, err))
	}
	defer rows.Close()
	// OLD: dataAll, _, _ := sizlib.RowsToInterface(rows)
	dataAll, _, _ := RowsToInterface(rows)
	for _, row := range dataAll {
		data2 = append(data2, row["x"].(string))
	}

	inListLock.Lock()
	inListQryData[stmt] = data2
	inListLock.Unlock()
	return ValidInList(em, data2, dataX)
}

// {Name: "fmt", Label: "File Format ( ” => JSON, 'JSON', 'xml', 'csv' or 'Excel' )", Type: "s", ListValues: []string{"JSON", "csv", "xml", "Excel"}, Validate: "list_case_insensitive"},
// {Name: "method", Label: "Processing Methode, one of GET, POST, PUT, DELETE", Type: "s", ListValues: []string{"GET", "POST", "PUT", "DELETE"}, Validate: "list"},
var namedChecks = map[string]ValidationFunction{
	"email":                 ValidEmailAddress,
	"us_zip":                ValidUSZip,
	"in_list":               ValidInList,
	"in_list_qry":           ValidInListQry,
	"list":                  ValidList,
	"list_case_insensitive": ValidListInsensitive,
}

// AddValidationFunction will add a new (or replace an existing) named validation.  The default validations are email and us_zip.
func AddValidationFunction(name string, fx ValidationFunction) {
	validationLock.Lock()
	defer validationLock.Unlock()
	namedChecks[name] = fx
}

func GetKeysFromMap(m map[string]string) (keys []string) {
	for k := range m {
		keys = append(keys, k)
	}
	return
}

var Db8_vd = false
var db400 = true
var db401 = false // print out skipped validation
var db405 = false

/* vim: set noai ts=4 sw=4: */
