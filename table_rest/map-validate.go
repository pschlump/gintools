package table_rest

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import "github.com/gin-gonic/gin"

// ValidateInputParameters checks input values for type and value.  Also processing of AltNames and Defaults.
func ValidateInputParametersMap(c *gin.Context, CrudData CrudConfig, dMa map[string]string, method string) (err error) {

	x := CrudData.InputList
	if method == "GET" {
		if len(CrudData.GET_InputList) > 0 { // InputList: []*MuxInput{
			x = CrudData.GET_InputList
		}
	} else if method == "POST" {
		if len(CrudData.POST_InputList) > 0 { // InputList: []*MuxInput{
			x = CrudData.POST_InputList
		}
	} else if method == "PUT" {
		if len(CrudData.PUT_InputList) > 0 { // InputList: []*MuxInput{
			x = CrudData.PUT_InputList
		}
	} else if method == "DELETE" {
		if len(CrudData.DELETE_InputList) > 0 { // InputList: []*MuxInput{
			x = CrudData.DELETE_InputList
		}
	}

	if x == nil {
		return nil
	}

	_, err = ValidationFunctionCommon(c,
		CrudData.NoValidate,
		-2,
		/*FxGetNameList*/ func() []string {
			return GetKeysFromMap(dMa)
		},
		/*FxGetDataValue*/ func(name string) (string, bool) {
			a, b := dMa[name]
			return a, b
		},
		/*FxSetDataValue*/ func(name, val string) {
			dMa[name] = val
		},
		x, // CrudData.InputList,
		gCfg.LogFileEncryptionKey,
	)
	return

}

/* vim: set noai ts=4 sw=4: */
