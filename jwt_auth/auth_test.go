package jwt_auth

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/pschlump/dbgo"
	"github.com/pschlump/json"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestAppendStructToZapLog(t *testing.T) {

	fields := []zapcore.Field{
		zap.String("message", "Stored Procedure (q_auth_v1_login) error return"),
		zap.String("go_location", dbgo.LF()),
	}

	var rvStatus RvLoginType
	rvStatus = RvLoginType{
		UserId:    "a",
		AuthToken: "b",
		TmpToken:  "c",
		UserConfig: map[string]string{
			"aa": "aaa",
			"bb": "bbb",
		},
	}

	// func AppendStructToZapLog(fields []zapcore.Field, input interface{}) []zapcore.Field {
	fields = AppendStructToZapLog(fields, rvStatus)

	a := dbgo.SVarI(fields)
	b := `[
		{
			"Key": "message",
			"Type": 15,
			"Integer": 0,
			"String": "Stored Procedure (q_auth_v1_login) error return",
			"Interface": null
		},
		{
			"Key": "go_location",
			"Type": 15,
			"Integer": 0,
			"String": "File: /Users/philip/go/src/github.com/pschlump/gintools/jwt_auth/auth_test.go LineNo:22",
			"Interface": null
		},
		{
			"Key": "status",
			"Type": 15,
			"Integer": 0,
			"String": "",
			"Interface": null
		},
		{
			"Key": "user_id",
			"Type": 15,
			"Integer": 0,
			"String": "a",
			"Interface": null
		},
		{
			"Key": "auth_token",
			"Type": 15,
			"Integer": 0,
			"String": "b",
			"Interface": null
		},
		{
			"Key": "tmp_token",
			"Type": 15,
			"Integer": 0,
			"String": "c",
			"Interface": null
		},
		{
			"Key": "user_config",
			"Type": 15,
			"Integer": 0,
			"String": "map[aa:aaa bb:bbb]",
			"Interface": null
		}
	]`
	if db8113 {
		fmt.Printf("a= \n->%s<-\n", a)
		fmt.Printf("b= \n->%s<-\n", b)
	}
	want := make([]zapcore.Field, 0, 10)
	_ = json.Unmarshal([]byte(b), &want)

	if !reflect.DeepEqual(fields, want) {
		t.Errorf("failed: a!=b, ->%s<- ->%s<-", a, b)
	}
}

var db8113 = false

/* vim: set noai ts=4 sw=4: */
