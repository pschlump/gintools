package log_enc

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"fmt"
	"os"
	"testing"

	"github.com/pschlump/dbgo"
	"github.com/pschlump/filelib"
	"github.com/pschlump/gintools/data"
)

func Test_LogIt(t *testing.T) {

	var err error

	tests := []struct {
		LogFileName string
		Db8         bool
	}{
		{
			LogFileName: "./out/tA.log",
			Db8:         true,
		},
	}

	os.MkdirAll("./out", 0755)

	for ii, test := range tests {

		db8 = test.Db8

		if logFilePtr != nil {
			logFilePtr.Close()
		}
		logFilePtr, err = filelib.Fopen(test.LogFileName, "w")
		if err != nil {
			t.Errorf("Test %d, unable to open %s for output: %s\n", ii, test.LogFileName, err)
		}

		LogIt(fmt.Sprintf("Test %d", ii), "a", "b", "c")

		//if got != test.Expected {
		//	t.Errorf("Test %d, expected %s got %s\n", ii, test.Expected, got)
		//}
	}

}

// "data", EncryptLogData(encPat, data...), // "data", dbgo.SVar(PreProcessData(data)), // "data", SVar(data),
func Test_EncryptLogData(t *testing.T) {

	var err error

	tests := []struct {
		LogFileName      string
		EncPat           string
		EncData          []interface{}
		NotExpect        string
		Expect           string
		UseLogEncryption string
		// if gCfg.UseLogEncryption == "no" {
		// if gCfg.UseLogEncryption == "dev-dummy" {
		// } else if gCfg.UseLogEncryption == "b64-dummy" {
		// } else if gCfg.UseLogEncryption == "yes" {
		Db8 bool
	}{
		{
			LogFileName:      "./out/t1.log",
			EncPat:           "e.!e",
			EncData:          []interface{}{"aaa", "bbb", "ccc", "ddd"},
			NotExpect:        "[]",
			Expect:           `["aaa","bbb","ccc","ddd"]`,
			UseLogEncryption: "no",
			Db8:              false,
		},
		{
			LogFileName:      "./out/t2.log",
			EncPat:           "e.!e",
			EncData:          []interface{}{"aaa", "bbb", "ccc", "ddd"},
			NotExpect:        "[]",
			Expect:           `["$$$Encrypted$$$aaa$$$End$$$","bbb","$$$skipped$$$","$$$Encrypted$$$ddd$$$End$$$"]`,
			UseLogEncryption: "dev-dummy",
			Db8:              false,
		},
		// 2, 3: Test were pat is NIL or ""
		// 4, Test were pat shorter than data
		// 5, Test were pat longer than data
		// 6, Test with real encryption
	}

	os.MkdirAll("./out", 0755)

	gCfg = &data.BaseConfigType{}
	xx := &data.AppConfig{}
	xx.LogEncryptionPassword = "test-password-00001"
	_ = xx

	for ii, test := range tests {

		xx.UseLogEncryption = test.UseLogEncryption
		db8 = test.Db8

		if logFilePtr != nil {
			logFilePtr.Close()
		}
		logFilePtr, err = filelib.Fopen(test.LogFileName, "w")
		if err != nil {
			t.Errorf("Test %d, unable to open %s for output: %s\n", ii, test.LogFileName, err)
		}

		// "data", EncryptLogData(encPat, data...), // "data", dbgo.SVar(PreProcessData(data)), // "data", SVar(data),
		s := EncryptLogData(test.EncPat, test.EncData...)

		dbgo.DbPf(db8, "s ->%s<- at:%(LF)\n", s)

		if len(s) == 0 {
			t.Errorf("Test %d, got 0 length\n", ii)
		}
		if s == test.NotExpect {
			t.Errorf("Test %d, got ->%s<- this is bad\n", ii, s)
		}
		if test.Expect != "" && s != test.Expect {
			t.Errorf("Test %d, got ->%s<- expected %s\n", ii, s, test.Expect)
		}
	}

}
