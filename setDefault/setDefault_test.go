package SetDefault

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"os"
	"testing"

	"github.com/pschlump/dbgo"
)

// Test with embeded struct.
type Test2EmbedType struct {
	AaaEmbeded string `default:"aaa-embeded-value"`
	AbbEmbeded string `default:"$ENV$Abb"`
}

type Test2Type struct {
	Test2EmbedType
	ExampeWithDefault string
	SomePassword      string `default:"dflt-2"`
	CheckDefault      string `default:"dflt-3"`
}

func Test2(t *testing.T) {

	tests := []struct {
		SetEnvName string
		SetEnvVal  string
		Expected   string
	}{
		{
			SetEnvName: "Abb",
			SetEnvVal:  "abb-value-from-env",
			Expected: `{
	"AaaEmbeded": "aaa-embeded-value",
	"AbbEmbeded": "abb-value-from-env",
	"ExampeWithDefault": "",
	"SomePassword": "dflt-2",
	"CheckDefault": "dflt-3"
}`,
		},
	}

	db1 = false // turn on output for debuging in ReadFile
	db2 = false // turn on output for debuging in SetFromEnv
	db3 = false //

	var test2 Test2Type

	for ii, test := range tests {
		os.Setenv(test.SetEnvName, test.SetEnvVal)
		SetDefault(&test2)
		// fmt.Printf("Result: %s\n", dbgo.SVarI(test2))
		got := dbgo.SVarI(test2)
		if got != test.Expected {
			t.Errorf("Test %d, expected %s got %s\n", ii, test.Expected, got)
		}
	}

}
