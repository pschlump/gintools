package table_rest_test

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"testing"

	"github.com/pschlump/dbgo"
	"github.com/pschlump/gintools/table_rest"
)

// func SplitURI(uri string) (result []string) {
func TestSplitURI(t *testing.T) {
	var tests = []struct {
		uri      string
		expected []string
	}{
		{
			uri:      "/someDir/apage",
			expected: []string{"someDir", "apage"},
		},
		{
			uri:      "/",
			expected: []string{""},
		},
		{
			uri:      "",
			expected: []string{""},
		},
		{
			uri:      "/aa//bb",
			expected: []string{"aa", "bb"},
		},
		{
			uri:      "/aa/../bb",
			expected: []string{"bb"},
		},
		{
			uri:      "/aa/../../bb",
			expected: []string{"bb"},
		},
		{
			uri:      "/aa/././bb",
			expected: []string{"aa", "bb"},
		},
	}

	for ii, vv := range tests {
		got := table_rest.SplitURI(vv.uri)
		if len(got) != len(vv.expected) {
			t.Errorf("Lengths did not match, test=%d: got:%d/%s expected:%d/%s\n", ii, len(got), dbgo.SVar(got), len(vv.expected), dbgo.SVar(vv.expected))
		} else {
			for jj, gotII := range got {
				if gotII != vv.expected[jj] {
					t.Errorf("Did not match, test=%d: at pos %d got: ->%s<- expected: ->%s<-\n", ii, jj, gotII, vv.expected[ii])
				}
			}
		}
	}
}
