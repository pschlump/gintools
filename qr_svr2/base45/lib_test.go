package base45

// BSD 3 clause Licensed.  Copyright (C) Philip Schlump, 2022.

import (
	"testing"
)

func Test_EncodeDecode(t *testing.T) {

	tests := []struct {
		in     string
		expect string
	}{
		{
			in:     "http://example.com/testdir/b.html",
			expect: "A9DIWE0G7S:5$9FQ$DTVD+%5+3E/:56$C6WE*EDP:50*5FWEI2",
		},
	}

	// func Base45Encode(s []byte) string {
	// func Base45Decode(s string) []byte {
	for ii, test := range tests {
		b := Base45Encode([]byte(test.in))
		if b != test.expect {
			t.Errorf("Error %2d, Invalid encode base 45 : ->%s<-, expected ->%s<-\n", ii, b, test.expect)
		}

		s := Base45Decode(b)
		if string(s) != test.in {
			t.Errorf("Error %2d, Invalid decode base 45 : ->%s<-, expected ->%x<-\n", ii, s, test.in)
		}
	}

}

/* vim: set noai ts=4 sw=4: */
