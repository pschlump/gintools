package qr_svr2

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"fmt"
	"os"
	"testing"
)

func TestExampleEncode(t *testing.T) {
	if png, err := Encode("https://example.org", Medium, 256); err != nil {
		t.Errorf("Error: %s", err.Error())
	} else {
		if db1 {
			fmt.Printf("PNG is %d bytes long", len(png))
		}
	}
}

func TestExampleWriteFile(t *testing.T) {
	os.Mkdir("./out", 0755)
	fn := "./out/example.png"
	if err := WriteFile("https://example.org", Medium, 256, fn); err != nil {
		t.Errorf("Error: %s", err.Error())
	}
}

var db1 = false
