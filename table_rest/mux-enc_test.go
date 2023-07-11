package table_rest

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"fmt"
	"os"
	"testing"
)

func TestEncryptTextToB64Indexable(t *testing.T) {

	key := []byte(os.Getenv("DB_ENC_KEY"))
	iv := []byte(os.Getenv("DB_ENC_IV_DATA"))
	text := []byte(`This is a test set of text that needs to be encrypted.`)

	a := EncryptTextToB64Indexable(key, iv, text)
	b := EncryptTextToB64Indexable(key, iv, text)
	if a != b {
		t.Errorf("Encryption of username failed: a!=b, ->%s<- ->%s<-", a, b)
	}
	if db8112 {
		fmt.Printf("a= ->%s<-\n", a)
		fmt.Printf("b= ->%s<-\n", b)
	}
}

var db8112 = false

/* vim: set noai ts=4 sw=4: */
