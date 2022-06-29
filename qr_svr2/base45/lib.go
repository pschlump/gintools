package base45

// Taken directly from the base45 standard example code.
// RFC terms make this public domain code.
// See:

import (
	"bytes"
)

var qrCharset = []byte("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:")
var qrCharsetLen = len(qrCharset) // should equal 45

func Base45Encode(s []byte) string {
	// Go through the list two bytes at a time
	firstlist := ""
	for i := 1; i < len(s); i += 2 {
		v := int(s[i-1])*256 + int(s[i])
		for j := 0; j < 3; j++ {
			firstlist = firstlist + string(qrCharset[(v%qrCharsetLen)])
			v = v / qrCharsetLen
		}
	}

	// If odd even of bytes, deal with last byte separately
	if len(s)%2 == 1 {
		v := int(s[len(s)-1])
		for j := 0; j < 2; j++ {
			firstlist = firstlist + string(qrCharset[(v%qrCharsetLen)])
			v = v / qrCharsetLen
		}
	}

	return firstlist
}

func Base45Decode(s string) []byte {
	// Go through the list three bytes at a time
	firstlist := ""
	for i := 2; i < len(s); i += 3 {
		v := 0
		for j := 0; j < 3; j++ {
			v = v*45 + bytes.IndexByte(qrCharset, s[i-j])
		}
		firstlist = firstlist + string(rune(v/256)) + string(rune(v%256))
	}

	// Take care of last two bytes if they exist
	if len(s)%3 > 0 {
		v := 0
		i := len(s) - 1
		for j := 0; j < 2; j++ {
			v = v*45 + bytes.IndexByte(qrCharset, s[i-j])
		}
		firstlist = firstlist + string(rune(v))
	}

	return []byte(firstlist)
}

/* vim: set noai ts=4 sw=4: */
