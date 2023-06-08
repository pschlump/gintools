package table_rest

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/pschlump/HashStrings"
)

var prefix = "Marrrry had a littttle lambb, ItS FleEse was White a gold"

func EncryptTextToB64(key, text []byte) string {

	enc, err := EncryptText(key, text)
	if err != nil {
		enc = []byte(fmt.Sprintf("%s", err))
	}

	return base64.StdEncoding.EncodeToString(enc)
}

func EncryptText(key, text []byte) ([]byte, error) {
	// use SHA256 of "key" to generate real key.  Add a "fixed salt" for hash PJS
	tkey := HashStrings.HashStrings(prefix, string(key))
	rkey := ([]byte(tkey))[0:32]
	block, err := aes.NewCipher(rkey)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize] // Generate Randome !!! PJS
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

func DecryptText(key, text []byte) ([]byte, error) {
	tkey := HashStrings.HashStrings(prefix, string(key))
	rkey := ([]byte(tkey))[0:32]
	block, err := aes.NewCipher(rkey)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}

func EncryptTextToB64Indexable(key, iv, text []byte) string {

	enc, err := EncryptTextIndexable(key, iv, text)
	if err != nil {
		enc = []byte(fmt.Sprintf("%s", err))
	}

	return base64.StdEncoding.EncodeToString(enc)
}

func EncryptTextIndexable(key, xiv, text []byte) ([]byte, error) {
	// use SHA256 of "key" to generate real key.  Add a "fixed salt" for hash PJS
	tkey := HashStrings.HashStrings(prefix, string(key))
	rkey := ([]byte(tkey))[0:32]
	block, err := aes.NewCipher(rkey)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize] // Generate Randome !!! PJS
	for ii := 0; ii < aes.BlockSize; ii++ {
		if ii < len(xiv) {
			iv[ii] = xiv[ii]
		} else {
			iv[ii] = 0x22
		}
	}
	//	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
	//		return nil, err
	//	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}
