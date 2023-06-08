package main

// Copyright (C) Philip Schlump, 2015-2019.
// This file is MIT Clause licensed.
// See ./LICENSE.mit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"

	"github.com/pschlump/dbgo"
)

func HashPassword(a ...string) []byte {
	h := sha256.New()
	for _, z := range a {
		h.Write([]byte(z))
	}
	return h.Sum(nil)
}

func LogEncrypt(plaintext []byte, keyString string) (encryptedString string, err error) {

	dbgo.Printf("at:%(LF)\n")
	key := HashPassword(keyString)

	// Create a new Cipher Block from the using key
	block, err := aes.NewCipher(key)
	if err != nil {
		dbgo.Printf("at:%(LF) err=%s\n", err)
		return
	}

	// Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	// See : https://golang.org/pkg/crypto/cipher/#NewGCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		// panic(err.Error())
		dbgo.Printf("at:%(LF) err=%s\n", err)
		return
	}

	// Create a nonce. Nonce should be from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		dbgo.Printf("at:%(LF) err=%s\n", err)
		return
	}

	// Encrypt the data using aesGCM.Seal
	// Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the
	// encrypted data. The first nonce argument in Seal is the prefix.
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)

	// Convert to base 64 string
	so := base64.StdEncoding.EncodeToString(ciphertext)

	dbgo.Printf("at:%(LF)\n")
	return so, nil
	// return fmt.Sprintf("%x", ciphertext), nil // xyzzy - change to base 64
}

func LogDecrypt(encryptedString string, keyString string) (decrypted []byte, err error) {

	dbgo.Printf("at:%(LF)\n")
	key := HashPassword(keyString)

	// enc, err := hex.DecodeString(encryptedString) // xyzzy
	enc, err := base64.StdEncoding.DecodeString(encryptedString)
	if err != nil {
		dbgo.Printf("at:%(LF) err=%s\n", err)
		return
	}

	// Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		dbgo.Printf("at:%(LF) err=%s\n", err)
		return
	}

	// Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		dbgo.Printf("at:%(LF) err=%s\n", err)
		return
	}

	//Get the nonce size
	nonceSize := aesGCM.NonceSize()

	// Extract the nonce from the encrypted data
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	// Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		dbgo.Printf("at:%(LF) err=%s\n", err)
		return
	}

	dbgo.Printf("at:%(LF)\n")
	return plaintext, nil
}

/* vim: set noai ts=4 sw=4: */
