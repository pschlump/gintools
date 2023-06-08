package ethProc

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"fmt"
	"io/ioutil"

	"github.com/ethereum/go-ethereum/accounts/keystore"
)

func ByteSliceToByte32(x []byte) (rv [32]byte) {
	for i := 0; i < 32 && i < len(x); i++ {
		rv[i] = x[i]
	}
	return
}

func ByteSliceToByte2(x []byte) (rv [2]byte) {
	for i := 0; i < 2 && i < len(x); i++ {
		rv[i] = x[i]
	}
	return
}

// DecryptKeyFile reads in a key file decrypt it with the password.
func DecryptKeyFile(keyFile, password string) (*keystore.Key, error) {
	data, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("Faield to read KeyFile %s [%v]", keyFile, err)
	}
	key, err := keystore.DecryptKey(data, password)
	if err != nil {
		return nil, fmt.Errorf("Decryption error %s [%v]", keyFile, err)
	}
	return key, nil
}

// DecryptKeyFileData takes keyfile data and decrypt it with the password.
func DecryptKeyFileData(data, password string) (*keystore.Key, error) {
	key, err := keystore.DecryptKey([]byte(data), password)
	if err != nil {
		return nil, fmt.Errorf("Decryption error %s [%v]", data, err)
	}
	return key, nil
}
