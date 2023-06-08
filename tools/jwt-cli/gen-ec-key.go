package main

/*
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

func GenerateSigningTestKey(sigAlg SignatureAlgorithm) (sig, ver interface{}) {
	switch sigAlg {
	case RS256, RS384, RS512, PS256, PS384, PS512:
		sig = rsaTestKey
		ver = &rsaTestKey.PublicKey
	case HS256, HS384, HS512:
		sig, _, _ = randomKeyGenerator{size: 16}.genKey()
		ver = sig
	case ES256:
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		sig = key
		ver = &key.PublicKey
	case ES384:
		key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		sig = key
		ver = &key.PublicKey
	case ES512:
		key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		sig = key
		ver = &key.PublicKey
	default:
		panic("Must update test case")
	}

	return
}


---------------------------------------------------------------------------------
From: https://stackoverflow.com/questions/71850135/generate-an-ed25519-key-pair-from-golang

import "github.com/mikesmitty/edkey"

pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
publicKey, _ := ssh.NewPublicKey(pubKey)

pemKey := &pem.Block{
    Type:  "OPENSSH PRIVATE KEY",
    Bytes: edkey.MarshalED25519PrivateKey(privKey),  // <- marshals ed25519 correctly
}
privateKey := pem.EncodeToMemory(pemKey)
authorizedKey := ssh.MarshalAuthorizedKey(publicKey)

_ = ioutil.WriteFile("id_ed25519", privateKey, 0600)
_ = ioutil.WriteFile("id_ed25519.pub", authorizedKey, 0644)

*/

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func GenerateECKey(fn_public, fn_private, Alg string) (key *ecdsa.PrivateKey, err error) {
	var c elliptic.Curve
	switch Alg {
	case "ES256":
		c = elliptic.P256()
	case "ES384":
		c = elliptic.P384()
	case "ES512":
		c = elliptic.P521()
	}
	// privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privateKey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate ECDSA privateKey: %s\n", err)
		return
	}
	publicKey := &privateKey.PublicKey

	priv, pub, err := encodeECKey(privateKey, publicKey)
	if err != nil {
		fmt.Printf("Failed to PEM encode ECDSA keys: %s\n", err)
		return nil, err
	}
	ioutil.WriteFile(fn_private, []byte(priv), 0600)
	ioutil.WriteFile(fn_public, []byte(pub), 0644)
	return
}

func encodeECKey(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string, error) {
	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", "", err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", "", err
	}
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	return string(pemEncoded), string(pemEncodedPub), nil
}

func decodeECKey(pemEncoded string, pemEncodedPub string) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)

	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)

	return privateKey, publicKey
}
