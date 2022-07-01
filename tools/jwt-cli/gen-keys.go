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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"time"
)

func generateECKey(fn_public, fn_private string) (key *ecdsa.PrivateKey) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate ECDSA privateKey: %s\n", err)
		return
	}
	publicKey := &privateKey.PublicKey

	priv, pub := encodeECKey(privateKey, publicKey)
	ioutil.WriteFile(fn_private, []byte(priv), 0600)
	ioutil.WriteFile(fn_public, []byte(pub), 0644)

	return
}

func encodeECKey(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string) {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	// xyzzy - deal with errors
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
	// xyzzy - deal with errors
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	return string(pemEncoded), string(pemEncodedPub)
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

func generateRSAKey() (key *rsa.PrivateKey) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %s\n", err)
	}

	keyDer := x509.MarshalPKCS1PrivateKey(key)

	keyBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyDer,
	}

	keyFile, err := os.Create("rsa_key.pem")
	if err != nil {
		log.Fatalf("Failed to open rsa_key.pem for writing: %s", err)
	}
	defer func() {
		keyFile.Close()
	}()

	pem.Encode(keyFile, &keyBlock)
	return
}

func generateCert(pub, priv interface{}, filename string) {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Docker, Inc."},
		},
		NotBefore: time.Now().Add(-time.Hour * 24 * 365),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),
	}
	certDer, err := x509.CreateCertificate(
		rand.Reader, &template, &template, pub, priv,
	)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s\n", err)
	}

	certBlock := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDer,
	}

	certFile, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Failed to open '%s' for writing: %s", filename, err)
	}
	defer func() {
		certFile.Close()
	}()

	pem.Encode(certFile, &certBlock)
}
