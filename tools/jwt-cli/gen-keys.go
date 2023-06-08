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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

//func generateRSAKey() (key *rsa.PrivateKey) {
//
//	key, err := rsa.GenerateKey(rand.Reader, 3072)
//	if err != nil {
//		log.Fatalf("Failed to generate RSA key: %s\n", err)
//	}
//
//	keyDer := x509.MarshalPKCS1PrivateKey(key)
//
//	keyBlock := pem.Block{
//		Type:  "RSA PRIVATE KEY",
//		Bytes: keyDer,
//	}
//
//	keyFile, err := os.Create("rsa_key.pem")
//	if err != nil {
//		log.Fatalf("Failed to open rsa_key.pem for writing: %s", err)
//	}
//	defer func() {
//		keyFile.Close()
//	}()
//
//	pem.Encode(keyFile, &keyBlock)
//	return
//}

// See: https://www.ibm.com/docs/en/sva/9.0.6?topic=jwt-support

func GenerateRSAKeys(fn_public, fn_private, Alg string) (err error) {
	var keyLen int = 2048
	switch Alg {
	case "PS256":
		keyLen = 2048
	case "PS384":
		keyLen = 3072
	case "PS512":
		keyLen = 4096
	case "RS256":
		keyLen = 2048
	case "RS384":
		keyLen = 3072
	case "RS512":
		keyLen = 4096
	}

	// generate key
	// privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	privatekey, err := rsa.GenerateKey(rand.Reader, keyLen)
	if err != nil {
		return fmt.Errorf("Cannot generate RSA key: %s\n", err)
	}
	publickey := &privatekey.PublicKey

	// dump private key to file
	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privatekey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privatePem, err := os.Create(fn_private)
	if err != nil {
		return fmt.Errorf("error when create private.pem: %s \n", err)
	}
	err = pem.Encode(privatePem, privateKeyBlock)
	if err != nil {
		return fmt.Errorf("error when encode private pem: %s \n", err)
	}

	// dump public key to file
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		return fmt.Errorf("error when dumping publickey: %s \n", err)
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicPem, err := os.Create(fn_public)
	if err != nil {
		return fmt.Errorf("error when create public.pem: %s \n", err)
	}
	err = pem.Encode(publicPem, publicKeyBlock)
	if err != nil {
		return fmt.Errorf("error when encode public pem: %s \n", err)
	}
	return nil
}
