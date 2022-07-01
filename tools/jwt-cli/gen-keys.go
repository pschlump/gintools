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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"
)

func generateECKey() (key *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate ECDSA key: %s\n", err)
	}

	keyDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		log.Fatalf("Failed to serialize ECDSA key: %s\n", err)
	}

	keyBlock := pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDer,
	}

	keyFile, err := os.Create("ec_key.pem")
	if err != nil {
		log.Fatalf("Failed to open ec_key.pem for writing: %s", err)
	}
	defer func() {
		keyFile.Close()
	}()

	pem.Encode(keyFile, &keyBlock)
	return
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

// func GenerateEd25519Keys() (*ED25519Keys, error) {
func GenerateEd25519Keys() (key ed25519.PrivateKey, err error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	_ = publicKey

	//publicED25519Key, err := ssh.NewPublicKey(publicKey)
	//if err != nil {
	//	return nil, err
	//}

	// pubKeyBytes := ssh.MarshalAuthorizedKey(publicED25519Key)

	bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	privBlock := pem.Block{
		Type:    "PRIVATE KEY",
		Headers: nil,
		Bytes:   bytes,
	}

	privatePEM := pem.EncodeToMemory(&privBlock)

	//return &ED25519Keys{
	//	Public:  pubKeyBytes,
	//	Private: privatePEM,
	//}, nil

	return (ed25519.PrivateKey)(privatePEM), nil
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

func demo_main() {
	// Generate ECDSA P-256 Key
	log.Println("Generating an ECDSA P-256 Private Key")
	ECKey := generateECKey()

	// Generate Self-Signed Certificate using ECDSA P-256 Key
	log.Println("Generating a Self-Signed Certificate from ECDSA P-256 Key")
	generateCert(&ECKey.PublicKey, ECKey, "ec_cert.pem")

	// Generate RSA 3072 Key
	log.Println("Generating an RSA 3072 Private Key")
	RSAKey := generateRSAKey()

	// Generate Self-Signed Certificate using RSA 3072 Key
	log.Println("Generating a Self-Signed Certificate from RSA 3072 Key")
	generateCert(&RSAKey.PublicKey, RSAKey, "rsa_cert.pem")
}

/*
rsa_cert.pem
-----BEGIN CERTIFICATE-----
MIIDpzCCAhGgAwIBAgIBATALBgkqhkiG9w0BAQswFzEVMBMGA1UEChMMRG9ja2Vy
LCBJbmMuMB4XDTEzMDcyNTAxMTAyN1oXDTE1MDcyNTAxMTAyN1owFzEVMBMGA1UE
ChMMRG9ja2VyLCBJbmMuMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA
yjZxk2+omquAx6+R46uCXmKkHZLaYCECeoLxfjcaV3/XQG5pABupALYfjTuglFl9
NECrcj/LydmUBzO699hCNL/i/m/cG0NzkPxp6NDQAUNdml9MDnjlvGQEd0cx44Hz
EYzIXNJBpnYBzJ278g4+NL9fQS82zr+hgOxP9HBvs4NBBW8+Y+9ZLYalI4inFimr
/IGxZsXqWadzYYBelMaugJf4b3i7VeLiJEX9G7DfV96X9iiMDxRiQtmpzBmDGpZs
kNocozaUpg2UyTH9IGCwf7YoDpvDhvqng+TEbhoDak6PaIMEhvuGyIzK2vnHnap+
jt04peiqQ69trYC3YWsVEf6TgTANt9G7MGc40BW7gZcYXz6owBOilH+NNJbS81hu
OVCqeiGiF4XM3fIQNKywldPKONfX5arDb+pKui1sg+fSsavaMWTnIzSoB2eVIckn
FMq271Lj6MXOX8knA/hNFtMGOv0KnMnJHCtyD+Ll9fg18ULeJoFyihm6RPFeZL3L
AgMBAAGjAjAAMAsGCSqGSIb3DQEBCwOCAYEAZXKUYYesoUuTGB3tc394AkQKQe06
k0fHlNL7EY85gNJkGUVvV7Akgo+XxcAkb3fXbfoQrCC++UQovdxjYm/Ps1gwRYUR
5u8l+2FFfiGrAWYhzcOvTqs/OetVfO4v58BpXrslyqXX3o8zhW76Q2N2Wdbj7fgG
yW4TSS/Lk/uUL6J0R1jT0uhekJt5XgKfhi5FxBSdTW2PRdS3YUBY1ga9ObQQs+e5
sr5pqZf5g2IgPUo8BgwqPvsbA4MyHP2xqydLgva4JizGunQ9Abz1V5x8oF6AOsKB
8zRiECZv+vlT5rQeno5UfRMPwxXOf5iEfX/q+CIsRDY1fVGjO412U393jSbkG/IY
3pcxmMpm8EMiC5HhpIo/fTKfPJmKgriXX+PLpSqAZ32Xpq0zAIMXSBNgDX9/PhxY
+706gVrZR1OGOxrRNEwkAcC7vwzwNJyxoZykedO6ovrU9vXcQqB7Z3yPadt29SSy
ZLhXjw/wuF1X7YdMMRWYGilB0sJMyXIuPKn6
-----END CERTIFICATE-----
rsa_key.pem
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
@dphans
dphans commented on Feb 15 •
Great example!
But can you guide how to generate private key and public key as below (your first certs snipet), or tell me which algorithm generates the above keys? i tried with keytool rsa, x509 but not the correct format..

Private key:

-----BEGIN CERTIFICATE-----
MIIBHjCBxaADAgECAgEBMAoGCCqGSM49BAMCMBcxFTATBgNVBAoTDERvY2tlciwg
SW5jLjAeFw0xMzA3MjUwMTEwMjRaFw0xNTA3MjUwMTEwMjRaMBcxFTATBgNVBAoT
DERvY2tlciwgSW5jLjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMolCWAO0iP7
tkX/KLjQ9CKeOoHYynBgfFcd1ZGoxcefmIbWjHx29eWI3xlhbjS6ssSxhrw1Kuh5
RrASfUCHD7SjAjAAMAoGCCqGSM49BAMCA0gAMEUCIQDRLQTSSeqjsxsb+q4exLSt
EM7f7/ymBzoUzbXU7wI9AgIgXCWaI++GkopGT8T2qV/3+NL0U+fYM0ZjSNSiwaK3
+kA=
-----END CERTIFICATE-----
Public key:

-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEFRa42BSz1uuRxWBh60vePDrpkgtELJJMZtkJGlExuLoAoGCCqGSM49
AwEHoUQDQgAEyiUJYA7SI/u2Rf8ouND0Ip46gdjKcGB8Vx3VkajFx5+YhtaMfHb1
5YjfGWFuNLqyxLGGvDUq6HlGsBJ9QIcPtA==
-----END EC PRIVATE KEY-----
*/
