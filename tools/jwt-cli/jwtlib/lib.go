package jwtlib

import (
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/filelib"
	"github.com/pschlump/jsonSyntaxErrorLib"
)

// xtoken, err := jwtlib.VerifyToken ( tokData , Alg, PublicKey )
//
// if ES*, PS*, RS*, Ed25519 - then key is the public key.
// if HS then key is just the single value (same as private key).
func VerifyToken(rawToken []byte, alg string, keyData []byte) (token *jwt.Token, err error) {

	// trim possible whitespace from token
	rawToken = TrimWhitespaceBytes(rawToken) //	tokData = regexp.MustCompile(`\s*$`).ReplaceAll(tokData, []byte{})

	// Parse the token.  Load the key from command line option
	token, err = jwt.Parse(string(rawToken), func(t *jwt.Token) (interface{}, error) {
		if IsEs(alg) {
			return jwt.ParseECPublicKeyFromPEM(keyData)
		} else if IsEd25519(alg) {
			return jwt.ParseEdPublicKeyFromPEM(keyData)
		} else if IsRs(alg) {
			return jwt.ParseRSAPublicKeyFromPEM(keyData)
		} // else IsHs(alg) ... just return the keyData
		return keyData, nil
	})
	return
}

// func SignToken(rawToken []byte, Alg string, Head ArgList, claims jwt.MapClaims, keyData []byte) (err error) {
//
// keyData is the private key if EC/RS etc.  It is the secret hash if HS256, HS384.
func SignToken(rawToken []byte, Alg string, Head map[string]string, claims jwt.MapClaims, keyData []byte) (signedToken string, err error) {

	// get the signing mthd
	mthd := jwt.GetSigningMethod(Alg)
	if mthd == nil {
		return "", fmt.Errorf("Couldn't find signing method: %s", Alg)
	}

	// create a new token
	token := jwt.NewWithClaims(mthd, claims)

	// add command line headers
	if len(Head) > 0 {
		for k, v := range Head {
			token.Header[k] = v
		}
	}

	var key interface{}
	if IsEs(Alg) {
		key, err = jwt.ParseECPrivateKeyFromPEM(keyData)
	} else if IsEd25519(Alg) {
		key, err = jwt.ParseEdPrivateKeyFromPEM(keyData)
	} else if IsRs(Alg) {
		key, err = jwt.ParseRSAPrivateKeyFromPEM(keyData)
	} else if IsHs(Alg) {
		key = keyData
	} else {
		err = fmt.Errorf("Couldn't identify type of signing key ->%s<-", Alg)
	}
	if err != nil {
		return "", err
	}

	signedToken, err = token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("Error signing token: %v", err)
	}

	return
}

func IsEs(flagAlg string) bool {
	return strings.HasPrefix(flagAlg, "ES")
}

func IsEd25519(flagAlg string) bool {
	return strings.HasPrefix(flagAlg, "EdDSA")
}

func IsRs(flagAlg string) bool {
	return strings.HasPrefix(flagAlg, "RS") || strings.HasPrefix(flagAlg, "PS")
}

func IsHs(flagAlg string) bool {
	return strings.HasPrefix(flagAlg, "HS")
}

// PrintJSON will print a json object as an indendent or not JSON string.
func PrintJSON(data interface{}, indent bool, fp *os.File) {
	var out string

	if indent {
		out = dbgo.SVarI(data)
	} else {
		out = dbgo.SVar(data)
	}

	fmt.Fprintf(fp, "%s\n", out)
}

// LoadData will read input from specified file or stdin if file name is '-'
func LoadData(fn string) ([]byte, error) {
	if fn == "" {
		return nil, fmt.Errorf("No file name specified")
	}

	if fn == "-" {
		return ioutil.ReadAll(os.Stdin)
	}

	f, err := filelib.Fopen(fn, "r")
	if err != nil {
		return nil, fmt.Errorf("Unable to open %s for input, error:%s", fn, err)
	}
	defer f.Close()
	return ioutil.ReadAll(f)
}

func TrimWhitespaceBytes(tokData []byte) (rv []byte) {
	rv = regexp.MustCompile(`\s*$`).ReplaceAll(tokData, []byte{})
	return
}

func PrintErrorJson(js string, err error) (rv string) {
	rv = jsonSyntaxErrorLib.GenerateSyntaxError(js, err)
	fmt.Fprintf(os.Stderr, "%s\n", rv)
	return
}
