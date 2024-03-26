package main

// A useful tool and a good example of how to use the different capabilities of JWT tokens.

// A useful example app.  You can use this to debug your tokens on the command line.
// This is also a great place to look at how you might use this library.
//
// Example usage:
// The following will create and sign a token, then verify it and output the original claims.
//     echo {\"foo\":\"bar\"} | bin/jwt -key test/sample_key -alg RS256 -sign - | bin/jwt -key test/sample_key.pub -verify -

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/filelib"
	"github.com/pschlump/gintools/tools/jwt-cli/jwtlib"
)

var (
	out  *os.File        = os.Stdout
	DbOn map[string]bool = make(map[string]bool)

	// Options
	flagAlg        = flag.String("alg", "", "signing algorithm identifier")                        // ES, RS, HS, Ed25519 ?
	flagKey        = flag.String("key", "", "path to key file or '-' to read from stdin")          //
	flagIndentJSON = flag.Bool("indent-json", true, "Output Indented JSON.")                       //
	flagOutput     = flag.String("out", "", "File to send output to, os.Stdout if not specified.") //

	// Comma seperated list of debug flags are:
	//	VerifyToken
	//	SignToken
	//	ShowToken
	//	Generate
	flagDebug = flag.String("debug", "", "Turn on debuging flags.") //

	flagClaims = make(ArgList) // ArgList === map[string]string
	flagHead   = make(ArgList)

	// Modes - exactly one of these is required
	flagSign    = flag.String("sign", "", "path to claims object to sign, '-' to read from stdin, or '+' to use only -claim args")
	flagVerify  = flag.String("verify", "", "path to JWT token to verify or '-' to read from stdin")
	flagShow    = flag.String("show", "", "path to JWT file or '-' to read from stdin")
	flagShowAlg = flag.Bool("show-alg", false, "Show JWT algorythms")

	// PJS Added
	flagGenKeys  = flag.String("generate", "", "Name to generate keys ( name-private.pem, name-public.pem ).") // PJS
	flagKeysType = flag.String("key-type", "ed25519", "Type of key to generate.")                              // PJS
	flagKeysPath = flag.String("key-path", "./", "Directory to geneate keys in.")                              // PJS
)

func main() {
	// Plug in Var flags
	// type ArgList map[string]string - will meet the interface for flag.Var
	flag.Var(flagClaims, "claim", "Add additional claims.  May be used more than once.")
	flag.Var(flagHead, "header", "Add additional header params.  May be used more than once.")

	// Usage message if you ask for -help or if you mess up inputs.
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage:

%s -sign <File.json>     -alg <algorythm>  -key <private-key.pem>   -out <output-file>
%s -verify <File.token > -alg <algorythm>  -key <public-key.pem>    -out <output-file>
%s -show <File.token>    -alg <algorythm>  -key <public-key.pem>    -out <output-file>
%s -show-alg

algorythm should be one of: ES256, ES384, ES512, EdDSA, HS256, HS384, HS512, PS256, PS384, PS512, RS256, RS384, RS512

Example: 
	./jwt-cli -key  ./private-key.pem -alg ES256 -sign ./testdata/data002.json >./out/test002.token
	./jwt-cli -key  ./public-key.pem -alg ES256 -verify ./out/test002.token >./out/test002.out

`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if *flagDebug != "" {
		ss := strings.Split(*flagDebug, ",")
		for _, v := range ss {
			DbOn[v] = true
		}
	}

	// check that --alg xXXX is valid.
	if !filelib.InArray(*flagAlg, jwt.GetAlgorithms()) {
		fmt.Fprintf(os.Stderr, "Error: ->%s<- is invalid, should bin in %s\n", *flagAlg, jwt.GetAlgorithms())
		os.Exit(1)
	}

	if *flagOutput != "" {
		fp, err := filelib.Fopen(*flagOutput, "w")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Unable to open ->%s<- for output: error: %s\n", *flagOutput, err)
			os.Exit(1)
		}
		out = fp
		defer fp.Close()
	}

	// Implement the command line args.
	if err := start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// Figure out which thing to do and then do that
func start() error {
	if *flagSign != "" {
		return SignToken(*flagSign, *flagKey, *flagAlg, flagClaims, flagHead, out)
	} else if *flagVerify != "" {
		return VerifyToken(*flagVerify, *flagKey, *flagAlg, *flagIndentJSON, out)
	} else if *flagShow != "" {
		return ShowToken(*flagShow, *flagKey, *flagAlg, *flagIndentJSON, out)
	} else if *flagGenKeys != "" {
		return generateKeys(*flagGenKeys, *flagKey, *flagAlg)
	} else if *flagShowAlg {
		return showAlg()
	} else {
		flag.Usage()
		return fmt.Errorf("Missing required flag.")
	}
}

// -------------------------------------------------------------------------------------------------------------------------
// Implementation Code
// -------------------------------------------------------------------------------------------------------------------------

func showAlg() (err error) {
	allalg := jwt.GetAlgorithms()
	fmt.Printf("Algorythms are: %s\n", allalg)
	return
}

// flagGenKeys  = flag.String("generate", "", "Name to generate keys ( name-private.pem, name-public.pem ).") // PJS
// flagKeysType = flag.String("key-type", "ed25519", "Type of key to generate.")                              // PJS
// flagKeysPath = flag.String("key-path", "./", "Directory to geneate keys in.")                              // PJS
func generateKeys(flagGenerate, flagKey, flagAlg string) (err error) {
	// xyzzy - TODO -

	if flagAlg == "EdDSA" {
		fn_private := fmt.Sprintf("%s-Ed25519-private.pem", flagGenerate)
		fn_public := fmt.Sprintf("%s-Ed25519-public.pem", flagGenerate)
		err = GenerateSaveEd25519(fn_private, fn_public)

	} else if jwtlib.IsEs(flagAlg) {
		fn_private := fmt.Sprintf("%s-EC-private.pem", flagGenerate)
		fn_public := fmt.Sprintf("%s-EC-public.pem", flagGenerate)
		_, err = GenerateECKey(fn_public, fn_private, flagAlg)

	} else if jwtlib.IsRs(flagAlg) {
		fn_private := fmt.Sprintf("%s-RSA-private.pem", flagGenerate)
		fn_public := fmt.Sprintf("%s-RSA-public.pem", flagGenerate)
		err = GenerateRSAKeys(fn_public, fn_private, flagAlg)

	} else if jwtlib.IsHs(flagAlg) {
		var s string
		s, err = RandomHex(128 / 2)
		ioutil.WriteFile(fmt.Sprintf("%s.key", flagGenerate), []byte(fmt.Sprintf("%s\n", s)), 0600)

	} else {
		err = fmt.Errorf("Error: unable to geneate %s type keys -- not implemented yet", flagAlg)
	}

	return
}

func RandomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Verify a token and output the claims.  This is a great example
// of how to verify and view a token.
func VerifyToken(Verify, Key, Alg string, IndentJSON bool, out *os.File) error {
	// get the token
	tokData, err := jwtlib.LoadData(Verify)
	if IsDbOn("VerifyToken") {
		dbgo.Printf("tokData ->%s<- %(LF)\n", tokData)
	}
	if err != nil {
		return fmt.Errorf("Couldn't read token: %v", err)
	}

	keyData, err := jwtlib.LoadData(Key)
	if err != nil {
		return err
	}

	// Do the work of verifying the token and extrcting the claims.  tokData is the input, the token is
	// in Alg format(signing method).  The Public key is passed in keyData.
	//
	// token, err := jwtlib.VerifyToken([]byte(token), gCfg.AuthJWTKeyType, gCfg.AuthJWTPublic )
	token, err := jwtlib.VerifyToken(tokData, Alg, keyData)

	if IsDbOn("VerifyToken") && token != nil {
		dbgo.Fprintf(os.Stderr, "AT: %(LF)\nValid : %v\nHeader: %v\nClaims: %v\n", token.Valid, token.Header, token.Claims)
		dbgo.Fprintf(os.Stderr, "AT: %(LF)\nToken is ->%s<-\n", dbgo.SVarI(token))
	}
	if IsDbOn("VerifyToken.ShowToken") && token != nil {
		dbgo.Fprintf(os.Stderr, "Token: %s\n", dbgo.SVarI(token))
	}

	// Print an error if we can't parse for some reason
	if err != nil {
		e0 := fmt.Errorf("Couldn't parse token: %v", err)
		dbgo.Fprintf(os.Stderr, "Error %s at: %(LF)\n", e0)
		// jwtlib. PrintErrorJson(js, err)
		return e0
	}

	if !token.Valid {
		return fmt.Errorf("Token is invalid, invalid JWT signature")
	}

	jwtlib.PrintJSON(token.Claims, IndentJSON, out)
	return nil
}

// SignToken takes the signData as a source of input (file name or '-' for stdin) and
// reads that then signs the data with the specified algorythm, `Alg`, and key
// information `Key`.
//
// Create, sign, and output a token.  This is a great, simple example of
// how to use this library to create and sign a token.
func SignToken(signData, Key, Alg string, Claims, Head ArgList, out *os.File) error {
	// get the token data from command line arguments
	tokData, err := jwtlib.LoadData(signData)
	if err != nil {
		return fmt.Errorf("Error reading data to sign: %s", err)
	}
	if IsDbOn("SignToken") {
		fmt.Fprintf(os.Stderr, "Data To Sign: Length: %d data: ->%s<- bytes", len(tokData), tokData)
	}

	// parse the JSON of the claims
	var claims jwt.MapClaims
	if err := json.Unmarshal(tokData, &claims); err != nil {
		rv := jwtlib.PrintErrorJson(string(tokData), err)
		return fmt.Errorf("Couldn't parse claims JSON: %s\n%s", err, rv)
	}

	// add command line claims
	if len(Claims) > 0 {
		for k, v := range Claims {
			claims[k] = v
		}
	}

	// read in the private key.
	key, err := jwtlib.LoadData(Key)
	if err != nil {
		return fmt.Errorf("Couldn't read key: %v", err)
	}

	signedToken, err := jwtlib.SignToken(tokData, Alg, Head, claims, key)

	fmt.Fprintf(out, "%s\n", signedToken) // xyzzy - should return this.

	return nil
}

// ShowToken pretty-prints the token on the command line.
func ShowToken(showData, Key, Alg string, IndentJSON bool, out *os.File) error {

	DbOn["VerifyToken.ShowToken"] = true
	return VerifyToken(showData, Key, Alg, IndentJSON, out)

}

func IsDbOn(s string) bool {
	if v, ok := DbOn[s]; ok {
		return v
	}
	return false
}
