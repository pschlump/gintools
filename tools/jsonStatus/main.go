package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	jsonSyntaxErroLib "github.com/pschlump/check-json-syntax/lib"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/json"
)

var DbFlagParam = flag.String("db_flag", "", "Additional Debug Flags")
var Input = flag.String("i", "", "Input JSON File")
var Rev = flag.Bool("r", false, "Reverse logic - must not have")

var DbOn map[string]bool = make(map[string]bool)
var Debug bool

func init() {
	DbOn = make(map[string]bool)
}

func main() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "jsonCheck : Usage: %s [-r] -i file name1... name2...\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse() // Parse CLI arguments to this, --cfg <name>.json

	fns := flag.Args()
	if len(fns) != 0 {
		fmt.Printf("Extra arguments are not supported [%s]\n", fns)
		os.Exit(1)
	}

	// xyzzy - Create DbOn

	jsonSyntaxErroLib.Debug = &Debug

	buf, err := ioutil.ReadFile(*Input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open %s error : %s\n", *Input, err)
		os.Exit(1)
	}
	if len(buf) == 0 {
		fmt.Fprintf(os.Stderr, "Empty File %s\n", *Input)
		os.Exit(1)
	}

	mdata := make(map[string]interface{})
	err = json.Unmarshal(buf, &mdata)
	if err != nil {
		fmt.Fprintf(os.Stderr, "JSON parse error on %s error : %s\n", *Input, err)
		printSyntaxError(string(buf), err)
		os.Exit(1)
	}

	n_err := 0

	if *Rev == false {

		if vv, ok := mdata["status"]; !ok {
			n_err++
			fmt.Fprintf(os.Stderr, "JSON missing field ->%s<- in ->%s<- error\n", "status", *Input)
		} else {
			if vv != "success" {
				n_err++
				fmt.Fprintf(os.Stderr, "JSON Unxpected Error")
			}
		}

	} else {

		if vv, ok := mdata["status"]; !ok {
			n_err++
			fmt.Fprintf(os.Stderr, "JSON missing field ->%s<- in ->%s<- error\n", "status", *Input)
		} else {
			if vv == "success" {
				n_err++
				fmt.Fprintf(os.Stderr, "JSON Unxpected **lack of error** Error, data=%s\n", buf)
			}
		}

	}

	if n_err == 0 {
		dbgo.Printf("\n%(green)PASS\n")
	} else {
		fmt.Printf("Failed: %d errors\n", n_err)
	}
	os.Exit(n_err)
}

func printSyntaxError(js string, err error) {
	es := jsonSyntaxErroLib.GenerateSyntaxError(js, err)
	fmt.Printf("%s", es)
}
