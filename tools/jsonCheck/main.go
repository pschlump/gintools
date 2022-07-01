package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	jsonSyntaxErroLib "github.com/pschlump/check-json-syntax/lib"
	"github.com/pschlump/json"
	"github.com/pschlump/uuid"
)

var DbFlagParam = flag.String("db_flag", "", "Additional Debug Flags")
var Input = flag.String("i", "", "Input JSON File")
var Rev = flag.Bool("r", false, "Reverse logic - must not have")

var IsNonZeroLen = flag.Bool("z", false, "Check for non-zero length field") // TODO -- not tested yet
var IsUUID = flag.Bool("u", false, "Check Field is a UUID")                 // TODO -- not tested yet
var IsInt = flag.Bool("n", false, "Check Field is an Int/Number")           // TODO -- not tested yet

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
	if len(fns) == 0 {
		fmt.Printf("Missing arguments are not supported [%s]\n", fns)
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

		for _, arg := range fns {
			if vv, ok := mdata[arg]; !ok {
				n_err++
				fmt.Fprintf(os.Stderr, "JSON missing field ->%s<- in ->%s<- error\n", arg, *Input)
			} else {
				if *IsNonZeroLen {
					if ss, ok := vv.(string); !ok {
						n_err++
						fmt.Fprintf(os.Stderr, "JSON unable to cast to a string - not a valid string ->%s<- in ->%s<- error\n", arg, *Input)
					} else {
						if len(ss) == 0 {
							n_err++
							fmt.Fprintf(os.Stderr, "JSON length of string 0 ->%s<- in ->%s<- error\n", arg, *Input)
						}
					}
				}
				if *IsUUID {
					if ss, ok := vv.(string); !ok {
						n_err++
						fmt.Fprintf(os.Stderr, "JSON unable to cast to a string - not a valid string ->%s<- in ->%s<- error\n", arg, *Input)
					} else {
						if !uuid.IsUUID(ss) {
							n_err++
							fmt.Fprintf(os.Stderr, "JSON invalid UUID ->%s<- in ->%s<- error\n", arg, *Input)
						}
					}
				}
				if *IsInt {
					if ss, ok := vv.(string); !ok {
						n_err++
						fmt.Fprintf(os.Stderr, "JSON unable to cast to a string - not a valid string ->%s<- in ->%s<- error\n", arg, *Input)
					} else {
						if _, err := strconv.ParseInt(ss, 10, 64); err != nil {
							n_err++
							fmt.Fprintf(os.Stderr, "JSON invalid integer ->%s<- in ->%s<- error:%s\n", arg, *Input, err)
						}
					}
				}
			}
		}

	} else {

		for _, arg := range fns {
			if vv, ok := mdata[arg]; ok {
				n_err++
				fmt.Fprintf(os.Stderr, "JSON field that should not be there ->%s<- found in ->%s<- error\n", arg, *Input)
			} else {
				if *IsNonZeroLen {
					if ss, ok := vv.(string); !ok { // Logic Same As Reversed -- Must Still Be a String
						n_err++
						fmt.Fprintf(os.Stderr, "JSON unable to cast to a string - not a valid string ->%s<- in ->%s<- error\n", arg, *Input)
					} else {
						if len(ss) != 0 { // Logic Reversed from above
							n_err++
							fmt.Fprintf(os.Stderr, "JSON length of string 0 ->%s<- in ->%s<- error\n", arg, *Input)
						}
					}
				}
				if *IsUUID {
					if ss, ok := vv.(string); !ok { // Logic Same As Reversed -- Must Still Be a String
						n_err++
						fmt.Fprintf(os.Stderr, "JSON unable to cast to a string - not a valid string ->%s<- in ->%s<- error\n", arg, *Input)
					} else {
						if uuid.IsUUID(ss) { // Logic Reversed from above
							n_err++
							fmt.Fprintf(os.Stderr, "JSON invalid UUID ->%s<- in ->%s<- error\n", arg, *Input)
						}
					}
				}
				if *IsInt {
					if ss, ok := vv.(string); !ok { // Logic Same As Reversed -- Must Still Be a String
						n_err++
						fmt.Fprintf(os.Stderr, "JSON unable to cast to a string - not a valid string ->%s<- in ->%s<- error\n", arg, *Input)
					} else {
						if _, err := strconv.ParseInt(ss, 10, 64); err == nil { // Logic Reversed from above
							n_err++
							fmt.Fprintf(os.Stderr, "JSON invalid integer ->%s<- in ->%s<- error:%s\n", arg, *Input, err)
						}
					}
				}
			}
		}

	}

	if n_err == 0 {
		fmt.Printf("\nPASS\n")
	} else {
		fmt.Printf("Failed: %d errors\n", n_err)
	}
	os.Exit(n_err)
}

func printSyntaxError(js string, err error) {
	es := jsonSyntaxErroLib.GenerateSyntaxError(js, err)
	fmt.Printf("%s", es)
}
