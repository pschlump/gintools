package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"

	"github.com/pschlump/filelib"
)

var input = flag.String("input", "", "Input file, instead of taking input form CLI")
var output = flag.String("output", "", "Output file, instead of sending output to Stdout")

func main() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "url-encode: Usage: %s [ --input file ] [ --output file ] [ values... ]\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse() // Parse CLI arguments to this, --cfg <name>.json

	ofp := os.Stdout
	if *output != "" {
		var err error
		ofp, err = filelib.Fopen(*output, "w")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to open %s for output.  Error: %s\n", *output, err)
			os.Exit(1)
		}
	}

	if *input != "" {
		if len(flag.Args()) != 0 {
			fmt.Fprintf(os.Stderr, "Arguments are not supported with --input <file> is used.\n")
			os.Exit(1)
		}
		buf, err := ioutil.ReadFile(*input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to open %s for input.  Error: %s\n", *input, err)
			os.Exit(1)
		}
		fmt.Fprintf(ofp, "%s\n", url.QueryEscape(string(buf)))
	} else {
		for _, vv := range flag.Args() {
			// fmt.Printf("Extra arguments are not supported [%s]\n", fns)
			// os.Exit(1)
			fmt.Fprintf(ofp, "%s\n", url.QueryEscape(vv))
		}
	}
}
