package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
)

func main() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "url-encode: Usage: %s values...\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse() // Parse CLI arguments to this, --cfg <name>.json

	for _, vv := range flag.Args() {
		// fmt.Printf("Extra arguments are not supported [%s]\n", fns)
		// os.Exit(1)
		fmt.Printf("%s\n", url.QueryEscape(vv))
	}
}
