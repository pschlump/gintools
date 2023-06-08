package main

/*
======================================================================== JSON formatter ========================================================================
input [{"a":12,"b":"abc"},{"a":44,"b":"xyz"}]
  or
input {"data":[...]}
ouptut:
	a	b
	12	abc
	44	xyz
Options:
	--cols="[{"name":"a"},{"name":"b","tmpl":"{{.b}}"}]		-- lists in order to dispay, skip column if no display, else a default template set.
	--hdr=""
	--footer=""
	--fmt=text|html											-- deault text or html template

	--input fn
	--output fn


Example data source:
	-rwxr-xr-x  1 philip    340 Oct 12 13:45 tgo_list_users.sh
Example Data
	./testdata/get-table-user.out

*/

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
var Input = flag.String("input", "", "Input JSON File")
var Output = flag.String("output", "-", "Output JSON File")

var DbOn map[string]bool = make(map[string]bool)

var Debug bool

type tab []row
type row map[string]interface{}

func init() {
	DbOn = make(map[string]bool)
}

func main() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "json-formatter : Usage: %s [-r] -i file name1... name2...\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse() // Parse CLI arguments to this, --cfg <name>.json

	fns := flag.Args()
	if len(fns) != 0 {
		fmt.Printf("Additional arguments are not supported\n")
		os.Exit(1)
	}

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

	var TabData tab
	mdata := make(map[string]interface{})
	// mdata2 := make([]map[string]interface{}, 10)
	err = json.Unmarshal(buf, &mdata)
	dbgo.Printf("%(LF) len=%d\n", len(mdata))
	if err == nil && len(mdata) > 0 {
		dbgo.Printf("%(LF)\n")
		if data, ok := mdata["data"]; ok {
			dbgo.Printf("%(LF)\n")
			var ok2 bool
			x1, ok2 := data.([]interface{})
			if ok2 {
				dbgo.Printf("%(LF)\n")
				for ii, vv := range x1 {
					dbgo.Printf("%(LF)\n")
					dd, ok3 := vv.(map[string]interface{})
					if !ok3 {
						dbgo.Printf("%(LF) - row is not a map[string]interface{} at %d\n", ii)
					}
					TabData = append(TabData, dd)
				}
				dbgo.Printf("%(LF)\n")
				goto parsed
			}
			fmt.Fprintf(os.Stderr, "Type Conversion error on %s error, Type is %T\n", *Input, data)
			os.Exit(1)
		}
	}

	// xyzzy - TODO []map[stirng]interface data.
	if err != nil {
		dbgo.Printf("%(LF)len=%d\n", len(mdata))
		if err != nil {
			fmt.Fprintf(os.Stderr, "JSON parse error on %s error : %s\n", *Input, err)
			printSyntaxError(string(buf), err)
			os.Exit(1)
		}
		dbgo.Printf("%(LF)len=%d\n", len(mdata))
	}

parsed:
	;

	dbgo.Printf("%(AT)\n")
	defaultTemplates := make(map[string]string)
	for _, vv := range TabData {
		for k := range vv {
			defaultTemplates[k] = fmt.Sprintf("{{.%s}}", k)
		}
	}

	dbgo.Printf("%(yellow)%s\n", dbgo.SVarI(defaultTemplates))

}

func printSyntaxError(js string, err error) {
	es := jsonSyntaxErroLib.GenerateSyntaxError(js, err)
	fmt.Printf("%s", es)
}
