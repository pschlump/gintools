package main

// Read Input - By Stream - and split into chunks

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"

	"github.com/pschlump/dbgo"
	"github.com/pschlump/filelib"
)

// --pattern PAT for output		"z-%04d" -
// --output-dir DIR
// --size-k Output-Size-in-K or M
// --size-m Output-Size-in-K or M
// stream-split --output-dir ./testout --size-m 5 -pattern "z-%07d--$DT.dat" --tmp-dir ./tmp --exec-cmd "./backup-and-encrypt-file.sh %s"

var DbFlagParam = flag.String("db_flag", "", "Additional Debug Flags.")
var Pattern = flag.String("pattern", "z-%04d", "File Name Pattern.")
var OutputDir = flag.String("output-dir", "./", "Directory to place fiels in.")
var TmpDir = flag.String("tmp-dir", "", "Directory to place intermediate fiels in.")
var SizeK = flag.String("size-k", "", "Size in Kb of each output file.")
var SizeM = flag.String("size-m", "", "Size in Mb of each output file.")
var Input = flag.String("input", "", "Name of Input file - default is to use stdin.")
var ExecCmd = flag.String("exec-cmd", "", "Command to run when file is complete.")

var DbOn map[string]bool = make(map[string]bool)

func main() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "jsonCheck : Usage: %s [-r] -i file name1... name2...\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse() // Parse CLI arguments to this, --cfg <name>.json

	fns := flag.Args()
	if len(fns) != 0 {
		fmt.Printf("Arguments are not supported [%s]\n", fns)
		os.Exit(1)
	}

	// ----------------------------------------------------------------------------------------------------------

	r := os.Stdin
	if *Input != "" {
		fp, err := filelib.Fopen(*Input, "r")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening %s for input: %s\n", *Input, err)
			os.Exit(1)
		}
		r = fp
	}

	nk := 1
	if *SizeK != "" {
		n, err := strconv.ParseInt(*SizeK, 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error not a numeric value for --size-k: ->%s<- error: %s\n", *SizeK, err)
			os.Exit(1)
		}
		nk = int(n)
	} else if *SizeM != "" {
		n, err := strconv.ParseInt(*SizeM, 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error not a numeric value for --size-m: ->%s<- error: %s\n", *SizeM, err)
			os.Exit(1)
		}
		nk = int(n) * 1024
	} else {
		fmt.Fprintf(os.Stderr, "Must supply --size-k VALUE or --size-m VALUE parameters.\n")
		os.Exit(1)
	}

	if DbOn["show-output-size"] {
		dbgo.Fprintf(os.Stderr, "Size in K = %d at:%(LF)\n", nk)
	}

	// ----------------------------------------------------------------------------------------------------------

	b := make([]byte, 1024)
	var ofp *os.File = nil
	ofp = nil
	var fn, fn2 string

	ii, jj, nbw, fnNo := 0, 0, 0, 0
	done := false
	for {
		n, err := r.Read(b)

		if err == io.EOF {
			done = true
		}

		if DbOn["output-details"] {
			fmt.Printf("n = %d err = %s ", n, err)
			if n > 0 {
				fmt.Printf("b = ->%s<-\n", b[:n])
			} else {
				fmt.Printf("b = \"\"\n")
			}
		}

		if ii >= nk || ofp == nil {
			if ofp != nil {
				ofp.Close()
				if nbw == 0 {
					os.Remove(fn)
				} else {
					if fn != fn2 {
						err := os.Rename(fn, fn2)
						if err != nil {
							fmt.Fprintf(os.Stderr, "Error Failed to rename from: ->%s<- to: ->%s<- error: %s\n", fn, fn2, err)
							os.Exit(1)
						}
					}
					if *ExecCmd != "" {
						RunCmd(*ExecCmd, fn2)
					}
				}
				nbw = 0
			}

			if *TmpDir != "" {
				fn = fmt.Sprintf("%s/"+*Pattern, *TmpDir, fnNo)
			} else {
				fn = fmt.Sprintf("%s/"+*Pattern, *OutputDir, fnNo)
			}
			fn2 = fmt.Sprintf("%s/"+*Pattern, *OutputDir, fnNo)
			fnNo++

			ofp, err = filelib.Fopen(fn, "w")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error opening ->%s<- for output: %s\n", fn, err)
				os.Exit(1)
			}
			ii = 0
		}
		ii++

		if n > 0 {
			nbw += n
			ofp.Write(b[0:n])
		}

		if done {
			break
		}

		jj++
	}
	if ofp != nil {
		ofp.Close()
		if nbw == 0 {
			os.Remove(fn)
		} else {
			if fn != fn2 {
				err := os.Rename(fn, fn2)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error Failed to rename from: ->%s<- to: ->%s<- error: %s\n", fn, fn2, err)
					os.Exit(1)
				}
			}
			if *ExecCmd != "" {
				RunCmd(*ExecCmd, fn2)
			}
		}
		nbw = 0
	}
}

func RunCmd(cmd0 string, param ...string) (err error) {

	cmd := exec.Command(cmd0, param...)

	err = cmd.Run()

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error running ->%s<- with ->%s<- Error: %s\n", cmd0, param, err)
		return
	}

	return
}
