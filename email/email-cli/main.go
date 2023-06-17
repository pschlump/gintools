package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/pschlump/filelib"
	"github.com/pschlump/gintools/data"
	"github.com/pschlump/gintools/email"
)

var gCfg data.BaseConfigType
var DbFlag map[string]bool = make(map[string]bool)
var logFilePtr *os.File = os.Stderr

// var Cfg = flag.String("cfg", "cfg.json", "config file for this call")
var DbFlagParam = flag.String("db_flag", "", "Additional Debug Flags")

var Transport = flag.String("transport", "sendgrid", "One of 'sendgrid' or 'aws_ses' - determines how to send the email")
var FromName = flag.String("from-name", "Philip Schlump", "Name of person sending email from")
var FromEmailAddress = flag.String("from-addr", "pschlump@gmail.com", "Email address sednding from")
var Subject = flag.String("subject", "Test Email", "Subject of email")
var ToName = flag.String("to-name", "Philip Schlump", "Name of person sending to.")
var ToEmailAddress = flag.String("to-addr", "pschlump@gmail.com", "Email address sending to.")
var TextBody = flag.String("text-body", "This is a test body - text.", "Text body of email.")
var HtmlBody = flag.String("html-body", "<h1>This is a test</h1><br /><p> body - html.</p>", "HTML body of email")

func main() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "email-cli: Usage: %s [flags]\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse() // Parse CLI arguments to this, --cfg <name>.json

	fns := flag.Args()
	if len(fns) != 0 {
		fmt.Printf("Extra arguments are not supported [%s]\n", fns)
		os.Exit(1)
	}

	gCfg = data.BaseConfigType{}

	for _, s := range strings.Split(*DbFlagParam, ",") {
		DbFlag[s] = true
	}

	if *Transport == "aws_ses" {
		if !filelib.Exists(fmt.Sprintf("%s/.aws/credentials", os.Getenv("HOME"))) {
			fmt.Fprintf(os.Stderr, "Missing ~/.aws/credentials file\n")
			os.Exit(1)
		}
	}
	if *Transport == "sendgrid" {
		if os.Getenv("SENDGRID_API_KEY") == "" {
			fmt.Fprintf(os.Stderr, "Missing SENDGRID_API_KEY in environment\n")
			os.Exit(1)
		}
	}

	em := email.NewEmailSender(*Transport, &gCfg, DbFlag, logFilePtr, nil /*conn*/, nil /*ctx*/, nil /*logger*/, nil /* /metrics */)

	err := em.SendEmailViaVendor("--id--", *FromName, *FromEmailAddress, *Subject, *ToName, *ToEmailAddress, *TextBody, *HtmlBody)

	if err != nil {
		fmt.Printf("Error:%s\n", err)
		return
	}

}
