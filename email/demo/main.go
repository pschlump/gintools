package main

import (
	"os"

	"github.com/pschlump/gintools/data"
	"github.com/pschlump/gintools/email"
)

var gCfg data.BaseConfigType
var DbFlag map[string]bool
var logFilePtr *os.File

func main() {
	gCfg = data.BaseConfigType{}
	DbFlag = make(map[string]bool)
	logFilePtr = os.Stderr

	// email.SetupEmail(gcfg *ymux.BaseConfigType, db map[string]bool, f *os.File)
	em := email.NewEmailSender("sendgird", &gCfg, DbFlag, logFilePtr, nil /*conn*/, nil /*ctx*/, nil /*logger*/, nil /* /metrics */)

	fromName := "Philip Schlump"
	fromAddress := "pschlump@gmail.com"
	subject := "test 1"
	toName := "Philip Schlump Test 1"
	toAddress := "pschlump@gmail.com"
	textBody := "Text Body"
	htmlBody := "<h1> HTML body </h1>"

	em.SendEmailViaVendor("", fromName, fromAddress, subject, toName, toAddress, textBody, htmlBody)

}
