package email

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

// using SendGrid's Go Library, See: https://github.com/sendgrid/sendgrid-go

import (
	"fmt"
	"io"
	"os"

	"github.com/pschlump/dbgo"
	sendgrid "github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

type SendgridEmailSender struct {
	// Log file to write logging to
	emailLogFilePtr io.WriteCloser // emailLogFilePtr *os.File
}

// func NewEmailSenderSendgrid(f *os.File) (rv EmailSenderImplementation) {
func NewEmailSenderSendgrid(f io.WriteCloser) (rv EmailSenderImplementation) {
	return &SendgridEmailSender{
		emailLogFilePtr: f,
	}
}

// -------------------------------------------------------------------------------------------------------------------------
func (em *SendgridEmailSender) SendEmailViaVendor(rowID, fromName, fromAddress, subject, toName, toAddress, textBody, htmlBody string) (err error, result string) {
	// from := mail.NewEmail("Example User", "test@example.com")
	from := mail.NewEmail(fromName, fromAddress)
	// subject := "Sending with SendGrid is Fun"
	// to := mail.NewEmail("Example User", "pschlump@gmail.com")
	to := mail.NewEmail(toName, toAddress)
	// plainTextContent := "and easy to do anywhere, even with Go"
	plainTextContent := textBody
	// htmlContent := "<strong>and easy to do anywhere, even with Go</strong>"
	htmlContent := htmlBody
	message := mail.NewSingleEmail(from, subject, to, plainTextContent, htmlContent)
	client := sendgrid.NewSendClient(os.Getenv("SENDGRID_API_KEY"))
	response, e0 := client.Send(message)
	if e0 != nil {
		dbgo.Fprintf(os.Stderr, "%(red)#Email# Send Error: %s\n", err)
		return e0, ""
	}
	if response.StatusCode == 202 || response.StatusCode == 200 {
		dbgo.Printf("%(green)StatusCode=%v\n", response.StatusCode)
		fmt.Println(response.Body)
		fmt.Println(response.Headers)
	} else {
		dbgo.Printf("%(red)StatusCode=%v\n", response.StatusCode)
		dbgo.Printf("%(red)body=%s\n", response.Body)
		dbgo.Printf("%(red)Headers=%s\n", response.Headers)
		err = fmt.Errorf("Status: %v Message: %s\n", response.StatusCode, response.Body)
		return err, ""
	}
	return nil, fmt.Sprintf(`{"status":"success","status_code":%d,"header":%q,"body":%q}`, response.StatusCode, response.Headers, response.Body)
}

/* vim: set noai ts=4 sw=4: */
