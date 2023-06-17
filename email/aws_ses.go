package email

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

// using AwsSes's Go Library
// https://github.com/sendgrid/sendgrid-go

import (
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/pschlump/dbgo"
)

type AwsSesEmailSender struct {
	// Log file to write logging to
	emailLogFilePtr *os.File
	// Really shoudl
	// client := sendgrid.NewSendClient(os.Getenv("SENDGRID_API_KEY"))
}

const (
	// The character encoding for the email.
	CharSet = "UTF-8"
)

func NewEmailSenderAwsSes(f *os.File) (rv EmailSenderImplementation) {
	return &AwsSesEmailSender{
		emailLogFilePtr: f,
	}
}

// -------------------------------------------------------------------------------------------------------------------------
func (em *AwsSesEmailSender) SendEmailViaVendor(rowID, fromName, fromAddress, subject, toName, toAddress, textBody, htmlBody string) (error, string) {

	// Create a new session in the us-east-1 region.
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-1")},
	)
	if err != nil {
		return err, ""
	}

	// Create an SES session.
	svc := ses.New(sess)

	// Assemble the email.
	input := &ses.SendEmailInput{
		Destination: &ses.Destination{
			CcAddresses: []*string{},
			ToAddresses: []*string{
				aws.String(toAddress),
			},
		},
		Message: &ses.Message{
			Body: &ses.Body{
				Html: &ses.Content{
					Charset: aws.String(CharSet),
					Data:    aws.String(htmlBody),
				},
				Text: &ses.Content{
					Charset: aws.String(CharSet),
					Data:    aws.String(textBody),
				},
			},
			Subject: &ses.Content{
				Charset: aws.String(CharSet),
				Data:    aws.String(subject),
			},
		},
		Source: aws.String(fromAddress),
		// Uncomment to use a configuration set
		// ConfigurationSetName: aws.String(ConfigurationSet),
	}

	// Attempt to send the email.
	result, err := svc.SendEmail(input)

	// Display error messages if they occur.
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case ses.ErrCodeMessageRejected:
				fmt.Println(ses.ErrCodeMessageRejected, aerr.Error())
			case ses.ErrCodeMailFromDomainNotVerifiedException:
				fmt.Println(ses.ErrCodeMailFromDomainNotVerifiedException, aerr.Error())
			case ses.ErrCodeConfigurationSetDoesNotExistException:
				fmt.Println(ses.ErrCodeConfigurationSetDoesNotExistException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and Message from an error.
			fmt.Println(err.Error())
		}

		// em.LogError(rowID, "Failed to send email", err)
		return err, ""
	}

	// dbgo.Fprintf(em.emailLogFilePtr, "Success: result= ->%s<-\n", dbgo.SVarI(result))

	// em.LogSuccess(rowID)
	return nil, fmt.Sprintf("%s", dbgo.SVar(result))
}

/* vim: set noai ts=4 sw=4: */
