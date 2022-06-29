package email

// using SendGrid's Go Library
// https://github.com/sendgrid/sendgrid-go

import (
	"fmt"
	"os"

	"github.com/pschlump/ReadConfig"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/gintools/data"
	"github.com/pschlump/gintools/run_template"
	"github.com/pschlump/uuid"
	sendgrid "github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

var logFilePtr *os.File
var gCfg *data.BaseConfigType
var DbFlag = make(map[string]bool)

func SetupEmail(gcfg *data.BaseConfigType, db map[string]bool, f *os.File) {
	gCfg = gcfg
	DbFlag = db
	logFilePtr = f
}

func SendEmailViaSendgrid(fromName, fromAddress, subject, toName, toAddress, textBody, htmlBody string) {
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
	response, err := client.Send(message)
	if err != nil {
		fmt.Fprintf(logFilePtr, "#Email# Send Error: %s\n", err)
	} else {
		fmt.Println(response.StatusCode)
		fmt.Println(response.Body)
		fmt.Println(response.Headers)
	}
}

// SendEmail combines a base template name with globacl configuration on where to find the templates
// and turns that into all the parts of an email, then calls SendEmailViaSendgrid to send the email.
func SendEmail(template_name string, param ...interface{}) (err error) {

	tfn := fmt.Sprintf("%s/%s.tmpl", gCfg.EmailTmplDir, template_name)
	if !ReadConfig.Exists(tfn) {
		fmt.Fprintf(os.Stderr, "#Email# Missing template file [%s]\n", tfn)
		fmt.Fprintf(logFilePtr, "#Email# Missing template file [%s]\n", tfn)
		return fmt.Errorf("Missing template file [%s]\n", tfn)
	}

	mdata := make(map[string]interface{})
	for ii := 0; ii < len(param); ii += 2 {
		var val interface{}
		if ii+1 < len(param) {
			val = param[ii+1]
		} else {
			val = ""
		}
		key := fmt.Sprintf("%s", param[ii])
		mdata[key] = val
	}
	mdata["tfn"] = tfn
	mdata["from_name"] = gCfg.EmailFromName
	mdata["from_address"] = gCfg.EmailFromAddress

	// run_template.RunTemplate(TemplateFn string, name_of string, g_data map[string]interface{}) string {
	fromName := run_template.RunTemplate(tfn, "from_name", mdata)
	fromAddress := run_template.RunTemplate(tfn, "from_address", mdata)
	subject := run_template.RunTemplate(tfn, "subject", mdata)
	toName := run_template.RunTemplate(tfn, "to_name", mdata)
	toAddress := run_template.RunTemplate(tfn, "to_address", mdata)
	textBody := run_template.RunTemplate(tfn, "text_body", mdata)
	htmlBody := run_template.RunTemplate(tfn, "html_body", mdata)

	mdata["FromName"] = fromName
	mdata["FromAddress"] = fromAddress
	mdata["ToName"] = toName
	mdata["ToAddress"] = toAddress
	mdata["Subject"] = subject
	mdata["TextBody"] = textBody
	mdata["HtmlBody"] = htmlBody
	mdata["randomval"] = GenUUID() // <a href="{{.server}}api/v1/auth/email-confirm?email_verify_token={{.token}}&redirect_to={{.server}}&__ran__={{.randomval}}"> {{.server}}confirm-email.html </a><br>

	fmt.Fprintf(logFilePtr, "%sEmailData%s\n", dbgo.ColorYellow, dbgo.ColorReset)
	fmt.Fprintf(logFilePtr, "#EmailData#%s\n", dbgo.SVar(mdata))

	dbgo.Printf("%(LF) DbFlag=%s\n", dbgo.SVarI(DbFlag))
	if DbFlag["__email_no_send__:"+toAddress] {
		dbgo.Printf("%(LF) address %s blocked send\n", toAddress)
		fmt.Fprintf(os.Stderr, "at bottom - skip, at:%s\n", dbgo.LF())
		fmt.Fprintf(logFilePtr, "at bottom - skip, at:%s\n", dbgo.LF())
	} else {
		SendEmailViaSendgrid(fromName, fromAddress, subject, toName, toAddress, textBody, htmlBody)
	}
	if DbFlag["__email_no_send__:"+toAddress] || DbFlag["dump-email"] {
		fmt.Fprintf(os.Stderr, "\n%s+============================================================================================================\n", dbgo.ColorCyan)
		fmt.Fprintf(os.Stderr, "| Skip of Send of Email.\n|    From Name:%s\n|    From Address:%s\n|    Subject:%s\n|    To:%s\n|    To Address:%s\n|    Text Body:--->%s<---\n     HTML Body --->%s<---\n", fromName, fromAddress, subject, toName, toAddress, textBody, htmlBody)
		fmt.Fprintf(os.Stderr, "+============================================================================================================\n%s\n", dbgo.ColorReset)

		fmt.Fprintf(logFilePtr, "\n%s+============================================================================================================\n", "")
		fmt.Fprintf(logFilePtr, "| Skip of Send of Email.\n|   From Name:%s\n|    From Address:%s\n|    Subject:%s\n|    To:%s\n|    To Address:%s\n|    Text Body:--->%s<---\n     HTML Body --->%s<---\n", fromName, fromAddress, subject, toName, toAddress, textBody, htmlBody)
		fmt.Fprintf(logFilePtr, "+============================================================================================================\n%s\n", "")
	}

	return
}

// GenUUID generates a UUID and returns it.
func GenUUID() string {
	newUUID, _ := uuid.NewV4() // Intentionally ignore errors - function will never return any.
	return newUUID.String()
}
