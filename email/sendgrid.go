package email

// using SendGrid's Go Library
// https://github.com/sendgrid/sendgrid-go

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pschlump/ReadConfig"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/gintools/data"
	"github.com/pschlump/gintools/run_template"
	"github.com/pschlump/scany/pgxscan"
	"github.com/pschlump/uuid"
	sendgrid "github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

// var logFilePtr *os.File
// var gCfg *data.BaseConfigType
// var DbFlag = make(map[string]bool)

//func SetupEmail(gcfg *data.BaseConfigType, db map[string]bool, f *os.File) {
//	gCfg = gcfg
//	DbFlag = db
//	logFilePtr = f
//}

/*
Mail interface to sendgrid.
===============================================
	sendgrid "github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"

	to := mail.NewEmail(toName, toAddress)
	message := mail.NewSingleEmail(from, subject, to, plainTextContent, htmlContent)
	client := sendgrid.NewSendClient(os.Getenv("SENDGRID_API_KEY"))
	response, err := client.Send(message)
*/

type EmailSender interface {
	SendEmailViaVendor(rowID, fromName, fromAddress, subject, toName, toAddress, textBody, htmlBody string)
	SendEmail(template_name string, param ...interface{}) (err error)
	LogError(rowID, msg string, err error)
	LogSuccess(rowID string)
}

type SendgridEmailSender struct {
	// Configuration data
	gCfg *data.BaseConfigType
	// Debug flags like prevent send of email for testing
	DbFlag map[string]bool
	// Log file to write logging to
	logFilePtr *os.File

	// Database Context and Connection
	//
	// Will be used by the LogError, LogSuccess fuctions to track email.
	conn *pgxpool.Pool
	ctx  context.Context

	// Really shoudl ... xyzzy TODO
	// client := sendgrid.NewSendClient(os.Getenv("SENDGRID_API_KEY"))
}

func NewEmailSender(gcfg *data.BaseConfigType, db map[string]bool, f *os.File, conn *pgxpool.Pool, ctx context.Context) (rv EmailSender) {
	return &SendgridEmailSender{
		gCfg:       gcfg,
		DbFlag:     db,
		logFilePtr: f,
		conn:       conn,
		ctx:        ctx,
	}
}

// -------------------------------------------------------------------------------------------------------------------------
/*
   -- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
   -- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
   CREATE TABLE if not exists q_qr_email_log (
   	  email_email_id		uuid DEFAULT uuid_generate_v4() not null primary key
   	, updated 			timestamp
   	, created 			timestamp default current_timestamp not null
   	, user_id			uuid
   	, state				text
   	, error_msg			text
   	, email_data		text
   );
*/
func (this SendgridEmailSender) LogError(rowID, msg string, err error) {

	stmt := `
		update into q_qr_email_log 
			set state = 'Error'
				error_msg = $2
			where email_log_id = $1
	`
	_, e0 := this.SqlRunStmt(stmt, "..", rowID, fmt.Sprintf("%s: %s", msg, err))
	if e0 != nil {
		dbgo.Fprintf(os.Stderr, "%(red)%(LF)Error on update of q_qr_email_log ->%s<- %s error:%s\n", stmt, XData(rowID), e0)
		dbgo.Fprintf(this.logFilePtr, "%(red)%(LF)Error on update of q_qr_email_log ->%s<- %s error:%s\n", stmt, XData(rowID), e0)
	}

}

// -------------------------------------------------------------------------------------------------------------------------
func (this SendgridEmailSender) LogSuccess(rowID string) {

	stmt := `
		update into q_qr_email_log 
			set state = 'Sent-Success'
			where email_log_id = $1
	`
	_, err := this.SqlRunStmt(stmt, "..", rowID)
	if err != nil {
		dbgo.Fprintf(os.Stderr, "%(green)%(LF)Error on update of q_qr_email_log ->%s<- %s error:%s\n", stmt, XData(rowID), err)
		dbgo.Fprintf(this.logFilePtr, "%(green)%(LF)Error on update of q_qr_email_log ->%s<- %s error:%s\n", stmt, XData(rowID), err)
	}

}

// -------------------------------------------------------------------------------------------------------------------------
func (this *SendgridEmailSender) SendEmailViaVendor(rowID, fromName, fromAddress, subject, toName, toAddress, textBody, htmlBody string) {
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
		fmt.Fprintf(this.logFilePtr, "#Email# Send Error: %s\n", err)
		this.LogError(rowID, "Failed to send email", err)
	} else {
		fmt.Println(response.StatusCode)
		fmt.Println(response.Body)
		fmt.Println(response.Headers)
		this.LogSuccess(rowID)
	}
}

// -------------------------------------------------------------------------------------------------------------------------
// SendEmail combines a base template name with globacl configuration on where to find the templates
// and turns that into all the parts of an email, then calls SendEmailViaVendor to send the email.
func (this *SendgridEmailSender) SendEmail(template_name string, param ...interface{}) (err error) {

	tfn := fmt.Sprintf("%s/%s.tmpl", this.gCfg.EmailTmplDir, template_name)
	if !ReadConfig.Exists(tfn) {
		fmt.Fprintf(os.Stderr, "#Email# Missing template file [%s]\n", tfn)
		fmt.Fprintf(this.logFilePtr, "#Email# Missing template file [%s]\n", tfn)
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
	mdata["from_name"] = this.gCfg.EmailFromName
	mdata["from_address"] = this.gCfg.EmailFromAddress

	// run_template.RunTemplate(TemplateFn string, name_of string, g_data map[string]interface{}) string {
	fromName := run_template.RunTemplate(tfn, "from_name", mdata)
	fromAddress := run_template.RunTemplate(tfn, "from_address", mdata)
	subject := run_template.RunTemplate(tfn, "subject", mdata)
	toName := run_template.RunTemplate(tfn, "to_name", mdata)
	toAddress := run_template.RunTemplate(tfn, "to_address", mdata)
	textBody := run_template.RunTemplate(tfn, "text_body", mdata)
	htmlBody := run_template.RunTemplate(tfn, "html_body", mdata)
	UserID, ok := mdata["UserID"]
	if !ok {
		UserID = ""
	}

	if this.gCfg.RedirectEmailSendTo != "" {
		dbgo.Fprintf(os.Stderr, "Redirecting ->%s<- to ->%s<-\n", toAddress, this.gCfg.RedirectEmailSendTo)
		dbgo.Fprintf(this.logFilePtr, "Redirecting ->%s<- to ->%s<-\n", toAddress, this.gCfg.RedirectEmailSendTo)
		toAddress = this.gCfg.RedirectEmailSendTo
	}

	mdata["FromName"] = fromName
	mdata["FromAddress"] = fromAddress
	mdata["ToName"] = toName
	mdata["ToAddress"] = toAddress
	mdata["Subject"] = subject
	mdata["TextBody"] = textBody
	mdata["HtmlBody"] = htmlBody
	mdata["randomval"] = GenUUID() // <a href="{{.server}}api/v1/auth/email-confirm?email_verify_token={{.token}}&redirect_to={{.server}}&__ran__={{.randomval}}"> {{.server}}confirm-email.html </a><br>

	fmt.Fprintf(this.logFilePtr, "%sEmailData%s\n", dbgo.ColorYellow, dbgo.ColorReset)
	fmt.Fprintf(this.logFilePtr, "#EmailData#%s\n", dbgo.SVar(mdata))

	/*
	   -- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	   -- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	   CREATE TABLE if not exists q_qr_email_log (
	   	  email_email_id		uuid DEFAULT uuid_generate_v4() not null primary key
	   	, updated 			timestamp
	   	, created 			timestamp default current_timestamp not null
	   	, user_id			uuid
	   	, state				text
	   	, error_msg			text
	   	, email_data		text
	   );
	*/
	rowID := GenUUID()
	stmt := `insert into q_qr_email_log ( email_log_id, user_id, state, email_data ) values ( $1, $2, $3, $4 )`
	_, err = this.SqlRunStmt(stmt, "...", rowID, UserID, "planned", dbgo.SVar(mdata))
	if err != nil {
		dbgo.Fprintf(os.Stderr, "%(red)%(LF)Error on insert of q_qr_email_log ->%s<- %s error:%s\n", stmt, XData(rowID, UserID, dbgo.SVar(mdata), "planned"), err)
		dbgo.Fprintf(this.logFilePtr, "%(red)%(LF)Error on insert of q_qr_email_log ->%s<- %s error:%s\n", stmt, XData(rowID, UserID, dbgo.SVar(mdata), "planned"), err)
	}

	dbgo.Printf("%(LF) DbFlag=%s\n", dbgo.SVarI(this.DbFlag))
	if this.DbFlag["__email_no_send__:"+toAddress] {
		dbgo.Printf("%(LF) address %s blocked send\n", toAddress)
		fmt.Fprintf(os.Stderr, "at bottom - skip, at:%s\n", dbgo.LF())
		fmt.Fprintf(this.logFilePtr, "at bottom - skip, at:%s\n", dbgo.LF())

		stmt := `
			update into q_qr_email_log 
				set state = 'Dev-Skip'
				where email_log_id = $1
		`
		_, err := this.SqlRunStmt(stmt, "..", rowID, fmt.Sprintf("%s", err))
		if err != nil {
			dbgo.Fprintf(os.Stderr, "%(red)%(LF)Error on update of q_qr_email_log ->%s<- %s error:%s\n", stmt, XData(rowID), err)
			dbgo.Fprintf(this.logFilePtr, "%(red)%(LF)Error on update of q_qr_email_log ->%s<- %s error:%s\n", stmt, XData(rowID), err)
		}

	} else {
		this.SendEmailViaVendor(rowID, fromName, fromAddress, subject, toName, toAddress, textBody, htmlBody)
	}
	if this.DbFlag["__email_no_send__:"+toAddress] || this.DbFlag["dump-email"] {
		fmt.Fprintf(os.Stderr, "\n%s+============================================================================================================\n", dbgo.ColorCyan)
		fmt.Fprintf(os.Stderr, "| Skip of Send of Email.\n|    From Name:%s\n|    From Address:%s\n|    Subject:%s\n|    To:%s\n|    To Address:%s\n|    Text Body:--->%s<---\n     HTML Body --->%s<---\n", fromName, fromAddress, subject, toName, toAddress, textBody, htmlBody)
		fmt.Fprintf(os.Stderr, "+============================================================================================================\n%s\n", dbgo.ColorReset)

		fmt.Fprintf(this.logFilePtr, "\n%s+============================================================================================================\n", "")
		fmt.Fprintf(this.logFilePtr, "| Skip of Send of Email.\n|   From Name:%s\n|    From Address:%s\n|    Subject:%s\n|    To:%s\n|    To Address:%s\n|    Text Body:--->%s<---\n     HTML Body --->%s<---\n", fromName, fromAddress, subject, toName, toAddress, textBody, htmlBody)
		fmt.Fprintf(this.logFilePtr, "+============================================================================================================\n%s\n", "")
	}

	return
}

// -------------------------------------------------------------------------------------------------------------------------
func (this SendgridEmailSender) SqlRunStmt(stmt string, encPat string, data ...interface{}) (rv []map[string]interface{}, err error) {
	if this.conn == nil {
		dbgo.Fprintf(this.logFilePtr, "Connection is nil -- no database connected -- :%(LF)\n")
		return
	}
	fmt.Fprintf(os.Stderr, "Database Stmt ->%s<- data ->%s<-\n", stmt, dbgo.SVar(data))
	fmt.Fprintf(this.logFilePtr, "Database Stmt ->%s<- data ->%s<-\n", stmt, dbgo.SVar(data))

	err = pgxscan.Select(this.ctx, this.conn, &rv, stmt, data...)
	if err != nil {
		fmt.Fprintf(this.logFilePtr, "Sql error: %s stmt: ->%s<- params: %s", err, stmt, XData(data))
		return nil, fmt.Errorf("Sql error: %s stmt: ->%s<- params: %s", err, stmt, XData(data))
	}

	return nil, nil
}

// -------------------------------------------------------------------------------------------------------------------------
// XData convers a list of parameters to a JSON data showing what the list contains.  This is returned as a string.
func XData(x ...interface{}) (rv string) {
	rv = dbgo.SVar(x)
	return
}

// -------------------------------------------------------------------------------------------------------------------------
// GenUUID generates a UUID and returns it.
func GenUUID() string {
	newUUID, _ := uuid.NewV4() // Intentionally ignore errors - function will never return any.
	return newUUID.String()
}
