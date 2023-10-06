package email

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

// EMail interface to sendgrid, aws_ses.

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pschlump/ReadConfig"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/filelib"
	"github.com/pschlump/gintools/data"
	"github.com/pschlump/gintools/metrics"
	"github.com/pschlump/gintools/run_template"
	"github.com/pschlump/scany/pgxscan"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type EmailSender interface {
	SendEmailViaVendor(rowID, fromName, fromAddress, subject, toName, toAddress, textBody, htmlBody string) (err error)
	SendEmail(template_name string, param ...interface{}) (err error)
	SendEmailMapdata(template_name string, mdata map[string]interface{}) (err error)
	LogError(rowID, msg string, err error)
	LogSuccess(rowID string)
}

type EmailSenderImplementation interface {
	SendEmailViaVendor(rowID, fromName, fromAddress, subject, toName, toAddress, textBody, htmlBody string) (err error, result string)
}

type GenericEmailSender struct {
	SenderName string

	TheSender EmailSenderImplementation

	// Configuration data
	gCfg *data.BaseConfigType
	// Debug flags like prevent send of email for testing
	DbFlag map[string]bool
	// Log file to write logging to
	emailLogFilePtr *os.File

	// Logging and Metrics
	md     *metrics.MetricsData
	logger *zap.Logger

	// Database Context and Connection
	//
	// Will be used by the LogError, LogSuccess fuctions to track email.
	conn *pgxpool.Pool
	ctx  context.Context

	// Timed Sender Data
	nTicks  int
	ch      chan string
	timeout chan string
}

// func NewEmailSender(senderType string, gcfg *data.BaseConfigType, db map[string]bool, f *os.File, conn *pgxpool.Pool, ctx context.Context, lgr *zap.Logger, xmd *metrics.MetricsData) (rv GenericEmailSender) {
func NewEmailSender(senderType string, gcfg *data.BaseConfigType, db map[string]bool, f *os.File, conn *pgxpool.Pool, ctx context.Context, lgr *zap.Logger, xmd *metrics.MetricsData) (rv EmailSender) {

	if xmd != nil {
		validKeys := []metrics.MetricsTypeInfo{
			{
				Key:  "email_sender_successful_emails",
				Desc: "Count of Successful Emails Sent",
			},
			{
				Key:  "email_sender_failed_emails",
				Desc: "Count of Failed Emails Sent",
			},
			{
				Key:  "email_sender_redirect_email_to_address",
				Desc: "Count of Failed Emails Sent",
			},
			{
				Key:  "email_sender_sql_error",
				Desc: "Count of sql errors",
			},
			{
				Key:  "email_sender_timed_check_for_email",
				Desc: "Count of sql errors",
			},
		}

		xmd.AddMetricsKeys(validKeys)
	}

	var xv GenericEmailSender

	xv.SenderName = senderType
	xv.nTicks = 0
	xv.ch = make(chan string, 1)
	xv.timeout = make(chan string, 2)
	xv.emailLogFilePtr = f
	xv.gCfg = gcfg
	xv.DbFlag = db
	xv.conn = conn
	xv.ctx = ctx
	xv.logger = lgr
	xv.md = xmd

	switch senderType {
	case "sendgrid":
		xv.TheSender = NewEmailSenderSendgrid(f)
	case "aws_ses":
		xv.TheSender = NewEmailSenderAwsSes(f)
	default:
		fmt.Fprintf(xv.emailLogFilePtr, "Fatal Configuration Error: Invalid email sender type >%s<-, should be one of [ \"sendgrid\", \"aws_ses\" ]\n", senderType)
		os.Exit(1)
	}

	if gcfg.EmailTickerSeconds >= 1 {
		xv.initializeTimedSender()
	}

	return &xv
}

// -------------------------------------------------------------------------------------------------------------------------
/*
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
func (em GenericEmailSender) LogError(rowID, msg string, err error) {
	stmt := `
		update q_qr_email_log 
			set state = 'Error'
				error_msg = $2
			where email_log_id = $1
	`
	_, e0 := em.SqlRunStmt(stmt, "..", rowID, fmt.Sprintf("%s: %s", msg, err))
	if e0 != nil {
		dbgo.Fprintf(os.Stderr, "%(red)%(LF)Error on update of q_qr_email_log ->%s<- %s error:%s\n", stmt, XData(rowID), e0)
		dbgo.Fprintf(em.emailLogFilePtr, "%(LF)Error on update of q_qr_email_log ->%s<- %s error:%s\n", stmt, XData(rowID), e0)
	}

}

func (em GenericEmailSender) LogSuccess(rowID string) {
	stmt := `
		update q_qr_email_log 
			set state = 'Sent-Success'
			where email_log_id = $1
	`
	_, err := em.SqlRunStmt(stmt, "..", rowID)
	if err != nil {
		dbgo.Fprintf(os.Stderr, "%(green)%(LF)Error on update of q_qr_email_log ->%s<- %s error:%s\n", stmt, XData(rowID), err)
		dbgo.Fprintf(em.emailLogFilePtr, "%(LF)Error on update of q_qr_email_log ->%s<- %s error:%s\n", stmt, XData(rowID), err)
	}
}

// SendEmailViaVendor will use the underlying implemenation to send the email.
func (em *GenericEmailSender) SendEmailViaVendor(rowID, fromName, fromAddress, subject, toName, toAddress, textBody, htmlBody string) (err error) {
	err, result := em.TheSender.SendEmailViaVendor(rowID, fromName, fromAddress, subject, toName, toAddress, textBody, htmlBody)
	if err != nil {
		em.md.AddCounter("email_sender_failed_emails", 1)
		em.LogError(rowID, "Failed to send email", err)
		fmt.Fprintf(em.emailLogFilePtr, "#Email# Send Error: %s\n", err)
		return
	}
	fmt.Fprintf(em.emailLogFilePtr, "#Email# Send Success, %v\n", result)
	em.md.AddCounter("email_sender_successful_emails", 1)
	dbgo.Fprintf(em.emailLogFilePtr, "Success: result= ->%s<-\n", dbgo.SVarI(result))
	em.LogSuccess(rowID)
	return err
}

// SendEmail combines a base template name with globacl configuration on where to find the templates
// and turns that into all the parts of an email, then calls SendEmailViaVendor to send the email.
func (em *GenericEmailSender) SendEmail(template_name string, param ...interface{}) (err error) {

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

	return em.SendEmailMapdata(template_name, mdata)
}

func (em *GenericEmailSender) SendEmailMapdata(template_name string, mdata map[string]interface{}) (err error) {

	dbgo.Printf("%(LF) %(cyan) ---- AT TOP mdata=%s\n", dbgo.SVarI(mdata))
	dbgo.Fprintf(em.emailLogFilePtr, "%(LF) --- AT TOP --- mdata=%s\n", dbgo.SVarI(mdata))

	tfn := fmt.Sprintf("%s/%s.tmpl", em.gCfg.EmailTmplDir, template_name)
	CurDir, _ := os.Getwd()
	dbgo.Printf("%(LF) %(cyan) ---- template file = ->%s<- in dir ->%s<-\n", tfn, CurDir)
	if !ReadConfig.Exists(tfn) {
		fmt.Fprintf(os.Stderr, "#Email# Missing template file [%s]\n", tfn)
		fmt.Fprintf(em.emailLogFilePtr, "#Email# Missing template file [%s]\n", tfn)
		return fmt.Errorf("Missing template file [%s]\n", tfn)
	}

	dbgo.Printf("%(LF)\n")

	mdata["tfn"] = tfn
	mdata["from_name"] = em.gCfg.EmailFromName
	mdata["from_address"] = em.gCfg.EmailFromAddress

	dbgo.Printf("%(LF) %(yellow) mdata=%s\n", dbgo.SVarI(mdata))
	dbgo.Fprintf(em.emailLogFilePtr, "%(LF) mdata=%s\n", dbgo.SVarI(mdata))

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

	dbgo.Printf("%(LF)\n")
	if em.gCfg.RedirectEmailSendTo != "" {
		if em.logger != nil {
			fields := []zapcore.Field{
				zap.String("message", "Redirecting Email"),
				zap.String("originalAddress", toAddress),
				zap.String("sentTo", em.gCfg.RedirectEmailSendTo),
			}
			em.logger.Info("email_sender_redirect_email_to_address", fields...)
		} else {
			dbgo.Fprintf(os.Stderr, "Redirecting ->%s<- to ->%s<-\n", toAddress, em.gCfg.RedirectEmailSendTo)
		}
		dbgo.Fprintf(em.emailLogFilePtr, "Redirecting ->%s<- to ->%s<-\n", toAddress, em.gCfg.RedirectEmailSendTo)
		toAddress = em.gCfg.RedirectEmailSendTo
	}

	dbgo.Printf("%(LF)\n")
	mdata["FromName"] = fromName
	mdata["FromAddress"] = fromAddress
	mdata["ToName"] = toName
	mdata["ToAddress"] = toAddress
	mdata["Subject"] = subject
	mdata["TextBody"] = textBody
	mdata["HtmlBody"] = htmlBody
	mdata["randomval"] = GenUUID() // <a href="{{.server}}api/v1/auth/email-confirm?email_verify_token={{.token}}&redirect_to={{.server}}&__ran__={{.randomval}}"> {{.server}}confirm-email.html </a><br>

	dbgo.Printf("%(LF)\n")
	if em.logger != nil {
		fields := []zapcore.Field{}
		fields = append(fields, zap.String("message", "email-template-fields"))
		for k, v := range mdata {
			fields = append(fields, zap.String(k, fmt.Sprintf("%s", v)))
		}
		em.logger.Info("email_sender_redirect_email_to_address", fields...)
	} else {
		dbgo.Fprintf(em.emailLogFilePtr, "%(yellow)EmailData\n")
	}
	fmt.Fprintf(em.emailLogFilePtr, "#EmailData#%s\n", dbgo.SVar(mdata))

	dbgo.Printf("%(LF)%(green) -- just before -- -- token -- ->%s<-\n", mdata["token"])
	// Used in test scripts to get the email token from the email log.  Do not change syntax.  ./test/tgo_register_and_login.sh
	dbgo.Fprintf(em.emailLogFilePtr, "\nAT: Email Data %(LF)\n\n#EmailToken#: %s\n\n", mdata["token"])

	dbgo.Printf("%(LF) %(yellow) mdata=%s\n", dbgo.SVarI(mdata))
	dbgo.Fprintf(em.emailLogFilePtr, "%(LF) mdata=%s\n", dbgo.SVarI(mdata))
	dbgo.Fprintf(em.emailLogFilePtr, "#textBody#= ---[[[%s]]]---\n", textBody)
	dbgo.Fprintf(em.emailLogFilePtr, "#htmlBody#= ---[[[->%s]]]---\n", htmlBody)

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
	var stmt string

	if UserID == "" {
		stmt = `insert into q_qr_email_log ( email_log_id, state, email_data ) values ( $1, $2, $3 )`
		_, err = em.SqlRunStmt(stmt, "...", rowID, "planned", dbgo.SVar(mdata))
	} else { // has UserID
		stmt = `insert into q_qr_email_log ( email_log_id, user_id, state, email_data ) values ( $1, $2, $3, $4 )`
		_, err = em.SqlRunStmt(stmt, "...", rowID, UserID, "planned", dbgo.SVar(mdata))
	}
	if err != nil {
		dbgo.Fprintf(os.Stderr, "%(red)%(LF)Error on insert of q_qr_email_log ->%s<- %s error:%s\n", stmt, XData(rowID, UserID, dbgo.SVar(mdata), "planned"), err)
		dbgo.Fprintf(em.emailLogFilePtr, "%(LF)Error on insert of q_qr_email_log ->%s<- %s error:%s\n", stmt, XData(rowID, UserID, dbgo.SVar(mdata), "planned"), err)
	}

	dbgo.Printf("%(LF) DbFlag=%s\n", dbgo.SVarI(em.DbFlag))
	if em.DbFlag["__email_no_send__:"+toAddress] {
		dbgo.Printf("%(LF) address %s in __email_no_send__\n", toAddress)
		dbgo.Fprintf(os.Stderr, "%(LF) address %s in __email_no_send__\n", toAddress)
		dbgo.Fprintf(em.emailLogFilePtr, "%(LF) address %s in __email_no_send__\n", toAddress)

		stmt := `
			update q_qr_email_log 
				set state = 'Dev-Skip'
				where email_log_id = $1
		`
		_, err := em.SqlRunStmt(stmt, "..", rowID, fmt.Sprintf("%s", err))
		if err != nil {
			dbgo.Fprintf(os.Stderr, "%(red)%(LF)Error on update of q_qr_email_log ->%s<- %s error:%s\n", stmt, XData(rowID), err)
			dbgo.Fprintf(em.emailLogFilePtr, "%(LF)Error on update of q_qr_email_log ->%s<- %s error:%s\n", stmt, XData(rowID), err)
		}

	} else if at, err := filelib.InPatternArray(toAddress, em.gCfg.NoEmailSendListRe); at >= 0 || err != nil {

		if err != nil {
			dbgo.Printf("%(LF)%(red) Invalid data in set of patterns for redirecting email %s, %s\n", em.gCfg.NoEmailSendListRe, err)
			dbgo.Fprintf(os.Stderr, "%(LF)Invalid data in set of patterns for redirecting email %s, %s\n", em.gCfg.NoEmailSendListRe, err)
			dbgo.Fprintf(em.emailLogFilePtr, "%(LF)Invalid data in set of patterns for redirecting email %s, %s\n", em.gCfg.NoEmailSendListRe, err)
		} else {
			dbgo.Printf("%(LF) address %s redirected to %s\n", toAddress, em.gCfg.RedirectEmailSendTo)
			dbgo.Fprintf(os.Stderr, "%(LF) address %s redirected to %s\n", toAddress, em.gCfg.RedirectEmailSendTo)
			dbgo.Fprintf(em.emailLogFilePtr, "%(LF) address %s redirected to %s\n", toAddress, em.gCfg.RedirectEmailSendTo)

			toAddress = em.gCfg.RedirectEmailSendTo

			stmt := `
				update q_qr_email_log 
					set state = 'Dev-Skip'
					where email_log_id = $1
			`
			_, err := em.SqlRunStmt(stmt, "..", rowID, fmt.Sprintf("%s", err))
			if err != nil {
				dbgo.Fprintf(os.Stderr, "%(red)%(LF)Error on update of q_qr_email_log ->%s<- %s error:%s\n", stmt, XData(rowID), err)
				dbgo.Fprintf(em.emailLogFilePtr, "%(LF)Error on update of q_qr_email_log ->%s<- %s error:%s\n", stmt, XData(rowID), err)
			}

			dbgo.Printf("\n%(green)Just before actual send of email to:%s, %(LF)\n", toAddress)
			err = em.SendEmailViaVendor(rowID, fromName, fromAddress, subject, toName, toAddress, textBody, htmlBody)
			if err != nil {
				dbgo.Printf("%(LF)%(red) Failed to send email: %s\n", err)
				dbgo.Fprintf(os.Stderr, "%(LF)Failed to send email: %s\n", err)
				dbgo.Fprintf(em.emailLogFilePtr, "%(LF)Failed to send email: %s\n", err)
			}
		}

	} else {

		dbgo.Printf("\n%(green)Just before actual send of email to:%s, %(LF)\n", toAddress)
		dbgo.Fprintf(em.emailLogFilePtr, "\n%(green)Just before actual send of email to:%s, %(LF)\n", toAddress)
		err = em.SendEmailViaVendor(rowID, fromName, fromAddress, subject, toName, toAddress, textBody, htmlBody)
		if err != nil {
			dbgo.Printf("%(LF)%(red) Failed to send email: %s\n", err)
			dbgo.Fprintf(os.Stderr, "%(LF)Failed to send email: %s\n", err)
			dbgo.Fprintf(em.emailLogFilePtr, "%(LF)Failed to send email: %s\n", err)
		}

		// logging occures in the SendEmailViaValidator ...

	}

	if err != nil {
		if em.logger != nil {
			fields := []zapcore.Field{
				zap.String("message", "Email Error"),
				zap.String("fromName", fromName),
				zap.String("fromAddress", fromAddress),
				zap.String("subject", subject),
				zap.String("toName", toName),
				zap.String("toAddress", toAddress),
				zap.String("textBody", textBody),
				zap.String("htmlBody", htmlBody),
			}
			em.logger.Error("email-did-not-send", fields...)
		} else {
			fmt.Fprintf(os.Stderr, "\n%s+============================================================================================================\n", dbgo.ColorRed)

			fmt.Fprintf(os.Stderr, "| Error -- did not send\n")
			fmt.Fprintf(os.Stderr, "| Skip of Send of Email.\n|    From Name:%s\n|    From Address:%s\n|    Subject:%s\n|    To:%s\n|    To Address:%s\n|    Text Body:--->%s<---\n     HTML Body --->%s<---\n", fromName, fromAddress, subject, toName, toAddress, textBody, htmlBody)
			fmt.Fprintf(os.Stderr, "+============================================================================================================\n%s\n", dbgo.ColorReset)
		}

		fmt.Fprintf(em.emailLogFilePtr, "\n%s+============================================================================================================\n", "")
		fmt.Fprintf(em.emailLogFilePtr, "| Skip of Send of Email.\n|   From Name:%s\n|    From Address:%s\n|    Subject:%s\n|    To:%s\n|    To Address:%s\n|    Text Body:--->%s<---\n     HTML Body --->%s<---\n", fromName, fromAddress, subject, toName, toAddress, textBody, htmlBody)
		fmt.Fprintf(em.emailLogFilePtr, "+============================================================================================================\n%s\n", "")

	} else if em.DbFlag["__email_no_send__:"+toAddress] || em.DbFlag["dump-email"] {
		if em.logger != nil {
			fields := []zapcore.Field{
				zap.String("message", "Email Success"),
				zap.Bool("mapped_addres_to_not_send_to", em.DbFlag["__email_no_send__:"+toAddress]),
				zap.Bool("dump_email_flag_set", em.DbFlag["dump-email"]),
				zap.String("fromName", fromName),
				zap.String("fromAddress", fromAddress),
				zap.String("subject", subject),
				zap.String("toName", toName),
				zap.String("toAddress", toAddress),
				zap.String("textBody", textBody),
				zap.String("htmlBody", htmlBody),
			}
			em.logger.Info("email-ignored-due-to-address-sent", fields...)
		} else {
			fmt.Fprintf(os.Stderr, "\n%s+============================================================================================================\n", dbgo.ColorCyan)

			fmt.Fprintf(os.Stderr, "| DbFlag Set 'dump-email' or '__email_no_send__:%s'\n", toAddress)
			fmt.Fprintf(os.Stderr, "| Skip of Send of Email.\n|    From Name:%s\n|    From Address:%s\n|    Subject:%s\n|    To:%s\n|    To Address:%s\n|    Text Body:--->%s<---\n     HTML Body --->%s<---\n", fromName, fromAddress, subject, toName, toAddress, textBody, htmlBody)
			fmt.Fprintf(os.Stderr, "+============================================================================================================\n%s\n", dbgo.ColorReset)
		}

		fmt.Fprintf(em.emailLogFilePtr, "\n%s+============================================================================================================\n", "")
		fmt.Fprintf(em.emailLogFilePtr, "| Skip of Send of Email.\n|   From Name:%s\n|    From Address:%s\n|    Subject:%s\n|    To:%s\n|    To Address:%s\n|    Text Body:--->%s<---\n     HTML Body --->%s<---\n", fromName, fromAddress, subject, toName, toAddress, textBody, htmlBody)
		fmt.Fprintf(em.emailLogFilePtr, "+============================================================================================================\n%s\n", "")

	} else {
		if em.logger != nil {
			fields := []zapcore.Field{
				zap.String("message", "Email Success"),
				zap.String("fromName", fromName),
				zap.String("fromAddress", fromAddress),
				zap.String("subject", subject),
				zap.String("toName", toName),
				zap.String("toAddress", toAddress),
				zap.String("textBody", textBody),
				zap.String("htmlBody", htmlBody),
			}
			em.logger.Info("email-sent", fields...)
		} else {
			fmt.Fprintf(os.Stderr, "\n%s+============================================================================================================\n", dbgo.ColorGreen)
			fmt.Fprintf(os.Stderr, "| Send of Email.\n|    From Name:%s\n|    From Address:%s\n|    Subject:%s\n|    To:%s\n|    To Address:%s\n|    Text Body:--->%s<---\n     HTML Body --->%s<---\n", fromName, fromAddress, subject, toName, toAddress, textBody, htmlBody)
			fmt.Fprintf(os.Stderr, "+============================================================================================================\n%s\n", dbgo.ColorReset)
		}
	}

	return
}

// SqlRunStmt will run a single statemt and return the data as an array of maps
func (em GenericEmailSender) SqlRunStmt(stmt string, encPat string, data ...interface{}) (rv []map[string]interface{}, err error) {
	if em.conn == nil {
		dbgo.Fprintf(em.emailLogFilePtr, "Connection is nil -- no database connected -- :%(LF)\n")
		return
	}
	fmt.Fprintf(os.Stderr, "Database Stmt ->%s<- data ->%s<-\n", stmt, dbgo.SVar(data))
	fmt.Fprintf(em.emailLogFilePtr, "Database Stmt ->%s<- data ->%s<-\n", stmt, dbgo.SVar(data))

	err = pgxscan.Select(em.ctx, em.conn, &rv, stmt, data...)
	if err != nil {
		em.md.AddCounter("email_sender_sql_error", 1)
		if em.logger != nil {
			fields := []zapcore.Field{
				zap.String("message", "Email SQL Error"),
				zap.Error(err),
				zap.String("stmt", stmt),
				zap.String("bind_vars", fmt.Sprintf("%s", data)),
				zap.String("location", dbgo.LF(-2)),
			}
			em.logger.Info("email-sql-error", fields...)
		}
		fmt.Fprintf(em.emailLogFilePtr, "Sql error: %s stmt: ->%s<- params: %s", err, stmt, XData(data))
		return nil, fmt.Errorf("Sql error: %s stmt: ->%s<- params: %s", err, stmt, XData(data))
	}

	return nil, nil
}

/* vim: set noai ts=4 sw=4: */
