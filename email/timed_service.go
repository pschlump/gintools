package email

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/pschlump/dbgo"
	"github.com/pschlump/scany/pgxscan"
)

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

// setup - create a tie in to a d.b. table that has email to send.

// timedSender - a call to this from a go-routine that checkes the table - on a timed basis (polled) - and sends email.

/*
CREATE TABLE if not exists q_qr_email_send (
	  email_send_id	uuid DEFAULT uuid_generate_v4() not null primary key
	, user_id			uuid					-- if available
	, state				text default 'pending' not null check ( state in ( 'pending', 'sent', 'error' ) )
	, template_name		text not null			-- "./tmpl/Name.tmpl"
	, email_data		text not null
	, error_info		text
	, updated 			timestamp
	, created 			timestamp default current_timestamp not null
);
*/

// 1. Set Directory to Pull Template From
// 1. Periodic pull of data / template name
// 2. Render tempalte
// 3. send

// timedDispatch waits for a "kick" or a timeout and calls QrGenerate forever.

func TimedDispatch(em *GenericEmailSender) {
	for {
		select {
		case <-em.ch:
			dbgo.Printf("%(blue)Chanel Activated\n")
			em.TemplateAndSend()

		case <-em.timeout:
			ts := time.Now().Format("2006-01-02 15:04:05")
			dbgo.Printf("%(blue)Clock-Ping At %s / Email Fetch Template and Send%(reset)\n", ts)
			em.TemplateAndSend()
		}
	}
}

// GetCurTics returns the number of times that a timeout has saved the data.
func (em *GenericEmailSender) GetCurTick() int {
	return em.nTicks
}

func (em *GenericEmailSender) initializeTimedSender() {

	// ------------------------------------------------------------------------------
	// Setup live monitor (timed insert)
	// ------------------------------------------------------------------------------
	go TimedDispatch(em)

	// ticker on channel - send once a minute
	go func(n int) {
		for {
			// dbgo.Printf("%(red)-------------------------------------------------------------------------------------------------------------------------------------------- %(cyan)Email - Time in Seconss %(LF) = %d\n", n)
			time.Sleep(time.Duration(n) * time.Second)
			em.timeout <- "timeout"
			em.nTicks++
		}
	}(em.gCfg.EmailTickerSeconds)
}

func (em *GenericEmailSender) TemplateAndSend() {
	em.md.AddCounter("gcail_sender_timed_check_for_email", 1)

	stmt := `
		select email_send_id::text as "email_send_id",
			user_id::text as "user_id",
			state,
			template_name,
			email_data
		from q_qr_email_send 
		where state = 'pending' 
		order by created
	`

	type ClientDataType struct {
		EmailSendId  string `json:"email_send_id" data:"email_send_id"`
		UserId       string `json:"user_id" data:"user_id"`
		State        string `json:"state" data:"state"`
		TemplateName string `json:"template_name" data:"template_name"`
		EmailData    string `json:"email_data" data:"email_data"`
	}

	dbgo.Fprintf(em.emailLogFilePtr, "Running %s at:%(LF)\n", stmt)

	var v2 []ClientDataType
	start := time.Now()
	err := pgxscan.Select(em.ctx, em.conn, &v2, stmt)
	elapsed := time.Since(start) // elapsed time.Duration
	if err != nil {
		dbgo.Fprintf(em.emailLogFilePtr, "Error: %s duration %s stmt %s at:%(LF)\n", err, elapsed, stmt)
		return
	}
	for _, vv := range v2 {
		mdata := make(map[string]interface{})
		err := json.Unmarshal([]byte(vv.EmailData), &mdata)
		if err != nil {
			dbgo.Fprintf(em.emailLogFilePtr, "Error Parsing JSON data: %s data %s rowid %s at:%(LF)\n", err, vv.EmailData, vv.EmailSendId)
			continue
		}

		err = em.SendEmailMapdata(vv.TemplateName, mdata)
		if err != nil {
			dbgo.Fprintf(em.emailLogFilePtr, "Error Sending Email: %s data %s rowid %s at:%(LF)\n", err, vv.EmailData, vv.EmailSendId)
			stmt = `update q_qr_email_send set state = 'error', error_info = $2 where email_send_id = $1`
			_, err := em.SqlRunStmt(stmt, "..", vv.EmailSendId, fmt.Sprintf("%s", err))
			if err != nil {
				dbgo.Fprintf(em.emailLogFilePtr, "Error: %s duration %s stmt %s rowid %s at:%(LF)\n", err, elapsed, stmt, vv.EmailSendId)
				continue
			}
			continue
		}

		stmt = `update q_qr_email_send set state = 'sent' where email_send_id = $1`
		_, err = em.SqlRunStmt(stmt, "..", vv.EmailSendId)
		if err != nil {
			dbgo.Fprintf(em.emailLogFilePtr, "Error: %s duration %s stmt %s rowid %s at:%(LF)\n", err, elapsed, stmt, vv.EmailSendId)
		}
	}
}

/* vim: set noai ts=4 sw=4: */
