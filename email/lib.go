package email

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"fmt"
	"os"

	"github.com/pschlump/dbgo"
	"github.com/pschlump/scany/pgxscan"
	"github.com/pschlump/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// XData convers a list of parameters to a JSON data showing what the list contains.  This is returned as a string.
func XData(x ...interface{}) (rv string) {
	rv = dbgo.SVar(x)
	return
}

// GenUUID generates a UUID and returns it.
func GenUUID() string {
	newUUID, _ := uuid.NewV4() // Intentionally ignore errors - function will never return any.
	return newUUID.String()
}

// SqlRunStmt will run a single statemt and return the data as an array of maps
func (em SendgridEmailSender) SqlRunStmt(stmt string, encPat string, data ...interface{}) (rv []map[string]interface{}, err error) {
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
