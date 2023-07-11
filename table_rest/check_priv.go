package table_rest

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/gintools/log_enc"
	"github.com/pschlump/scany/pgxscan"
)

func HasRolePriv(c *gin.Context, requiredAuthPrivilages []string) bool {
	if gCfg.UseRolePriv == "yes" {
		if len(requiredAuthPrivilages) == 0 { // if nothing is required, then return true
			return true
		}

		if found1, user_id := GetVar("__user_id__", c); found1 {
			// Are the "privs" loaded with the user on long?   Can we just check
			// that the user has this once.
			for _, aPriv := range requiredAuthPrivilages {
				if !CheckPriv(c, user_id, aPriv) {
					log_enc.LogSQLPrivelage(c, aPriv, ".", user_id) // Don't need to encyprt user_id
					c.JSON(http.StatusUnauthorized, gin.H{          // 401
						"status": "error",
						"msg":    fmt.Sprintf("Missing privage for this api end point [%s] [%s]", c.Request.RequestURI, aPriv),
					})
					return false
				}
			}
		}
	}
	return true
}

// CheckPriv returns true if the specified user_id contains the requested privilage
func CheckPriv(c *gin.Context, user_id, needs_priv string) (rv bool) {
	type SQLStringType struct {
		X string
	}

	// query to pull out if this user has the specified privilage.
	stmt := `
		select 'found' as "X"
		where exists ( 
			select 'found' as "X"
			from q_qr_user_to_priv as t1
			where t1.user_id = $1
			  and t1.priv_name = $2
		)
	`
	var v2 []*SQLStringType
	err := pgxscan.Select(ctx, conn, &v2, stmt, user_id, needs_priv)
	if err != nil {
		log_enc.LogSQLError(c, stmt, err, log_enc.EncryptLogData("..", user_id, needs_priv))
		return false
	}
	if len(v2) > 0 {
		dbgo.Fprintf(logFilePtr, "Call Returns: %s at:%(LF)\n", v2[0].X)
		return v2[0].X == "found"
	}
	return true
}

/* vim: set noai ts=4 sw=4: */
