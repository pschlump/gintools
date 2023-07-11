package table_rest

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"os"
	"testing"

	"github.com/pschlump/dbgo"
)

var setupTestRun = false

func SetupTest() {
	if setupTestRun {
		return
	}
	setupTestRun = true
	ConnectToDb()
}

func TestCrudSql(t *testing.T) {

	// func SetupCrud(f *os.File, d map[string]bool) {
	db := make(map[string]bool)
	db["crud-base-sql"] = true

	SetupTest()
	// ConnectToDb()
	// defer DisConnectToDb()

	SetupSQL(os.Stderr)

	data := make([]interface{}, 0, 1)

	// Create Table - start table to test with.
	stmt := "drop table if exists crud_test"
	res, err := conn.Exec(ctx, stmt)
	if err != nil {
		// LogSQLError(www, req, stmt, err)
		logQueries(stmt, err, data, 0)
	}
	_ = res

	stmt = "create table if not exists crud_test ( n int, m int )"
	res, err = conn.Exec(ctx, stmt)
	if err != nil {
		// LogSQLError(www, req, stmt, err)
		logQueries(stmt, err, data, 0)
	}
	_ = res

	// func SQLInsert(stmt string, data ...interface{}) (err error) {
	stmt = "insert into crud_test ( m, n ) values ( $1, $2 )"
	err = SQLInsert(stmt, 1, 2)

	var mm int
	stmt = "select n from crud_test where m = $1"
	// func SQLQuery(stmt string, data ...interface{}) (resultSet pgx.Rows, err error) {
	rs, err := SQLQuery(stmt, 1)
	if err != nil {
		t.Errorf("Error on 1st select:%s", err)
		logQueries(stmt, err, []interface{}{1}, 0)
	} else {
		for ii := 0; rs.Next(); ii++ {
			err = rs.Scan(&mm)
			if err != nil {
				t.Errorf("Error on 1st scan:%s", err)
			}

			if ii > 0 {
				t.Errorf("Error on 1st scan - too many rows")
				break
			}
			if mm != 2 {
				t.Errorf("Error expecte 2 got %d", mm)
			}
		}
	}

	// func SQLSelectRow(stmt string, data ...interface{}) (aRow pgx.Row) {
	rw := SQLSelectRow(stmt, 1)
	mm = 0
	err = rw.Scan(&mm)
	if err != nil {
		t.Errorf("Error on 1st scan:%s", err)
	}
	if mm != 2 {
		t.Errorf("Error expecte 2 got %d", mm)
	}

	// func SQLUpdate(stmt string, data ...interface{}) (nr int, err error) {
	stmt = "update crud_test set m = $1 where m = $2"
	nr, err := SQLUpdate(stmt, 5, 1)
	if err != nil {
		t.Errorf("Error on 1st update:%s", err)
	}
	if nr != 1 {
		t.Errorf("Error on 1st update: invalid number of rows updated")
	}

	// -------------------------------------------------------------------------------------------------
	// Create Table - start table to test with.
	stmt = "drop table if exists crud_test2"
	res, err = conn.Exec(ctx, stmt)
	if err != nil {
		// LogSQLError(www, req, stmt, err)
		logQueries(stmt, err, data, 0)
	}
	_ = res

	stmt = "create table if not exists crud_test2 ( n serial not null primary key, m int )"
	res, err = conn.Exec(ctx, stmt)
	if err != nil {
		// LogSQLError(www, req, stmt, err)
		logQueries(stmt, err, data, 0)
	}
	_ = res

	stmt = "insert into crud_test2 ( m ) values ( $1 ) RETURNING n"
	// func SQLInsertId(stmt string, data ...interface{}) (id int64, err error) {
	id, err := SQLInsertId(stmt, 2)
	if db240 {
		dbgo.Printf("%(cyan)id = %d\n", id)
	}
	if err != nil {
		t.Errorf("Error on SQLInsertId %s", err)
	}
	if id != 1 {
		t.Errorf("Error on SQLInsertId id shoudl be 1, got %d\n", id)
	}

	// func SQLDelete(stmt string, data ...interface{}) (err error) {
	stmt = "delete from crud_test2 where n = $1"
	err = SQLDelete(stmt, 1)
	if err != nil {
		t.Errorf("Error on SQLDelete %s", err)
	}

	// func SelectInt(stmt string, data ...interface{}) (n int) {
	stmt = "select m from crud_test"
	ww := SelectInt(stmt)
	if ww != 5 {
		t.Errorf("Error expecte 5 got %d", ww)
	}

	// OPTIONAL! Drop Table
	// func RunStmt(stmt string, data ...interface{}) (err error) {
	stmt = "drop table if exists crud_test"
	err = RunStmt(stmt)
	if err != nil {
		t.Errorf("Error on SQLDelete %s", err)
	}

}

var db240 = false

/* vim: set noai ts=4 sw=4: */
