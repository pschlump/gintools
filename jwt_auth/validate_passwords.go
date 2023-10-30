package jwt_auth

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

// Check that you have correct passwords(encryption keys) for running the server.

import (
	"fmt"
	"os"

	"github.com/pschlump/dbgo"
	"github.com/pschlump/gintools/log_enc"
	"github.com/pschlump/json"
)

/*
	jwt_auth.SetupNewInstall()

if err := jwt_auth.ValidatePasswords(); err != nil {

-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
create table if not exists q_qr_validate_startup (

	once_id								int unique primary key, -- only one row in table ever, no generation of PKs.
	validation_value_hmac 				bytea not null,
	validation_value_enc 				bytea not null

);

--
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
create or replace function q_auth_v1_setup_startup_one_time ( p_hmac_password varchar, p_userdata_password varchar )

	returns text
	as $$

DECLARE

	l_data					text;
	l_fail					bool;

BEGIN

	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	insert into t_output ( msg ) values ( 'function ->q_auth_v1_setup_startup_one_time<- m4___file__ m4___line__' );

	begin
		insert into q_qr_validate_startup ( once_id, validation_value_hmac, validation_value_enc ) values
			( 1
		 	, q_auth_v1_hmac_encode ( 'test@test.com', p_hmac_password )
		    , pgp_sym_encrypt('test@test.com', p_userdata_password)
			);

	exception
		when others then

			l_fail = true;
			l_data = '{"status":"error","msg":"Not initialized properly - incorrect passwrods","code":"2004","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Not initialized properly - incorrect passwords', '2005', 'File:m4___file__ Line No:m4___line__');
	end;

	if not l_fail then

		l_data = '{"status":"success"'
			||'}';

	end if;

	RETURN l_data;

END;
$$ LANGUAGE plpgsql;

--
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
create or replace function q_auth_v1_validate_startup_passwords ( p_hmac_password varchar, p_userdata_password varchar )

	returns text
	as $$

DECLARE

	l_data					text;
	l_fail					bool;
	l_debug_on 				bool;
	l_id					uuid;
	l_junk					text;

BEGIN

	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_auth_v1_validate_startup_passwords<- m4___file__ m4___line__' );
	end if;

	begin
		select 'found'
			into l_junk
			from q_qr_validate_startup
			where  once_id = 1
			 and validation_value_hmac = q_auth_v1_hmac_encode ( 'test@test.com', p_hmac_password )
			 and pgp_sym_decrypt(validation_value_enc, p_userdata_password) = 'test@test.com'
			;
		if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"Not configured properly - incorrect passwrods","code":"2005","location":"m4___file__ m4___line__"}';
		end if;
	exception
		when others then
			l_fail = true;
			l_data = '{"status":"error","msg":"Not configured properly - incorrect passwrods","code":"2007","location":"m4___file__ m4___line__"}';
	end;


	if not l_fail then

		l_data = '{"status":"success"'
			||'}';

	end if;

	RETURN l_data;

END;
$$ LANGUAGE plpgsql;

delete from q_qr_validate_startup ;

select q_auth_v1_setup_startup_one_time ( 'bob', 'bob' );
select q_auth_v1_validate_startup_passwords ( 'bb', 'ob' );

delete from q_qr_validate_startup ;
*/
type SQLStatusType struct {
	Status  string `json:"status"`
	LogUUID string `json:"LogUUID"`
}

// SetupNewInstall should be called once to setup the database using the encryption keys.  This function will call
// "q_auth_v1_setup_startup_one_time" with the keys and create a single row that is encrypted.   The row is used
// to validate that you do not start an applicaiton with an invalid set of keys.  Running with incorrect keys
// will result in a split-brain database.
func SetupNewInstall() (err error) {

	var resp SQLStatusType

	stmt := "q_auth_v1_setup_startup_one_time ( $1, $2 )"
	dbgo.Fprintf(logFilePtr, "In handler at %(LF): %s\n", stmt)
	rv, e0 := CallDatabaseJSONFunction(nil, stmt, "..", aCfg.EncryptionPassword, aCfg.UserdataPassword)
	if e0 != nil {
		err = e0
		return
	}
	dbgo.Fprintf(logFilePtr, "%(LF): rv=%s\n", rv)
	err = json.Unmarshal([]byte(rv), &resp)
	if resp.Status != "success" {
		resp.LogUUID = GenUUID()
		log_enc.LogStoredProcError(nil, stmt, ".", SVar(resp))
		return
	}

	return nil
}

// ValidatePasswords is the 2nd 1/2 of the pair - this is used to validate that the encryption keys are
// correct.  It should be called on startup of a server and checks that you have the correct keys at that
// time.
func ValidatePasswords() (err error) {

	var resp SQLStatusType

	stmt := "q_auth_v1_validate_startup_passwords ( $1, $2 )"
	dbgo.Fprintf(logFilePtr, "In handler at %(LF): %s\n", stmt)
	dbgo.Fprintf(os.Stderr, "%(cyan)In handler at %(LF): %s\n", stmt)
	rv, e0 := CallDatabaseJSONFunction(nil, stmt, "..", aCfg.EncryptionPassword, aCfg.UserdataPassword)
	if e0 != nil {
		err = e0
		return
	}
	dbgo.Fprintf(logFilePtr, "%(LF): rv=%s\n", rv)
	err = json.Unmarshal([]byte(rv), &resp)
	dbgo.Printf("%(red)%s\n", dbgo.SVarI(resp))
	if resp.Status != "success" {
		resp.LogUUID = GenUUID()
		log_enc.LogStoredProcError(nil, stmt, ".", SVar(resp))
		err = fmt.Errorf("Falied to initialize properly - bad passwords")
		return
	}

	return nil
}

/* vim: set noai ts=4 sw=4: */
