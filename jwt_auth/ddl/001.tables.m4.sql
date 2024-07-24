
-- Copyright (C) Philip Schlump, 2008-2023.
-- MIT Licensed.  See LICENSE.mit file.
-- BSD Licensed.  See LICENSE.bsd file.

-- xyzzyPartialReg
-- xyzzyOnSuccessfulX

-- xyzzyError100 - never true iff.
-- xyzzy-Fix-Error-Message-to-be-clear

-- FUNCTION q_auth_v1_login ( p_email varchar, p_pw varchar, p_am_i_known varchar, p_hmac_password varchar, p_userdata_password varchar, p_fingerprint varchar, p_sc_id varchar, p_hash_of_headers varchar, p_xsrf_id varchar ) RETURNS text

-- stmt = "q_auth_v1_validate_2fa_token ( $1, $2, $3, $4, $5 )"
-- FUNCTION q_auth_v1_validate_2fa_token ( p_email varchar, p_tmp_token varchar, p_2fa_secret varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text

m4_include(setup.m4)
m4_include(ver.m4)
m4_do_not_edit()

m4_comment([[[


-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------


select q_auth_v1_xsrf_setup ( '5e0026a0-e04b-4e45-67d8-9ff7f37f7d66','http://localhost:8080/','my long secret password','user info password' );

]]])




m4_define([[[m4_counter]]],[[[2000]]])m4_dnl
m4_define([[[m4_count]]],[[[m4_define([[[m4_counter]]],m4_eval(m4_counter+1))m4_counter]]])m4_dnl









-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS q_qr_role_name_application_url (
	id 					uuid DEFAULT uuid_generate_v4() not null primary key,
	role_name			text,
	application_url		text,
	updated 			timestamp,
	created 			timestamp default current_timestamp not null
);
comment on table q_qr_role_name_application_url is 'Role Creation Token to Applicaiton URL - Copyright (C) Philip Schlump, LLC, 2022. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';

create unique index if not exists q_qr_role_name_application_url_u1 on q_qr_role_name_application_url ( role_name );

m4_updTrig(q_qr_role_name_application_url)






-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- General purpose output and debuging table.
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE if not exists t_output (
	  seq 		serial not null primary key
	, msg 		text
	, created 	timestamp default current_timestamp not null
);
comment on table t_output is 'Temporary output for debuging - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';

-- used for cleanup of table - Delete everything that is
-- more than 1 hour old?
create index if not exists t_output_p1 on t_output ( created );


-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- General purpose key/value store
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE if not exists t_key_value (
	id			uuid DEFAULT uuid_generate_v4() not null primary key,
	key			text not null,	-- the key.
	data		jsonb,			-- the data.
	updated 	timestamp, 									 						-- Project update timestamp (YYYYMMDDHHMMSS timestamp).
	created 	timestamp default current_timestamp not null 						-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);
comment on table t_key_value is 'Key value store so we do not need redis running - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';

m4_updTrig(t_key_value)

create index if not exists t_key_value_h1 on t_key_value using hash ( key );
create unique index if not exists t_key_value_u1 on t_key_value ( key );


DO $$
BEGIN
	BEGIN
		-- ALTER TABLE t_key_value drop CONSTRAINT if exists t_key_value_uniq1 ;
		ALTER TABLE t_key_value
			ADD CONSTRAINT t_key_value_uniq1
			UNIQUE ( key )
			;
	EXCEPTION
		WHEN duplicate_table THEN	-- postgres raises duplicate_table at surprising times. Ex.: for UNIQUE constraints.
		WHEN duplicate_object THEN
			RAISE NOTICE 'Table constraint t_key_value already exists';
	END;
END $$;




-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- id.json - tracking table to see if user has been seen before on this device.
-- AT: File: /Users/philip/go/src/github.com/pschlump/gintools/jwt_auth/auth.go LineNo:356
-- 		email ->admin2@write-it-right.com<- pw ->abcdefghij<-
-- 		AmIKnown ->141cd3a8-321d-40e0-6d0b-352202e7dbd6<- XrefID ->63ddad38-66df-4ca2-be0f-2f6e8f40d110<-
-- 		hashOfHeadrs ->c0913a7535439615871db5a171fa7293e8f937102adb09c7d5341e3b33276e2a<-
-- 		FPData ->b11ba821e996ecc6b9dd1b0ca7fe139a<-
-- 		ScID ->06ee6e25-3158-4f19-9335-38c9b3822389<-
--------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
drop table if exists q_qr_device_track;
drop table if exists q_qr_manifest_version;
alter table if exists q_qr_manifest_version rename to q_qr_device_track;

-- alter table q_qr_device_track add column if not exists   user_id			uuid					;
-- alter table q_qr_device_track add column if not exists   etag_seen			text					;
-- alter table q_qr_device_track add column if not exists   n_seen 			int default 0 not null  ;
-- alter table q_qr_device_track add column if not exists   n_login 			int default 0 not null  ;
-- alter table q_qr_device_track add column if not exists   n_2fa_token 		int default 0 not null  ;
-- alter table q_qr_device_track add column if not exists   expires 			timestamp not null		;
-- alter table q_qr_device_track add column if not exists   fingerprint_data	text not null			;
-- alter table q_qr_device_track add column if not exists   sc_id				text 					;
-- alter table q_qr_device_track add column if not exists   header_hash		text 					;
-- alter table q_qr_device_track add column if not exists   am_i_known		text 					;
-- alter table q_qr_device_track add column if not exists   valid_user_id		uuid not null			;
-- alter table q_qr_device_track add column if not exists   state_data		text not null			;
-- alter table q_qr_device_track add column if not exists   updated 			timestamp				;
-- alter table q_qr_device_track add column if not exists   created 			timestamp default current_timestamp not null;

CREATE TABLE if not exists q_qr_device_track (
	  id				uuid DEFAULT uuid_generate_v4() not null primary key
	, user_id			uuid					-- a user specified ID to join to Q_QR_USERS.user_id
	, etag_seen			text					-- etag for id.json
    , n_seen 			int default 0 not null
    , n_login 			int default 0 not null
    , n_2fa_token 		int default 0 not null
	, expires 			timestamp not null
	, fingerprint_data	text    				-- FPDdata			fp_
	, sc_id				text 					-- ScID				scid
	, header_hash		text 					-- hashOfHeaders	hoh
	, am_i_known		text 					-- AmIKnown
	, valid_user_id		uuid 					-- Valid  User that has successfuly loged in on this device.
	, state_data		text
	, updated 			timestamp
	, created 			timestamp default current_timestamp not null
);
comment on table q_qr_device_track is 'Valid vesion of id.json, and device tracking - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';

create index if not exists q_qr_device_track_p1 on q_qr_device_track using hash ( etag_seen );
create index if not exists q_qr_device_track_p2 on q_qr_device_track ( created, user_id );
create index if not exists q_qr_device_track_p4 on q_qr_device_track ( expires );
create index if not exists q_qr_device_track_p5 on q_qr_device_track ( fingerprint_data );
create index if not exists q_qr_device_track_p6 on q_qr_device_track ( valid_user_id );
create index if not exists q_qr_device_track_p7 on q_qr_device_track ( fingerprint_data, valid_user_id );

m4_updTrig(q_qr_device_track)






DROP FUNCTION q_qr_device_track_expires();
DROP TRIGGER if exists q_qr_manifest_version_expire_trig
	ON "q_qr_device_track"
	;




-- trigger to set expires
CREATE OR REPLACE FUNCTION q_qr_device_track_expires() RETURNS trigger
AS $$
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	NEW.expires := current_timestamp + interval '3660 days';
	RETURN NEW;
END
$$ LANGUAGE 'plpgsql';


DROP TRIGGER if exists q_qr_device_track_expire_trig
	ON "q_qr_device_track"
	;


CREATE TRIGGER q_qr_device_track_expire_trig
	BEFORE insert or update ON "q_qr_device_track"
	FOR EACH ROW
	EXECUTE PROCEDURE q_qr_device_track_expires();




-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
drop table if exists q_qr_valid_xsrf_id ;

CREATE TABLE if not exists q_qr_valid_xsrf_id (
	  id				uuid DEFAULT uuid_generate_v4() not null primary key
	, device_track_id	uuid					-- a FK to q_qr_device_track.id
	, user_id			uuid					-- a user specified ID to join to Q_QR_USERS.user_id
	, xsrf_id			uuid not null
	, updated 			timestamp
	, created 			timestamp default current_timestamp not null
);
comment on table q_qr_valid_xsrf_id is 'Valid xref_id values - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';

m4_updTrig(q_qr_valid_xsrf_id)

create index if not exists q_qr_valid_xsrf_id_h1 on q_qr_valid_xsrf_id using hash ( xsrf_id );





-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- function set_user_has_loged_in ( fingerprint_data varchar, state_of_login varchar, p_user_id uuid )
-- state_of_login == 'un/pw' -- they have
-- state_of_login == '2fa-valid' -- they have done the 2fa - so this is a valid row

CREATE TABLE if not exists q_qr_308_redirect (
	  id					uuid not null primary key		-- ID on URL - to validate
	, valid_user_id			uuid			-- Valid  User that has successfuly loged in on this device.
);
comment on table q_qr_308_redirect is 'Valid login - unique ID - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';

create index if not exists q_qr_308_rediret_p1 on q_qr_308_redirect ( valid_user_id );





-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE if not exists q_qr_valid_referer (
	referer			text
);
comment on table q_qr_valid_referer is 'Valid referer headers - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';

create unique index if not exists  q_qr_valid_referer_u1 on q_qr_valid_referer ( referer );





-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION q_get_config ( p_name varchar ) RETURNS text
AS $$
DECLARE
	l_data text;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	select value into l_data from q_qr_config where name = p_name;
	if not found then
		l_data = '';
	end if;
	RETURN l_data;
END;
$$ LANGUAGE plpgsql;


-- drop function q_get_config_bool ( p_name varchar );

CREATE OR REPLACE FUNCTION q_get_config_bool ( p_name varchar ) RETURNS bool
AS $$
DECLARE
	l_data bool;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	select b_value into l_data from q_qr_config where name = p_name;
	if not found then
		l_data = false;
	end if;
	RETURN l_data;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION q_get_config_bool_dflt ( p_name varchar, p_dflt bool ) RETURNS bool
AS $$
DECLARE
	l_data bool;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	select b_value into l_data from q_qr_config where name = p_name;
	if not found then
		l_data = p_dflt;
	end if;
	RETURN l_data;
END;
$$ LANGUAGE plpgsql;


--	q_get_config_bigint_dflt ( 'matcine_no', 0 );

CREATE OR REPLACE FUNCTION q_get_config_bigint_dflt ( p_name varchar, p_dflt bigint ) RETURNS bigint
AS $$
DECLARE
	l_data bigint;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	select value::bigint into l_data from q_qr_config where name = p_name;
	if not found then
		l_data = p_dflt;
	end if;
	RETURN l_data;
END;
$$ LANGUAGE plpgsql;







-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION q_auth_v1_validate_fingerprint_data ( p_fingerprint_data varchar, p_state varchar, p_user_id uuid, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_debug_on 				bool;
	l_state					text;
	l_id					uuid;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );
	l_data = '{"status":"error"}';

	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_auth_v1_validate_fingerprint_data<- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '		p_fingerprint_data ->'||coalesce(to_json(p_fingerprint_data)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '		p_state ->'||coalesce(to_json(p_state)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '		p_user_id ->'||coalesce(to_json(p_user_id)::text,'---null---')||'<-');
	end if;

	select id, state_data
		into l_id, l_state
		from q_qr_device_track
		where fingerprint_data = p_fingerprint_data
		  and valid_user_id = p_user_id
		;

	if not found then
		insert into q_qr_device_track ( fingerprint_data, state_data ) values ( p_fingerprint_data, 'unknown' );
		l_state = 'unknown';
		l_fail = true;
		l_data = '{"status":"failed"'
			||'}';
	else
		if l_state = 'un/pw' then
			if p_state = '2fa/valid' then
				update q_qr_device_track
					set state_date = p_state
					where id = l_id
					;
			else
				l_fail = true;
				l_data = '{"status":"failed"'
					||'}';
			end if;
		elsif l_state = '2fa/valid' then
			l_fail = false;					-- successful return
		elsif l_state = 'unknown' then
			if p_state = '2fa/valid' then
				update q_qr_device_track
					set state_date = p_state
					where id = l_id
					;
			elsif p_state = 'un/pw' then
				update q_qr_device_track
					set state_date = p_state
					where id = l_id
					;
			else
				l_fail = true;
				l_data = '{"status":"failed"'
					||'}';
			end if;
		else
			l_fail = true;
			l_data = '{"status":"failed"'
				||'}';
		end if;
	end if;

	if not l_fail then

		l_data = '{"status":"success"'
			||'}';

	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;





-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- remove all other fingerpirnts that are from this device but not from this user.
-- Not used yet
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- xyzzy8 - fingerprint
CREATE OR REPLACE FUNCTION q_auth_v1_login_cleanup_fingerprint_data ( p_fingerprint_data varchar, p_state varchar, p_user_id uuid, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_debug_on 				bool;
	l_state					text;
	l_id					uuid;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );
	l_data = '{"status":"error"}';

	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_auth_v1_login_cleanup_fingerprint_data<- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '		p_fingerprint_data ->'||coalesce(to_json(p_fingerprint_data)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '		p_state ->'||coalesce(to_json(p_state)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '		p_user_id ->'||coalesce(to_json(p_user_id)::text,'---null---')||'<-');
	end if;

	if p_state = 'un/pw' or p_state = '2fa/valid' then
		delete from q_qr_device_track
			where fingerprint_data = p_fingerprint_data
			  and valid_user_id <> p_user_id
			;
	end if;

	if not l_fail then

		l_data = '{"status":"success"'
			||'}';

	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;






-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- This checks that a valid xsrf_id token is passed during login.
--
-- stmt := "q_auth_v1_validate_xsrf_id ( $1, $2, $3 )"
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION q_auth_v1_validate_xsrf_id ( p_id uuid, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_debug_on 				bool;
	l_junk 					int;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );
	l_data = '{"status":"error"}';

	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_auth_v1_validate_xsrf_id<- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '		p_id ->'||coalesce(to_json(p_id)::text,'---null---')||'<-');
	end if;

	select 1 into l_junk
		from q_qr_valid_xsrf_id
		where xsrf_id = p_id
		;

	if not found then
		insert into q_qr_valid_xsrf_id ( xsrf_id ) values ( p_id );
		-- l_fail = true;
		-- l_data = '{"status":"error","msg":"Invalid Application - Please Re-Install","code":"m4_count()","location":"m4___file__ m4___line__"}';
	end if;

	if not l_fail then

		l_data = '{"status":"success"'
			||'}';

	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;

-- select q_auth_v1_validate_xsrf_id ( '9ca5c33f-c6b2-4a38-aa99-470135aa81a4'::uuid, 'a', 'b' );
-- select q_auth_v1_validate_xsrf_id ( '9ca5c33f-c6b2-4a38-aa99-470135aa81a0'::uuid, 'a', 'b' );









-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Create a valid xsrf_id token that is passed back during the login process - and validated at login.
-- Note: this checks the referer that is used.  It must be in the q_qr_valid_refer table.
--
--	stmt := "q_auth_v1_xsrf_setup ( $1, $2, $3, $4 )"
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION q_auth_v1_xsrf_setup ( p_id uuid, p_ref varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_debug_on 				bool;
	l_junk 					int;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );
	l_data = '{"status":"error"}';

	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_auth_v1_xsrf_setup<- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '		p_id ->'||coalesce(to_json(p_id)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '		p_ref ->'||coalesce(to_json(p_ref)::text,'---null---')||'<-');
	end if;

	select 1 into l_junk
		from q_qr_valid_referer
		where referer = p_ref
		;

	if found then
		select 1
			into l_junk
			from q_qr_valid_xsrf_id
			where xsrf_id = p_id
			;
		if not found then
			insert into q_qr_valid_xsrf_id ( xsrf_id ) values ( p_id );
		end if;
	end if;

	if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Application - Please Reinstall on Application Menu Last Item","code":"m4_count()","location":"m4___file__ m4___line__"}';
	end if;

	if not l_fail then

		l_data = '{"status":"success"'
			||'}';

	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;

-- select q_auth_v1_xsrf_setup ( 'e2f49c64-2d98-4c93-4b16-313a64f830f5'::uuid,'http://localhost:8080/home','my long secret password','user in');

















-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE if not exists q_qr_s3_log (
	  s3_log_id			uuid DEFAULT uuid_generate_v4() not null primary key
	, group_id			uuid
	, user_id			uuid
	, file_name			text
	, state				text
	, error_msg			text
	, s3_file_name		text
	, updated 			timestamp
	, created 			timestamp default current_timestamp not null
);
comment on table q_qr_s3_log is 'log of files pushed to S3 - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';

create index if not exists q_qr_s3_log_p1 on q_qr_s3_log ( group_id );
create index if not exists q_qr_s3_log_p2 on q_qr_s3_log ( user_id );
create index if not exists q_qr_s3_log_p3 on q_qr_s3_log ( state );

m4_updTrig(q_qr_s3_log)








-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Track all the email that is sent.
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE if not exists q_qr_email_log (
	  email_log_id	uuid DEFAULT uuid_generate_v4() not null primary key
	, user_id			uuid
	, state				text
	, error_msg			text
	, email_data		text
	, updated 			timestamp
	, created 			timestamp default current_timestamp not null
);
comment on table q_qr_email_log is 'log of emails sent - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';

create index if not exists q_qr_email_log_p1 on q_qr_email_log ( state );
create index if not exists q_qr_email_log_p2 on q_qr_email_log ( user_id );

m4_updTrig(q_qr_email_log)


-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- email to be sent.
--
-- email_data is in JSON format as text and is a hash of named value pairs that matches with the template_name's requried values.
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
alter table if exists q_qr_email_send add column if not exists error_info		text;
CREATE TABLE if not exists q_qr_email_send (
	  email_send_id	uuid DEFAULT uuid_generate_v4() not null primary key
	, user_id			uuid					-- if available
	, state				text default 'pending' not null check ( state in ( 'pending', 'sent', 'error' ) )
	, template_name		text not null			-- "./tmpl/Name.tmpl"
	, email_data		text not null
	, error_info		text
	, error_log_id		uuid
	, updated 			timestamp
	, created 			timestamp default current_timestamp not null
);
comment on table q_qr_email_send is 'log of emails sent - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';

create index if not exists q_qr_email_send_p1 on q_qr_email_send ( state );
create index if not exists q_qr_email_send_p2 on q_qr_email_send ( user_id );
create index if not exists q_qr_email_send_p3 on q_qr_email_send ( state, created );

m4_updTrig(q_qr_email_send)











-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--
-- This table has one row to validate that the encryption passwords are setup correctly.
-- Use the function `q_auth_v1_validate_startup_passwords` to see if the passwords are correct.
-- This should happen via the libary call `func ValidatePasswords() (err error)` and
-- see if you get a non-error result.
--
-- Use the function `q_auth_v1_setup_startup_one_time` to set this up.
--
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE if not exists q_qr_validate_startup (
	once_id								int unique primary key, -- only one row in table ever, no generation of PKs.
	validation_value_hmac 				bytea not null,
	validation_value_enc 				bytea not null
);
comment on table q_qr_validate_startup is 'Check database has correct encryption passwords (one row only)  - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';


-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Function to setup checking of encryption passwords.
-- Call this once per install of the database.
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION q_auth_v1_setup_startup_one_time ( p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_db_name				text;
	l_fail					bool;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
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
			l_data = '{"status":"error","msg":"Not initialized properly - incorrect passwords","code":"m4_count()","location":"m4___file__ m4___line__"}';
	end;

	SELECT current_database()
		into l_db_name;

	if not l_fail then

		l_data = '{"status":"success"'
			||', "db_name":' 			||coalesce(to_json(l_db_name)::text,'""')
			||'}';

	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;














-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Function to check encryption passwords.  Return 'success' if the passwords are corect.
-- Doing this prevents encryption split/brain data.
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION q_auth_v1_validate_startup_passwords ( p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_debug_on 				bool;
	l_id					uuid;
	l_junk					text;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2023.
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
			l_data = '{"status":"error","msg":"Not configured properly - incorrect passwords","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Not configured properly - incorrect passwords', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;
	exception
		when others then
			l_fail = true;
			l_data = '{"status":"error","msg":"Not configured properly - incorrect passwords","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Not configured properly - incorrect passwords', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
	end;


	if not l_fail then

		l_data = '{"status":"success"'
			||'}';

	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;


-- -- Quick Test
-- delete from q_qr_validate_startup ;
-- select q_auth_v1_setup_startup_one_time ( 'bob', 'bob' );
-- select q_auth_v1_validate_startup_passwords ( 'bob', 'bob' );
-- delete from q_qr_validate_startup ;

























-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Called to get a ID with a hmac for the ETag.
--
-- Call Path:
--		{Method: "GET", Path: "/api/v1/id.json", Fx: loginTrackingJsonHandler, UseLogin: PublicApiCall},                                              //
--		((( From clearn_gif.go ))) line ~125
--		func loginTrackingJsonHandler(c *gin.Context) {
--
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- stmt := "q_auth_v1_etag_seen ( $1, $2, $3, $4 )"
CREATE OR REPLACE FUNCTION q_auth_v1_etag_seen ( p_id varchar, p_etag varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_debug_on 				bool;
	l_user_id				uuid;
	l_id					uuid;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_auth_v1_etag_seen <- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '		p_id ->'||coalesce(to_json(p_id)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '		p_etag ->'||coalesce(to_json(p_etag)::text,'---null---')||'<-');
	end if;

	if not l_fail then
		select
				  t1.id
				, t1.user_id
			into
				  l_id
				, l_user_id
			from q_qr_device_track as t1
			where t1.etag_seen = p_etag
			for update
		;
		if not found then
			l_fail = true;
			l_data = '{"status":"success"'
				||',"xmsg":'			||'"created"'
				||'}';
			insert into q_qr_device_track ( id, etag_seen ) values ( p_id::uuid, p_etag );
			l_id = p_id;
			if l_debug_on then
				insert into t_output ( msg ) values ( ' etag not found in q_qr_device_track ' );
			end if;
		else
			update q_qr_device_track as t1
				set updated = current_timestamp
				  , n_seen = n_seen + 1
				where t1.id = l_id
			;
			if l_debug_on then
				insert into t_output ( msg ) values ( ' etag found -updated with current timestamp in q_qr_device_track ' );
			end if;
		end if;
	end if;

	if not l_fail then

		l_data = '{"status":"success"'
			||', "user_id":' 		||coalesce(to_json(l_user_id)::text,'""')
			||', "id":' 			||coalesce(to_json(l_id)::text,'""')
			||', "etag":' 			||coalesce(to_json(p_etag)::text,'""')
			||'}';

	end if;

	if l_debug_on then
		insert into t_output ( msg ) values ( ' 		l_data= '||l_data );
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;










-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Called when 2fa-token is validated.
--
-- Call Path:
--		{Method: "POST", Path: "/api/v1/auth/validate-2fa-token", Fx: authHandleValidate2faToken, UseLogin: PublicApiCall},                           // 2nd step 2fa - create auth-token / jwtToken Sent
-- 		func authHandleValidate2faToken(c *gin.Context) {
--
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--
-- select * from q_qr_device_track ;
--
-- select q_auth_v1_etag_device_mark ( 'cf217b21-b030-4e47-59d3-6ce00174e4ea',4,'my long secret password','user info password');
--
-- select * from q_qr_device_track ;

-- drop function q_auth_v1_etag_device_mark ( p_seen_id varchar, p_user_id varchar, p_hmac_password varchar, p_userdata_password varchar );
-- drop function q_auth_v1_etag_device_mark ( p_seen_id varchar, p_user_id uuid, p_hmac_password varchar, p_userdata_password varchar );

-- to be called when you have a successful 2fa validation on a user_id
CREATE OR REPLACE FUNCTION q_auth_v1_etag_device_mark ( p_seen_id varchar, p_user_id uuid, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_debug_on 				bool;
	v_cnt 					int;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_auth_v1_etag_device_mark<- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '		p_seen_id ->'||coalesce(to_json(p_seen_id)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '		p_user_id ->'||coalesce(to_json(p_user_id)::text,'---null---')||'<-');
	end if;

	if not l_fail then
		-- xyzzy - TODO - upsert!
		update q_qr_device_track as t1
			set user_id = p_user_id
			  , n_2fa_token = n_2fa_token + 1
			where t1.id = p_seen_id::uuid
		;
		GET DIAGNOSTICS v_cnt = ROW_COUNT;
		if v_cnt = 0 then
			-- xyzzy - Error p_etag!!!!!!!!!!!!!!!!
			-- insert into q_qr_device_track ( id, user_id, etag_seen ) values ( p_seen_id::uuid, p_user_id, '38656434363231316634' );
			insert into q_qr_device_track ( id, user_id, etag_seen ) values ( p_seen_id::uuid, p_user_id, '00000000000000000000' );
			insert into t_output ( msg ) values ( '		set p_user_id ->'||p_user_id||'<- in q_qr_device_track -- shoudl be unreachable code');
		elsif v_cnt > 0 then
			insert into t_output ( msg ) values ( '		set p_user_id ->'||p_user_id||'<- in q_qr_device_track -- multiple rows, why');
		else
			insert into t_output ( msg ) values ( '		set p_user_id ->'||p_user_id||'<- !! not set !! q_qr_device_track');
		end if;
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "nr":'   		||coalesce(to_json(v_cnt)::text,'""')
			||'}';
	end if;

	if l_debug_on then
		insert into t_output ( msg ) values ( ' 		l_data= '||l_data );
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;











-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE SEQUENCE if not exists t_order_seq
	INCREMENT 1
	MINVALUE 1
	MAXVALUE 9223372036854775807
	START 1
	CACHE 1;





-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- stmt := "insert into q_qr_uploaded_fiels ( id, original_file_name, content_type, size ) values ( $1, $2, $3, $4 )"
-- alter table q_qr_uploaded_files  add image_confirmed	varchar(1) default 'n' not null check ( image_confirmed in ( 'y', 'n' ) );

alter table if exists q_qr_uploaded_files add column if not exists user_id				uuid;				-- UserId for the if login is used, may be null

-- drop table if exists q_qr_uploaded_files ;
CREATE TABLE if not exists q_qr_uploaded_files (
	id					uuid DEFAULT uuid_generate_v4() not null primary key,
	group_id			uuid,				-- a user specified ID to join to another table.
	group_n_id			int,
	original_file_name	text not null,
	content_type		text not null default 'text/plain',
	size 				int not null default 0,
	file_hash			text,
	url_path			text,
	local_file_path		text,
	image_confirmed		varchar(1) default 'n' not null check ( image_confirmed in ( 'y', 'n' ) ),
    seq 				bigint DEFAULT nextval('t_order_seq'::regclass) NOT NULL,
	user_id				uuid				-- UserId for the if login is used, may be null
);
comment on table q_qr_uploaded_files is 'files uploaded - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';

-- xyzzy - Add group_n_id		int					-- user specifed.
-- xyzzy - add URL_path for getting file			-- URL for getting file.
-- xyzzy - add local_file_path for getting file		-- ./www/files/XXXX....

create index if not exists q_qr_uploaded_files_p1 on q_qr_uploaded_files ( group_id );
create index if not exists q_qr_uploaded_files_p2 on q_qr_uploaded_files using hash ( file_hash );
create index if not exists q_qr_uploaded_files_p3 on q_qr_uploaded_files ( group_n_id );
create index if not exists q_qr_uploaded_files_p4 on q_qr_uploaded_files ( url_path );
create index if not exists q_qr_uploaded_files_p5 on q_qr_uploaded_files ( local_file_path );
create index if not exists q_qr_uploaded_files_p6 on q_qr_uploaded_files ( user_id, group_id )
	where user_id is not null
	;

-- xyzzyUpload
-- stmt = "insert into q_qr_uploaded_files ( id, original_file_name, content_type, size, file_hash, group_id, local_file_path, image_confirmed, url_path ) values ( $1, $2, $3, $4, $5, $6, $7, $8, $9 )"
-- stmt = "q_auth_v1_uploaded_files ( $1, $2, $3, $4, $5, $6, $7, $8, $9, $10 )"
drop FUNCTION if exists q_auth_v1_uploaded_files ( p_id uuid, p_original_file_name varchar, p_content_type varchar, p_size varchar, p_file_hash varchar, p_group_id varchar, p_local_file_path varchar, p_image_confirmed varchar, p_url_path varchar, p_user_id varchar );
--                                                    1          2                             3                       4           5                    6                   7                          8                          9                   10
CREATE OR REPLACE FUNCTION q_auth_v1_uploaded_files ( p_id uuid, p_original_file_name varchar, p_content_type varchar, p_size int, p_file_hash varchar, p_group_id varchar, p_local_file_path varchar, p_image_confirmed varchar, p_url_path varchar, p_user_id varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_user_id				uuid;
	l_debug_on 				bool;
	l_size 					int;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	begin

		if p_user_id is not null then
			l_user_id = p_user_id::uuid;
		else
			l_user_id = NULL;
		end if;

		if p_size is not null then
			l_size = p_size::int;
		else
			l_size = 0;
		end if;

	exception
		when others then

			l_fail = true;
			l_data = '{"status":"error","msg":"Type conversion error.","code":"m4_count()","location":"m4___file__ m4___line__"}';

	end;


--	begin

		insert into q_qr_uploaded_files ( id, original_file_name, content_type, size, file_hash, group_id, local_file_path, image_confirmed, url_path, user_id )
			values ( p_id, p_original_file_name, p_content_type, l_size, p_file_hash, p_group_id::uuid, p_local_file_path, p_image_confirmed, p_url_path, l_user_id )
			;

--	exception
--		when others then
--
--			l_fail = true;
--			l_data = '{"status":"error","msg":"error on insert.","code":"m4_count()","location":"m4___file__ m4___line__"}';
--
--	end;

	if not l_fail then

		l_data = '{"status":"success"'
			||'}';

		if l_debug_on then
			insert into t_output ( msg ) values ( ' l_data= '||l_data );
		end if;

	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;








































-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- CORS origins that are valid.  The data in the 'valid' field is a regular expression pattern.
-- This means that requests to this table result in a full table scan every time.
-- I.E. keep the number of rows in this table short.
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE if not exists t_valid_cors_origin (
	  id		uuid DEFAULT uuid_generate_v4() not null primary key
	, valid 	text not null
	, updated 	timestamp
	, created 	timestamp default current_timestamp not null
);
comment on table t_valid_cors_origin is 'valid CORS origins - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';

m4_updTrig(t_valid_cors_origin)






-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- QR Tables
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE if not exists q_qr_code (
	qr_code_id 			uuid default uuid_generate_v4() not null primary key,
	qr_type				varchar(30) not null default 'redirect' check ( qr_type in ( 'unknown', 'redirect', 'proxy', 'direct' ) ),
	qrid10				varchar(10) not null,
	body				text not null,		-- what is encoded in the QR
	file_name			text not null,		-- local relative file name
	url_name			text not null,		-- URL path to file
	owner_user_id		uuid,				-- UserId for the creator
	group_id			int,
	redirect_to			text,
	-- full_text_search 	tsvector,			-- TODO - add trigger and populate from split of body.
	encoding 			varchar(30) not null default 'text',
	img_size 			int not null default 256,
	redundancy			varchar(1) default 'M' check ( redundancy in ( 'M', 'H', 'L' ) ) not null,
	invert				varchar(1) default 'r' check ( invert in ( 'r', 'i' ) ) not null,
	direct				varchar(15) default 'proxy' check ( direct in ( 'direct', 'proxy' ) ) not null,
	add_ran				text default '' not null,									 		-- if not "", then add this as a random value to destination
	updated 			timestamp, 									 						-- Project update timestamp (YYYYMMDDHHMMSS timestamp).
	created 			timestamp default current_timestamp not null 						-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);
comment on table q_qr_code is 'Creation/tracking of QR codes  - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';


-- create index q_qr_code_h1 on q_qr_code using hash ( qrid10 );
create unique index if not exists  q_qr_code_h1 on q_qr_code ( qrid10 );

m4_updTrig(q_qr_code)










-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- State Table
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- SavedStateVars      map[string]string // uses cookie on client to save a set of state vars to d.b. -> g_quth_saved_state table
CREATE TABLE if not exists q_qr_saved_state (
	saved_state_id		uuid DEFAULT uuid_generate_v4() not null primary key, -- this is the X-Saved-State cookie
	user_id 			uuid not null,	-- should FK to user
	data				jsonb,			-- the data.
	expires 			timestamp not null,
	updated 			timestamp, 									 						-- Project update timestamp (YYYYMMDDHHMMSS timestamp).
	created 			timestamp default current_timestamp not null 						-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);
comment on table q_qr_saved_state is 'table of saved user state - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';

create index if not exists q_qr_saved_state_p1 on q_qr_saved_state ( expires );

m4_updTrig(q_qr_saved_state)

-- trigger to set expires

CREATE OR REPLACE FUNCTION q_qr_saved_state_expires() RETURNS trigger
AS $$
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	NEW.expires := current_timestamp + interval '92 days';
	RETURN NEW;
END
$$ LANGUAGE 'plpgsql';


DROP TRIGGER if exists q_qr_saved_state_expire_trig
	ON "q_qr_saved_state"
	;

CREATE TRIGGER q_qr_saved_state_expire_trig
	BEFORE insert or update ON "q_qr_saved_state"
	FOR EACH ROW
	EXECUTE PROCEDURE q_qr_saved_state_expires();






-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- QR Users Table
--
-- rfc8235 based ID xyzzyRfc8235 TODO
-- 	validator				number,									// v value, may need to store v,e,y,x
-- 	e						number,									// v value, may need to store v,e,y,x
-- 	y						number,									// v value, may need to store v,e,y,x
-- 	x						number,									// v value, may need to store v,e,y,x
-- 	auth_cfg				text default 'password' not null,		// 'sid' => use RFC 8235 => Use Validator, "password" => use password_hash
-- 	auth_tid				uuid,									// Redis data store or local data store for temporary ID data.
--
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- alter table q_qr_users add column validation_method		varchar(10) default 'un/pw' not null;
-- alter table q_qr_users add column validator				text;
-- alter table q_qr_users add column e_value				text;
-- alter table q_qr_users add column x_value				text;
-- alter table q_qr_users add column y_value				text;
-- alter table q_qr_users add column first_name_hmac 		text;
-- alter table q_qr_users add column last_name_hmac 		text;
-- alter table q_qr_users add column pdf_enc_password				text;

-- alter table q_qr_users drop column acct_state	;
-- alter table q_qr_users add column acct_state		varchar(40) default 'reg0' not null check ( acct_state in ( 'reg0', 'change-pw', 'change-2fa', 'change-email', 'other', 'reg1', 'reg2', 'reg3', 'reg4', 'reg5', 'reg6', 'reg7' ) );
-- reg0 => 2fa, email not confirmed.
-- reg2 => 2fa, email setup
-- alter table q_qr_users add column x_user_config 			jsonb default '{}'::json;

-- alter table q_qr_users add column login_2fa_failures 		int default 10 not null;

alter table if exists q_qr_users add column if not exists role_name 		text;
alter table if exists q_qr_users add column if not exists org_name			text;
alter table if exists q_qr_users add column if not exists n6_flag					text default '' not null;
alter table if exists q_qr_users add column if not exists validator		text;
alter table if exists q_qr_users add column if not exists claims			text;
alter table if exists q_qr_users add column if not exists id_token			text;
alter table if exists q_qr_users add column if not exists access_token			text;
alter table if exists q_qr_users add column if not exists refresh_token			text;

DO $$
BEGIN
	BEGIN
		ALTER TABLE q_qr_users DROP CONSTRAINT q_qr_users_account_type_check;
	EXCEPTION
		WHEN duplicate_table THEN	-- postgres raises duplicate_table at surprising times. Ex.: for UNIQUE constraints.
		WHEN duplicate_object THEN
			RAISE NOTICE 'Table constraint q_qr_users_account_type_check already exists';
	END;
	BEGIN
		ALTER TABLE q_qr_users ADD CONSTRAINT  q_qr_users_account_type_check check ( account_type in ( 'login', 'un/pw', 'token', 'other', 'sso' ) );
		-- account_type			varchar(20) default 'login' not null check ( account_type in ( 'login', 'un/pw', 'token', 'other', 'sso' ) ),
	EXCEPTION
		WHEN duplicate_table THEN	-- postgres raises duplicate_table at surprising times. Ex.: for UNIQUE constraints.
		WHEN duplicate_object THEN
			RAISE NOTICE 'Table constraint q_qr_users_account_type_check already exists';
		WHEN others THEN
			RAISE NOTICE 'Table constraint q_qr_users_account_type_check already creation error';
	END;
	BEGIN
		ALTER TABLE q_qr_users DROP CONSTRAINT q_qr_users_validation_method_check;
	EXCEPTION
		WHEN duplicate_table THEN	-- postgres raises duplicate_table at surprising times. Ex.: for UNIQUE constraints.
		WHEN duplicate_object THEN
			RAISE NOTICE 'Table constraint q_qr_users_validation_method_check already exists';
	END;
	BEGIN
		ALTER TABLE q_qr_users ADD CONSTRAINT  q_qr_users_validation_method_check check ( validation_method in ( 'un/pw', 'sip', 'srp6a', 'hw-key', 'webauthn', 'sso' ) );
		-- validation_method		varchar(10) default 'un/pw' not null check ( validation_method in ( 'un/pw', 'sip', 'srp6a', 'hw-key', 'webauthn', 'sso' ) ),
	EXCEPTION
		WHEN duplicate_table THEN	-- postgres raises duplicate_table at surprising times. Ex.: for UNIQUE constraints.
		WHEN duplicate_object THEN
			RAISE NOTICE 'Table constraint q_qr_users_validation_method_check already exists';
		WHEN others THEN
			RAISE NOTICE 'Table constraint q_qr_users_validation_method_check already creation error';
	END;
END $$;








CREATE TABLE if not exists q_qr_users (
	user_id 				uuid default uuid_generate_v4() not null primary key,
	email_hmac 				bytea not null,
	email_enc 				bytea not null,										-- encrypted/decryptable email address
	password_hash 			text not null,
	validation_method		varchar(10) default 'un/pw' not null check ( validation_method in ( 'un/pw', 'sip', 'srp6a', 'hw-key', 'webauthn', 'sso' ) ),
	validator				text, 
	e_value					text,
	x_value					text,
	y_value					text,
	client_id				uuid,	-- if not null then this users will use partitioned data by client_id. See: q_qr_client						-- NOT USED -- NOT USED -- !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	pdf_enc_password		text,	-- Password used for encryption of .pdf files - per user.
	first_name_enc			bytea not null,
	first_name_hmac 		text not null,
	last_name_enc			bytea not null,
	last_name_hmac 			text not null,
	acct_state				varchar(40) default 'reg0' not null check ( acct_state in ( 'reg0', 'change-pw', 'change-2fa', 'change-email', 'other', 'reg1', 'reg2', 'reg3', 'reg4', 'reg5', 'reg6', 'reg7' ) ),
	email_validated			varchar(1) default 'n' not null,
	email_verify_token		uuid,
	email_verify_expire 	timestamp,
	password_reset_token	uuid,
	password_reset_time		timestamp,
	failed_login_timeout 	timestamp,
	login_failures 			int default 0 not null,
	login_success 			int default 0 not null,
	login_2fa_failures 		int default 10 not null,
	parent_user_id 			uuid,
	account_type			varchar(20) default 'login' not null check ( account_type in ( 'login', 'un/pw', 'token', 'other', 'sso' ) ),
	require_2fa 			varchar(1) default 'y' not null,
	secret_2fa 				varchar(20),
	setup_complete_2fa 		varchar(1) default 'n' not null,					-- Must be 'y' to login / set by q_auth_v1_validate_2fa_token
	start_date				timestamp default current_timestamp not null,
	end_date				timestamp,
	privileges				text,												-- Copy of the privilages associated with role_name (if role_name changes then this sould be updated) (denormalized data) -- not used in login/auth
	x_user_config 			jsonb default '{}'::json not null,
	role_name 				text not null,
	org_name				text,												-- Used for testing - name of the Admin that this user is tied to
	n6_flag					text default '' not null,							-- used to mark if user was registered with n6 or n8 flag.
	claims 					text,
	id_token 				text,
	access_token 			text,
	refresh_token 			text,
	updated 				timestamp, 									 		-- Project update timestamp (YYYYMMDDHHMMSS timestamp).
	created 				timestamp default current_timestamp not null 		-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);
comment on table q_qr_users is 'Login authorization - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';

CREATE UNIQUE INDEX if not exists  q_qr_users_u1 on q_qr_users ( email_hmac );

CREATE INDEX if not exists q_qr_users_enc_u2 on q_qr_users ( email_verify_token )
	where email_verify_token is not null;

CREATE INDEX if not exists q_qr_users_enc_p1 on q_qr_users using HASH ( email_hmac );

CREATE INDEX if not exists q_qr_users_enc_p2 on q_qr_users ( email_verify_expire, email_validated )
	where email_verify_expire is not null;

CREATE INDEX if not exists q_qr_users_enc_p3 on q_qr_users ( password_reset_token )
	where password_reset_token is not null;

CREATE INDEX if not exists q_qr_users_enc_p4 on q_qr_users using HASH ( first_name_hmac );

CREATE INDEX if not exists q_qr_users_enc_p5 on q_qr_users using HASH ( last_name_hmac );

CREATE INDEX if not exists q_qr_users_enc_u6 on q_qr_users ( client_id, user_id )
	where client_id is not null;

CREATE INDEX if not exists q_qr_users_enc_u7 on q_qr_users ( client_id, email_hmac )
	where client_id is not null;

CREATE INDEX if not exists q_qr_users_enc_p8 on q_qr_users ( role_name );

m4_updTrig(q_qr_users)





update q_qr_users set n6_flag = 'n6' where n6_flag is null or n6_flag = '';

insert into q_qr_config ( name, value ) values
	  ( 'n6.flag', 'n6' )
On CONFLICT(name) DO NOTHING
;








-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- xyzzy99 - add 8th param -- {Method: "GET", Path: "/api/v1/auth/email-confirm", Fx: authHandlerEmailConfirm, UseLogin: PublicApiCall},                                    // token
-- xyzzy99 if n6 - 6 digit random returned by call
-- SELECT random();
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
alter table if exists q_qr_n6_email_verify add column if not exists updated 				timestamp; 									 		-- Project update timestamp (YYYYMMDDHHMMSS timestamp).
alter table if exists q_qr_n6_email_verify add column if not exists created 				timestamp default current_timestamp not null 		;

CREATE TABLE if not exists q_qr_n6_email_verify (
	n6_token 				int not null,
	email_verify_token		uuid not null,
	updated 				timestamp, 									 		-- Project update timestamp (YYYYMMDDHHMMSS timestamp).
	created 				timestamp default current_timestamp not null 		-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);

comment on table q_qr_n6_email_verify is 'n6/n8 keys - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';

CREATE UNIQUE INDEX if not exists  q_qr_n6_email_verify_u1 on q_qr_n6_email_verify ( n6_token );
DROP INDEX if exists q_qr_n6_email_verify_u2;
CREATE INDEX if not exists  q_qr_n6_email_verify_p1 on q_qr_n6_email_verify ( email_verify_token );
create index if not exists q_qr_n6_verify_p2 on q_qr_n6_email_verify ( created );



-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Join to users to track a set of keys for notification for a single user.
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE if not exists q_qr_vapid_keys (
	vapid_id 				uuid default uuid_generate_v4() not null primary key,
	user_id 				uuid not null,
	public_key				text not null,
	private_key				text not null,
	updated 				timestamp, 									 		-- Project update timestamp (YYYYMMDDHHMMSS timestamp).
	created 				timestamp default current_timestamp not null 		-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);
comment on table q_qr_vapid_keys is 'VAPID keys for user - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';

m4_updTrig(q_qr_vapid_keys)

CREATE INDEX if not exists q_qr_vapid_keys_p1 on q_qr_vapid_keys using HASH ( public_key );
CREATE INDEX if not exists q_qr_vapid_keys_p2 on q_qr_vapid_keys ( user_id, created );



















-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE if not exists q_qr_user_hierarchy (
	user_hierarchy_id 		uuid default uuid_generate_v4() not null primary key,
	user_id 				uuid not null,
	parent_user_id			uuid
);
comment on table q_qr_user_hierarchy is 'user hererchy (admin->user, admin->client, cilent->client-user, etc) - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';

CREATE INDEX if not exists q_qr_user_hierarchy_p1 on q_qr_user_hierarchy ( user_id );
CREATE INDEX if not exists q_qr_user_hierarchy_p2 on q_qr_user_hierarchy ( parent_user_id );




-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION q_qr_user_id_to_email ( p_user_id varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_email					text;
	x text;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()

 	select
		    pgp_sym_decrypt(t1.email_enc, p_userdata_password)::text as email
			, t1.email_hmac::text
		into l_email
			, x
		from q_qr_users as t1
		where t1.user_id = p_user_id::uuid
		limit 1
		;
	if not found then
		l_email = '';
	end if;
	RETURN l_email;
END;
$$ LANGUAGE plpgsql;

-- select q_qr_user_id_to_email ( '71fee0ec-5697-4d45-9759-5a6db492adc1', 'user info password' );
-- select q_qr_user_id_to_email ( 'ffca0fb8-c600-4ef2-af05-156aec4f683e', 'user info password' );




-- StoredProcedureName: "q_qr_email_to_user_id",
CREATE OR REPLACE FUNCTION q_qr_email_to_user_id ( p_email varchar,  p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_user_id					text;
	l_email_hmac				bytea;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()

	l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );
 	select
		    user_id::text
		into l_user_id
		from q_qr_users as t1
		where t1.email_hmac = l_email_hmac
		limit 1
		;
	if not found then
		l_user_id = '--not-found--';
	end if;
	RETURN l_user_id;
END;
$$ LANGUAGE plpgsql;

-- select q_qr_email_to_user_id ( 'bob@client.com', 'my long secret password', 'user info password' );
-- select q_qr_email_to_user_id ( 'bob.00080@client.com', 'my long secret password', 'user info password' );


-- select msg from t_output order by seq;



alter table q_qr_user_config add column if not exists   client_cfg				text not null default 'n';		-- if 'y' then report to client.



-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE if not exists q_qr_user_config (
	config_id 				uuid default uuid_generate_v4() not null primary key,
	user_id 				uuid not null,
	name					text not null,
	value					text not null,
	client_cfg				text not null default 'n',		-- if 'y' then report to client.
	updated 				timestamp, 									 		-- Project update timestamp (YYYYMMDDHHMMSS timestamp).
	created 				timestamp default current_timestamp not null 		-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);
comment on table q_qr_user_config is 'Per user conifiguraiton  - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';

create index if not exists q_qr_user_config_p1 on q_qr_user_config ( user_id );
create unique index if not exists  q_qr_user_config_u1 on q_qr_user_config ( user_id, name );



DO $$
BEGIN
	BEGIN
		-- ALTER TABLE q_qr_user_config drop CONSTRAINT if exists q_qr_user_config_fk1 ;
		ALTER TABLE q_qr_user_config
			ADD CONSTRAINT q_qr_user_config_fk1
			FOREIGN KEY (user_id)
			REFERENCES q_qr_users (user_id)
		;
	EXCEPTION
		WHEN duplicate_table THEN	-- postgres raises duplicate_table at surprising times. Ex.: for UNIQUE constraints.
		WHEN duplicate_object THEN
			RAISE NOTICE 'Table constraint q_qr_user_config already exists';
	END;
END $$;

DO $$
BEGIN
	BEGIN
		-- ALTER TABLE q_qr_user_config drop CONSTRAINT if exists q_qr_user_config_u1 ;
		ALTER TABLE q_qr_user_config
			ADD CONSTRAINT q_qr_user_config_u1
			UNIQUE USING INDEX q_qr_user_config_u1
		;
	EXCEPTION
		WHEN duplicate_table THEN	-- postgres raises duplicate_table at surprising times. Ex.: for UNIQUE constraints.
		WHEN duplicate_object THEN
			RAISE NOTICE 'Table constraint q_qr_user_config already exists';
		WHEN others THEN
			RAISE NOTICE 'Table constraint q_qr_user_config already exists';
	END;
END $$;

m4_updTrig(q_qr_user_config)







-- xyzzy400 - must create user with this user_id!

-- insert into q_qr_user_config ( user_id, name, value ) values
-- 	  ( '71fee0ec-5697-4d45-9759-5a6db492adc1'::uuid, 'display-mode',    		'light' )
-- 	, ( '71fee0ec-5697-4d45-9759-5a6db492adc2'::uuid, 'show-upload-button', 	'true'  )
-- 	;

CREATE TABLE if not exists q_qr_user_config_default (
	user_config_default_id 		uuid default uuid_generate_v4() not null primary key,
	role_name 					text not null,		-- join to Q_QR_ROLE2
	value						jsonb not null
);
comment on table q_qr_user_config_default is 'Per user conifiguraiton / default at registration based on role  - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';

create unique index if not exists  q_qr_user_config_default_u1 on q_qr_user_config_default ( role_name );

DO $$
BEGIN
	BEGIN
		-- ALTER TABLE q_qr_user_config_default drop CONSTRAINT if exists q_qr_user_config_defauilt__role_name_uniq1 ;
		ALTER TABLE q_qr_user_config_default
			ADD CONSTRAINT q_qr_user_config_defauilt__role_name_uniq1
			UNIQUE ( role_name )
			;
	EXCEPTION
		WHEN duplicate_table THEN	-- postgres raises duplicate_table at surprising times. Ex.: for UNIQUE constraints.
		WHEN duplicate_object THEN
			RAISE NOTICE 'Table constraint q_qr_user_config_default already exists';
	END;
END $$;


-- update q_qr_users set x_user_config = '{"display-mode":"light","show-upload-button":"hide" }'::jsonb ;
















-- drop function if exists get_user_list(character varying,character varying);

CREATE OR REPLACE FUNCTION get_user_list( p_hmac_password varchar, p_userdata_password varchar ) RETURNS TABLE (
    user_id uuid,
    email text,
	first_name text,
	last_name text
)
AS $$
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()

	RETURN QUERY
		SELECT
			  t1.user_id
		    , pgp_sym_decrypt(t1.email_enc,p_userdata_password)::text as email
		    , pgp_sym_decrypt(t1.first_name_enc,p_userdata_password)::text as first_name
		    , pgp_sym_decrypt(t1.last_name_enc,p_userdata_password)::text as last_name
		FROM q_qr_users as t1
		;
END;
$$ LANGUAGE 'plpgsql';








-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- drop function q_auth_v1_hmac_encode_email ( p_email varchar, p_hmac_password varchar );
-- drop function q_auth_v1_hmac_encode ( p_email varchar, p_hmac_password varchar );

CREATE OR REPLACE FUNCTION q_auth_v1_hmac_encode ( p_email varchar, p_hmac_password varchar ) RETURNS bytea
AS $$
DECLARE
	l_data					text;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()

	-- l_data = encode(hmac(p_email, p_hmac_password, 'sha256'), 'base64');
	l_data = hmac(p_email, p_hmac_password, 'sha256');
	RETURN l_data;
END;
$$ LANGUAGE plpgsql;

-- INSERT INTO q_qr_users (email_hmac, password_hash, first_name_enc, last_name_enc, email_enc ) VALUES
-- 	    (
-- 			 q_auth_v1_hmac_encode ( 'testAcct1@email.com', 'my-long-secret' )
-- 			, crypt('Think Pink Ink 9434', gen_salt('bf') )
-- 		    , pgp_sym_encrypt('Test User 1','p_userdata_password')
-- 		    , pgp_sym_encrypt('Test User 1','p_userdata_password')
-- 		    , pgp_sym_encrypt('testAcct1@email.com','p_userdata_password')
-- 		)
-- 	,   (
-- 			 q_auth_v1_hmac_encode ( 'testAcct2@email.com', 'my--other-long-secret' )
-- 			, crypt('Mimsey!81021', gen_salt('bf') )
-- 		    , pgp_sym_encrypt('Test User 1','p_userdata_password')
-- 		    , pgp_sym_encrypt('Test User 1','p_userdata_password')
-- 		    , pgp_sym_encrypt('testAcct2@email.com','p_userdata_password')
-- 		)
-- ;











-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Auth Token Table
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
alter table q_qr_auth_tokens add column if not exists   sc_id				text 					;

CREATE TABLE if not exists q_qr_auth_tokens (
	auth_token_id 			uuid default uuid_generate_v4() primary key not null,
	user_id 				uuid not null,
	token			 		uuid not null,			-- auth_token
	sc_id					text, 					-- ScID				scid
	api_encryption_key		text,
	expires 				timestamp not null
);
comment on table q_qr_auth_tokens is 'Per user auth tokens - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';

create unique index if not exists  q_qr_auth_tokens_u1 on q_qr_auth_tokens ( token );
create index if not exists q_qr_auth_tokens_p1 on q_qr_auth_tokens ( user_id );
create index if not exists q_qr_auth_tokens_p2 on q_qr_auth_tokens ( expires );
create index if not exists q_qr_auth_tokens_p3 on q_qr_auth_tokens ( api_encryption_key	) where  api_encryption_key is not null ;

DO $$
BEGIN
	BEGIN
		-- ALTER TABLE  q_qr_auth_tokens drop CONSTRAINT if exists  q_qr_auth_tokens_fk1 ;
		ALTER TABLE q_qr_auth_tokens
			ADD CONSTRAINT q_qr_auth_tokens_fk1
			FOREIGN KEY (user_id)
			REFERENCES q_qr_users (user_id)
		;
	EXCEPTION
		WHEN duplicate_table THEN	-- postgres raises duplicate_table at surprising times. Ex.: for UNIQUE constraints.
		WHEN duplicate_object THEN
			RAISE NOTICE 'Table constraint q_qr_auth_tokens already exists';
	END;
END $$;



CREATE OR REPLACE FUNCTION q_qr_auth_token_expires() RETURNS trigger
AS $$
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()

	-- NEW.expires := current_timestamp + interval '31 days';
	NEW.expires := current_timestamp + interval '2000 days';
	RETURN NEW;
END
$$ LANGUAGE 'plpgsql';


DROP TRIGGER if exists q_qr_auth_tokens_expire_trig
	ON "q_qr_auth_tokens"
	;

CREATE TRIGGER q_qr_auth_tokens_expire_trig
	BEFORE insert or update ON "q_qr_auth_tokens"
	FOR EACH ROW
	EXECUTE PROCEDURE q_qr_auth_token_expires();

CREATE OR REPLACE view q_qr_valid_token as
	select
		auth_token_id,
		user_id,
		token
	from q_qr_auth_tokens
	where expires >= current_timestamp
;

CREATE OR REPLACE view q_qr_expired_token as
	select
		auth_token_id,
		user_id,
		token
	from q_qr_auth_tokens
	where expires < current_timestamp
;











-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Tmp Token Table -- used for 2fa 2nd part validateion
--
-- This is a table of temporary access tokens.  The lifespan is usualy 10 minutes.
--
-- This is the place to put temporary data during login - tmp_token will be passed from call to call.
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

alter table if exists q_qr_tmp_token add column if not exists auth_token 			uuid;

CREATE TABLE if not exists q_qr_tmp_token (
	tmp_token_id 		uuid default uuid_generate_v4() primary key not null,
	user_id 			uuid not null,
	token			 	uuid not null,	-- the tmp_token
	auth_token		 	uuid not null,
	expires 			timestamp not null	-- set to 20 min in future by trigger.
);
comment on table q_qr_tmp_token is 'registration temporary tokens - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';

--	sip_x_value				text,
--	sip_e_value				text,
--	sip_v_value				text,
--	sip_y_value				text,

create unique index if not exists  q_qr_tmp_token_u1 on q_qr_tmp_token ( token );
create index if not exists q_qr_tmp_token_p1 on q_qr_tmp_token ( user_id );
create index if not exists q_qr_tmp_token_p2 on q_qr_tmp_token ( expires );
create index if not exists q_qr_tmp_token_p3 on q_qr_tmp_token ( user_id, auth_token );

DO $$
BEGIN
	BEGIN
		-- ALTER TABLE q_qr_tmp_token drop CONSTRAINT if exists q_qr_tmp_token_fk1 ;
		ALTER TABLE q_qr_tmp_token
			ADD CONSTRAINT q_qr_tmp_token_fk1
			FOREIGN KEY (user_id)
			REFERENCES q_qr_users (user_id)
		;
	EXCEPTION
		WHEN duplicate_table THEN	-- postgres raises duplicate_table at surprising times. Ex.: for UNIQUE constraints.
		WHEN duplicate_object THEN
			RAISE NOTICE 'Table constraint q_qr_tmp_token already exists';
	END;
END $$;



CREATE OR REPLACE FUNCTION q_qr_tmp_token_expires() RETURNS trigger
AS $$
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()

	if NEW.expires is null then
		NEW.expires := current_timestamp + interval '20 minutes';
	end if;
	RETURN NEW;
END
$$ LANGUAGE 'plpgsql';


DROP TRIGGER if exists q_qr_tmp_tokens_expire_tmp_trig
	ON "q_qr_tmp_token"
	;

CREATE TRIGGER q_qr_tmp_tokens_expire_tmp_trig
	BEFORE insert or update ON "q_qr_tmp_token"
	FOR EACH ROW
	EXECUTE PROCEDURE q_qr_tmp_token_expires();

CREATE OR REPLACE view q_qr_valid_tmp_token as
	select
		tmp_token_id,
		user_id,
		token
	from q_qr_tmp_token
	where expires >= current_timestamp
;

CREATE OR REPLACE view q_qr_expired_tmp_token as
	select
		tmp_token_id,
		user_id,
		token
	from q_qr_tmp_token
	where expires < current_timestamp
;





-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Depricated!
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--CREATE TABLE if not exists q_qr_auth_security_log (
--		security_log_id 	uuid default uuid_generate_v4() primary key not null,
--		user_id 			uuid not null,
--		activity			text,
--		location			text,
--		created 			timestamp default current_timestamp not null 						-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
--	);
--comment on table q_qr_auth_security_log is 'Security event log - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';





-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
drop TABLE if exists q_qr_auth_security_log ;

alter table if exists q_qr_auth_log add column if not exists seq 				bigint DEFAULT nextval('t_order_seq'::regclass) NOT NULL;

CREATE TABLE if not exists q_qr_auth_log (
	security_log_id 	uuid default uuid_generate_v4() primary key not null,
	user_id 			uuid,
	activity			text,
	code				text,
	location			text,
    seq 				bigint DEFAULT nextval('t_order_seq'::regclass) NOT NULL,
	created 			timestamp default current_timestamp not null 						-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);
comment on table q_qr_auth_log is 'Authentication log - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';





-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- CREATE TABLE if not exists q_qr_trace_params (
-- 	trace_params_id 	uuid default uuid_generate_v4() primary key not null,
-- 	json_data			text,
-- 	created 			timestamp default current_timestamp not null 						-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
-- );





-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE if not exists q_qr_one_time_password (
	one_time_password_id 	uuid default uuid_generate_v4() primary key not null,
	user_id					uuid not null,
	otp_hmac				text
);
comment on table q_qr_one_time_password is 'Per user one time passwords - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';

create unique index if not exists  q_qr_one_time_password_u1 on q_qr_one_time_password ( user_id, otp_hmac );

DO $$
BEGIN
	BEGIN
		-- ALTER TABLE  q_qr_one_time_password drop CONSTRAINT if exists q_qr_one_time_password_fk1 ;
		ALTER TABLE q_qr_one_time_password
			ADD CONSTRAINT q_qr_one_time_password_fk1
			FOREIGN KEY (user_id)
			REFERENCES q_qr_users (user_id)
		;
	EXCEPTION
		WHEN duplicate_table THEN	-- postgres raises duplicate_table at surprising times. Ex.: for UNIQUE constraints.
		WHEN duplicate_object THEN
			RAISE NOTICE 'Table constraint q_qr_one_time_password already exists';
	END;
END $$;










-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE if not exists q_qr_config (
	config_id 		uuid default uuid_generate_v4() primary key not null,
	name			text,
	value	 		text,
	b_value	 		bool,
	updated 		timestamp, 									 						-- Project update timestamp (YYYYMMDDHHMMSS timestamp).
	created 		timestamp default current_timestamp not null 						-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);
comment on table q_qr_config is 'Per site/application config - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';

create unique index if not exists  q_qr_config_u1 on q_qr_config ( name ) ;

m4_updTrig(q_qr_config)







drop view if exists q_qr_role_to_priv;
drop TABLE if exists q_qr_priv ;
drop TABLE if exists q_qr_role_priv ;
drop TABLE if exists q_qr_role ;
drop TABLE if exists q_qr_user_role ;

-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--old-priv--
--old-priv---- M:N join from users to roles.   The set of roles that a user has.
--old-priv--CREATE TABLE if not exists q_qr_user_role (
--old-priv--	user_role_id 	uuid default uuid_generate_v4() not null primary key,
--old-priv--	role_id 		uuid not null,
--old-priv--	user_id 		uuid not null
--old-priv--);
--old-priv--comment on table q_qr_user_role is 'user roles join - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';
--old-priv--
--old-priv--create unique index q_qr_user_role_u1 on q_qr_user_role ( role_id, user_id );
--old-priv--create unique index q_qr_user_role_u2 on q_qr_user_role ( user_id, role_id );
--old-priv--
--old-priv---- A list of all the possible roles that a user can have.
--old-priv--CREATE TABLE if not exists q_qr_role (
--old-priv--	  role_id 		uuid default uuid_generate_v4() not null primary key
--old-priv--	, role_name 	text not null
--old-priv--	, with_grant	varchar(1) default 'n'
--old-priv--);
--old-priv--comment on table q_qr_role is 'user roles - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';
--old-priv--
--old-priv--create unique index q_qr_role_u1 on q_qr_role ( role_name );
--old-priv--
--old-priv---- M:N join from roles to privileges - the set of privileges that each role has.
--old-priv--CREATE TABLE if not exists q_qr_role_priv (
--old-priv--	role_priv_id 	uuid default uuid_generate_v4() not null primary key,
--old-priv--	role_id 		uuid not null,
--old-priv--	priv_id 		uuid not null
--old-priv--);
--old-priv--comment on table q_qr_role_priv is 'roles priv join - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';
--old-priv--
--old-priv--create unique index q_qr_role_priv_u1 on q_qr_role_priv ( priv_id, role_id );
--old-priv--create unique index q_qr_role_priv_u2 on q_qr_role_priv ( role_id, priv_id );
--old-priv--
--old-priv---- A talbe containing all the possible things that a person can have a permission to do.
--old-priv--CREATE TABLE if not exists q_qr_priv (
--old-priv--	  priv_id 		uuid default uuid_generate_v4() not null primary key
--old-priv--	, priv_name 	text not null
--old-priv--	, with_grant	varchar(1) default 'n'
--old-priv--);
--old-priv--comment on table q_qr_priv is 'privs - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';
--old-priv--
--old-priv--create unique index q_qr_priv_u1 on q_qr_priv ( priv_name );
--old-priv--
--old-priv--
--old-priv--CREATE OR REPLACE view q_qr_role_to_priv as
--old-priv--	select t1.role_name, t3.priv_name, t1.role_id, t3.priv_id
--old-priv--	from q_qr_role as t1
--old-priv--		join q_qr_role_priv as t2 on ( t2.role_id = t1.role_id )
--old-priv--		join q_qr_priv as t3 on ( t2.priv_id = t3.priv_id )
--old-priv--	;
--old-priv--
--old-priv--CREATE OR REPLACE view q_qr_user_to_priv as
--old-priv--	select t1.user_id, t5.priv_name, t5.priv_id, t3.role_name, t3.role_id, t4.role_priv_id, t2.user_role_id
--old-priv--	from q_qr_users as t1
--old-priv--		join q_qr_user_role as t2 on ( t1.user_id = t2.user_id )
--old-priv--		join q_qr_role      as t3 on ( t2.role_id = t3.role_id )
--old-priv--		join q_qr_role_priv as t4 on ( t3.role_id = t4.role_id )
--old-priv--		join q_qr_priv      as t5 on ( t4.priv_id = t5.priv_id )
--old-priv--	;
--old-priv--
--old-priv--
-- https://rudra.dev/posts/generate-beautiful-json-from-postgresql/
-- xyzzy - TODO - xyzzy89232323 - Add in triggers gor generation of keywords / tsvector
-- select row_to_json("t2")
-- 	from (
-- 		select t1.priv_name, true as istrue
-- 		from q_qr_user_to_priv as t1
-- 	) as t2
-- 	;
--
-- SELECT json_agg(row_to_json(t2))
--       FROM (
-- 		select t1.priv_name, true as istrue
-- 		from q_qr_user_to_priv as t1
--       ) t2
-- 	;
--
-- SELECT json_agg(row_to_json(t2))
--       FROM (
-- 		select t1.priv_name
-- 		from q_qr_user_to_priv as t1
--       ) t2
-- 	;


--                     row_to_json
-- ---------------------------------------------------
--  {"priv_name":"May Change Password","istrue":true}
--  {"priv_name":"May Change Password","istrue":true}
-- (2 rows)
--
--                                                 json_agg
-- --------------------------------------------------------------------------------------------------------
--  [{"priv_name":"May Change Password","istrue":true}, {"priv_name":"May Change Password","istrue":true}]
-- (1 row)
--
--                                   json_agg
-- ----------------------------------------------------------------------------
--  [{"priv_name":"May Change Password"}, {"priv_name":"May Change Password"}]
-- (1 row)

-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- v2 - using a json data for privs.
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE if not exists q_qr_role2 (
	  role_id 		uuid default uuid_generate_v4() not null primary key
	, role_name 	text not null
	, with_grant	varchar(1) default 'n' not null
	, allowed		jsonb not null
);
comment on table q_qr_role2 is 'user roles - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';


create unique index if not exists  q_qr_role2_u1 on q_qr_role2 ( role_name );

DO $$
BEGIN
	BEGIN
		-- ALTER TABLE q_qr_role2 DROP CONSTRAINT IF EXISTS q_qr_role2_u1 ;
		ALTER TABLE q_qr_role2
			ADD CONSTRAINT q_qr_role2_u1
			UNIQUE USING INDEX q_qr_role2_u1
		;
	EXCEPTION
		WHEN duplicate_table THEN	-- postgres raises duplicate_table at surprising times. Ex.: for UNIQUE constraints.
		WHEN duplicate_object THEN
			RAISE NOTICE 'Table constraint q_qr_role2 already exists.';
		WHEN others THEN
			RAISE NOTICE 'Table constraint q_qr_role2 already exists.';
	END;
END $$;


drop view if exists q_qr_user_to_priv;

-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- select role_name, json_object_keys(allowed::json) from q_qr_role2 where role_name = 'role:user';
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE OR REPLACE view q_qr_user_to_priv as
	select json_object_keys(t1.allowed::json)  as priv_name, t1.role_name, t1.role_id, t2.user_id
	from q_qr_role2 as t1
		join q_qr_users as t2 on ( t1.role_name = t2.role_name )
	;





-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- List of valid privilages
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- drop TABLE if exists q_qr_priv2 ;

-- select role_name, json_object_keys(allowed::json) from q_qr_role2 where role_name = 'role:user';
CREATE OR REPLACE view q_qr_priv2 as
	select jsonb_object_keys(allowed) as priv_name
	from q_qr_role2
	group by priv_name
	;




--                                                                                                                     List of functions
--  Schema |      Name       | Result data type |               Argument data types               | Type | Volatility | Parallel | Owner  | Security | Access privileges | Language |                       Source code                       | Description
-- --------+-----------------+------------------+-------------------------------------------------+------+------------+----------+--------+----------+-------------------+----------+---------------------------------------------------------+-------------
--  public | q_admin_haspriv | boolean          | p_user_id uuid, p_priv_needed character varying | func | volatile   | unsafe   | philip | invoker  |                   | plpgsql  |                                                        +|
--         |                 |                  |                                                 |      |            |          |        |          |                   |          | DECLARE                                                +|
--         |                 |                  |                                                 |      |            |          |        |          |                   |          |         l_data bool;                                   +|
--         |                 |                  |                                                 |      |            |          |        |          |                   |          |         l_found text;                                  +|
--         |                 |                  |                                                 |      |            |          |        |          |                   |          | BEGIN                                                  +|
--         |                 |                  |                                                 |      |            |          |        |          |                   |          |         l_data = false;                                +|
--         |                 |                  |                                                 |      |            |          |        |          |                   |          |                                                        +|
--         |                 |                  |                                                 |      |            |          |        |          |                   |          |         if exists (                                    +|
--         |                 |                  |                                                 |      |            |          |        |          |                   |          |                         select 'found'                 +|
--         |                 |                  |                                                 |      |            |          |        |          |                   |          |                         from q_qr_user_to_priv         +|
--         |                 |                  |                                                 |      |            |          |        |          |                   |          |                         where user_id = p_user_id      +|
--         |                 |                  |                                                 |      |            |          |        |          |                   |          |                           and priv_name = p_priv_needed+|
--         |                 |                  |                                                 |      |            |          |        |          |                   |          |                 ) then                                 +|
--         |                 |                  |                                                 |      |            |          |        |          |                   |          |                 l_data = true;                         +|
--         |                 |                  |                                                 |      |            |          |        |          |                   |          |         end if;                                        +|
--         |                 |                  |                                                 |      |            |          |        |          |                   |          |                                                        +|
--         |                 |                  |                                                 |      |            |          |        |          |                   |          |         RETURN l_data;                                 +|
--         |                 |                  |                                                 |      |            |          |        |          |                   |          | END;                                                   +|
--         |                 |                  |                                                 |      |            |          |        |          |                   |          |                                                         |
-- (1 row)
--
CREATE OR REPLACE FUNCTION q_admin_HasPriv ( p_user_id uuid, p_priv_needed varchar ) RETURNS bool
AS $$
DECLARE
	l_data bool;
	l_found text;
	l_role_name text;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_data = false;

	select role_name
		into l_role_name
		from q_qr_users
		where user_id = p_user_id
		;
	if found then

		select allowed ? p_priv_needed
			into l_data
			from q_qr_role2
			where role_name = l_role_name
			;

	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION q_qr_admin_HasPriv_user_id ( p_user_id uuid, p_priv_needed varchar ) RETURNS text
AS $$
DECLARE
	l_data text;
	l_allowed bool;
	l_found text;
	l_role_name text;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2024.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_data = '{"status":"failed"}';			-- no such privilage granted.

	select role_name
		into l_role_name
		from q_qr_users
		where user_id = p_user_id
		;
	if not found then
		l_data = '{"status":"error","msg":"User not found.  Invalid user_id."}';			-- no such privilage granted.
	else

		select allowed ? p_priv_needed
			into l_allowed
			from q_qr_role2
			where role_name = l_role_name
			;
		if found then
			if l_allowed then
				l_data = '{"status":"success"}';
			else
				l_data = '{"status":"failed","msg":"Not Authorized"}';
			end if;
		end if;

	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;

--dev--CREATE OR REPLACE FUNCTION q_qr_admin_AddPriv_user_id ( p_user_id uuid, p_priv_needed varchar ) RETURNS text
--dev--AS $$
--dev--DECLARE
--dev--	l_data text;
--dev--	l_allowed bool;
--dev--	l_found text;
--dev--	l_role_name text;
--dev--	l_allowed_json jsonb;
--dev--BEGIN
--dev--	-- Copyright (C) Philip Schlump, 2008-2023.
--dev--	-- BSD 3 Clause Licensed.  See LICENSE.bsd
--dev--	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
--dev--	l_data = '{"status":"failed"}';			-- no such privilage granted.
--dev--
--dev--	select role_name
--dev--		into l_role_name
--dev--		from q_qr_users
--dev--		where user_id = p_user_id
--dev--		;
--dev--	if not found then
--dev--		l_data = '{"status":"error","msg":"invalid user id, not found"}';			-- no such privilage granted.
--dev--	else
--dev--
--dev--		select allowed ? p_priv_needed
--dev--			into l_allowed
--dev--			from q_qr_role2
--dev--			where role_name = l_role_name
--dev--			;
--dev--		if found then
--dev--			if l_allowed then
--dev--				l_data = '{"status":"success","msg":"already has this privilage."}';
--dev--			end if;
--dev--		else
--dev--			select allowed
--dev--				into l_allowed_json
--dev--				from q_qr_role2
--dev--				where role_name = l_role_name
--dev--				;
--dev--			l_allowed_json = jsonb_insert ( l_allowed_json, NULL, '{ "a":"b" }' );
--dev--		end if;
--dev--
--dev--	end if;
--dev--
--dev--	RETURN l_data;
--dev--END;
--dev--$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION q_qr_admin_HasPriv_email ( p_email text, p_priv_needed varchar, p_hmac_password varchar ) RETURNS text
AS $$
DECLARE
	l_data text;
	l_allowed bool;
	l_found text;
	l_role_name text;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_data = '{"status":"failed"}';			-- no such privilage granted.

	select t1.role_name
		into l_role_name
		from q_qr_users as t1
		where t1.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
		;
	if found then

		select allowed ? p_priv_needed
			into l_allowed
			from q_qr_role2
			where role_name = l_role_name
			;
		if found then
			if l_allowed then
				l_data = '{"status":"success"}';
			end if;
		end if;

	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;





-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Registration with a token.  Token must be valid.   Then the user that is created with this token
-- will have the specified role_name.
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- xyzzy204 - client table / token_registration
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- alter table q_qr_token_registration  add is_one_time				varchar(1) default 'n' not null;
-- alter table q_qr_token_registration  add email_note				text;

alter table if exists q_qr_token_registration add column if not exists admin_email 			text;
alter table if exists q_qr_token_registration add column if not exists application_url 		text;

CREATE TABLE if not exists q_qr_token_registration (
	  token_registration_id 	uuid default uuid_generate_v4() not null primary key
	, description				text not null
	, role_name 				text not null
	, client_id 				uuid 	-- if not null then the user will be created with client_id
	, admin_email				text
	, application_url			text	-- Taken from the 'application_url' priv in the privlates of the role name? -- if null then 'http://localhost:8080' (gCfg.BaseServerURL)
	, is_one_time				varchar(1) default 'n' not null
	, email_note				text	-- If for a specific email address then the email is listed (not requried)
	, updated 					timestamp
	, created 					timestamp default current_timestamp not null
);
comment on table q_qr_token_registration is 'Configured token based registration - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';

DO $$
BEGIN
	BEGIN
		-- ALTER TABLE q_qr_token_registration drop CONSTRAINT if exists q_qr_token_registration_fk1 ;
		ALTER TABLE q_qr_token_registration
			ADD CONSTRAINT q_qr_token_registration_fk1
			FOREIGN KEY (role_name)
			REFERENCES q_qr_role2(role_name)
			;
	EXCEPTION
		WHEN duplicate_table THEN	-- postgres raises duplicate_table at surprising times. Ex.: for UNIQUE constraints.
		WHEN duplicate_object THEN
			RAISE NOTICE 'Table constraint q_qr_token_registration already exists';
	END;
END $$;


m4_updTrig(q_qr_token_registration)










-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- xyzzy921 - Create trigger to track the changes in q_qr_token_registration
--
-- This is all the used rows in q_qr_token_registration
-- If is_one_time=='n', then the original row is still in q_qr_token_registration
--
-- Log this info into the security log stuff also via trigger.
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

CREATE TABLE if not exists q_qr_token_registration_hist (
	  token_registration_hist_id 	uuid default uuid_generate_v4() not null primary key
	, event						text not null default 'insert'
	, when_occured				timestamp default current_timestamp not null
	, token_registration_id 	uuid not null
	, description				text not null
	, role_name 				text not null
	, client_id 				uuid 	-- if not null then the user will be created with client_id
	, is_one_time				varchar(1) default 'n' not null
	, email_note				text	-- If for a specific email address then the email is listed (not requried)
	, updated 					timestamp
	, created 					timestamp default current_timestamp not null
);

comment on table q_qr_token_registration_hist is 'Token history for registration - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';






CREATE OR REPLACE FUNCTION q_qr_token_registration_hist_upd() RETURNS trigger
AS $$
BEGIN
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	insert into q_qr_token_registration_hist (
		  event
		, token_registration_id
		, description
		, role_name
		, client_id
		, is_one_time
		, email_note
		, updated
		, created
	) values (
		  'update'
		, NEW.token_registration_id
		, NEW.updated
		, NEW.description
		, NEW.role_name
		, NEW.client_id
		, NEW.is_one_time
		, NEW.email_note
		, NEW.updated
		, NEW.created
	);
	RETURN NEW;
END
$$ LANGUAGE 'plpgsql';


DROP TRIGGER if exists q_qr_token_registration_hist_upd_trig
	ON "q_qr_token_registration"
	;

CREATE TRIGGER q_qr_token_registration_hist_upd_trig
	BEFORE update ON "q_qr_token_registration"
	FOR EACH ROW
	EXECUTE PROCEDURE q_qr_token_registration_hist_upd()
	;







CREATE OR REPLACE FUNCTION q_qr_token_registration_hist_del() RETURNS trigger
AS $$
BEGIN
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	insert into q_qr_token_registration_hist (
		  event
		, token_registration_id
		, description
		, role_name
		, client_id
		, is_one_time
		, email_note
		, updated
		, created
	) values (
		  'delete'
		, OLD.token_registration_id
		, OLD.description
		, OLD.role_name
		, OLD.client_id
		, OLD.is_one_time
		, OLD.email_note
		, OLD.updated
		, OLD.created
	);
	RETURN OLD;
END
$$ LANGUAGE 'plpgsql';


DROP TRIGGER if exists q_qr_token_registration_hist_del_trig
	ON "q_qr_token_registration"
	;

CREATE TRIGGER q_qr_token_registration_hist_del_trig
	BEFORE delete ON "q_qr_token_registration"
	FOR EACH ROW
	EXECUTE PROCEDURE q_qr_token_registration_hist_del()
	;








CREATE OR REPLACE FUNCTION q_qr_token_registration_hist_ins() RETURNS trigger
AS $$
BEGIN
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	insert into q_qr_token_registration_hist (
		  event
		, token_registration_id
		, description
		, role_name
		, client_id
		, is_one_time
		, email_note
		, updated
		, created
	) values (
		  'insert'
		, NEW.token_registration_id
		, NEW.description
		, NEW.role_name
		, NEW.client_id
		, NEW.is_one_time
		, NEW.email_note
		, NEW.updated
		, NEW.created
	);
	RETURN OLD;
END
$$ LANGUAGE 'plpgsql';


DROP TRIGGER if exists q_qr_token_registration_hist_ins_trig
	ON "q_qr_token_registration"
	;

CREATE TRIGGER q_qr_token_registration_hist_ins_trig
	AFTER insert ON "q_qr_token_registration"
	FOR EACH ROW
	EXECUTE PROCEDURE q_qr_token_registration_hist_ins()
	;




























-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- client table / token_registration
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
alter table if exists q_qr_client add column if not exists client_email text;
alter table if exists q_qr_client add column if not exists designated_user_id uuid;
alter table if exists q_qr_client add column if not exists token_registration_id	uuid;
alter table if exists q_qr_client add column if not exists client_config			text;		-- JSON data thatis config per-client

CREATE TABLE if not exists q_qr_client (
	  client_id 			uuid default uuid_generate_v4() not null primary key
	, client_name			text not null
	, client_email 			text				-- for email dropdown list
	, designated_user_id 	uuid
	, token_registration_id	uuid
	, client_config			text		-- JSON data thatis config per-client
	, updated 				timestamp
	, created 				timestamp default current_timestamp not null
);
comment on table q_qr_client is 'List of clients - Copyright (C) Philip Schlump, 2008-2023. -- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()';

create unique index if not exists  q_qr_client_u1 on q_qr_client ( client_name );

m4_updTrig(q_qr_client)








create unique index if not exists q_qr_client_u1 on q_qr_client ( client_name );
create unique index if not exists q_qr_client_u2 on q_qr_client ( client_email );
create unique index if not exists q_qr_client_u3 on q_qr_client ( designated_user_id );
create unique index if not exists q_qr_client_u4 on q_qr_client ( token_registration_id );







-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- drop function q_admin_create_token_registration ( p_description varchar, p_client_id varchar, p_role_name varchar, p_hmac_password varchar, p_userdata_password varchar );
CREATE OR REPLACE FUNCTION q_admin_create_token_registration ( p_description varchar, p_client_id varchar, p_role_name varchar, p_email_note varchar, p_user_id uuid, p_admin_email varchar, p_application_url varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data 						text;
	l_found 					text;
	l_fail 						bool;
	l_debug_on 					bool;
	l_token_registration_id		uuid;
	l_client_id					uuid;
	l_email_note				text;
	l_application_url			text;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';
	l_application_url = p_application_url;

	if l_debug_on then
		insert into t_output ( msg ) values ( 'In q_admin_create_token_registration' );
		insert into t_output ( msg ) values ( '  p_description ->'||coalesce(to_json(p_description)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_role_name ->'||coalesce(to_json(p_role_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_client_id ->'||coalesce(to_json(p_client_id)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_email_note ->'||coalesce(to_json(p_email_note)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_admin_email ->'||coalesce(to_json(p_admin_email)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_application_url ->'||coalesce(to_json(p_application_url)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	--	// ------------------------------ xyzzy ---------------------------------------------------------
	--	//
	--	// Check role for logged in user.
	--	//
	--	// May Create User With:<Role> must exist for this user to create a role of this type.
	--	//
	--	// ----------------------------------------------------------------------------------------------
	if not ( q_admin_HasPriv ( p_user_id, 'Item Client Admin' ) ) then
		l_fail = true;
		l_data = '{"status":"error","msg":"Not authorized to ''Item Client Admin''","code":"m4_count()","location":"m4___file__ m4___line__"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( p_user_id::uuid, 'Not authorized to ''Item Client Admin''', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
	end if;

	-- xyzzy TODO - Add check at this point for recursive role

	if not l_fail then
		select application_url
			into l_found
			from q_qr_role_name_application_url
			where role_name = p_role_name
			;
		if found then
			l_application_url = l_found;
		end if;
	end if;

	if not l_fail then

		if p_client_id is null or p_client_id = '' then
			l_client_id = null;
			-- insert into q_qr_token_registration ( description, role_name, is_one_time ) values ( p_description, p_role_name, 'y' )
			-- 	returning token_registration_id into l_token_registration_id ;
		else
			l_client_id = p_client_id::uuid;
			--insert into q_qr_token_registration ( description, role_name, client_id, is_one_time ) values ( p_description, p_role_name, p_client_id::uuid, 'y' )
			--	returning token_registration_id into l_token_registration_id ;
		end if;
		if p_email_note is null or p_email_note = '' then
			l_email_note = null;
		else
			l_email_note = p_email_note;
		end if;
		if l_debug_on then
			insert into t_output ( msg ) values ( 'In q_admin_create_token_registration' );
			insert into t_output ( msg ) values ( '  l_client_id ->'||coalesce(to_json(l_client_id)::text,'---null---')||'<-');
			insert into t_output ( msg ) values ( '  l_email_note ->'||coalesce(to_json(l_email_note)::text,'---null---')||'<-');
			insert into t_output ( msg ) values ( '  l_application_url ->'||coalesce(to_json(l_application_url)::text,'---null---')||'<-');
			insert into t_output ( msg ) values ( '  ' );
		end if;

		insert into q_qr_token_registration (
				description,
				role_name,
				client_id,
				is_one_time,
				email_note,
				admin_email,
				application_url
			) values (
				p_description,
				p_role_name,
				l_client_id,
				'y',
				l_email_note,
				p_admin_email,
				l_application_url
			) returning token_registration_id into l_token_registration_id ;

	end if;

	if not l_fail then
		-- login_token=$( cat create_token.out | jq .registration_token | sed -e 's/"//g' )

		l_data = '{"status":"success"'
			||', "client_id":' 					||coalesce(to_json(l_client_id)::text,'""')
			||', "registration_token":' 		||coalesce(to_json(l_token_registration_id)::text,'""')
			||'}';

	end if;

	if l_debug_on then
		insert into t_output ( msg ) values ( 'In q_admin_create_token_registration - at bottom' );
		insert into t_output ( msg ) values ( '  l_data ->'||coalesce(to_json(l_data)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;










-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- drop function q_admin_create_client ( p_client_name varchar, p_description varchar, p_role_name varchar, p_hmac_password varchar, p_userdata_password varchar );
drop function if exists q_admin_create_client ( p_client_name varchar, p_description varchar, p_role_name varchar, p_user_id uuid, p_hmac_password varchar, p_userdata_password varchar );

CREATE OR REPLACE FUNCTION q_admin_create_client ( p_client_name varchar, p_description varchar, p_role_name varchar, p_email_addr varchar, p_user_id uuid, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data 				text;
	l_found 			text;
	l_fail 				bool;
	l_debug_on 			bool;
	l_status 			text;
	l_role_name 		text;
	l_client_id			uuid;
	l_token_registration_id			uuid;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if p_role_name is null or p_role_name = '' then
		l_role_name = 'role:item-client-user';
	else
		l_role_name = p_role_name;
	end if;

	if l_debug_on then
		insert into t_output ( msg ) values ( 'In q_admin_create_client' );
		insert into t_output ( msg ) values ( '  p_client_name ->'||coalesce(to_json(p_client_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_description ->'||coalesce(to_json(p_description)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_role_name ->'||coalesce(to_json(l_role_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_email_addr ->'||coalesce(to_json(p_email_addr)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_user_id ->'||coalesce(to_json(p_user_id)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	if not ( q_admin_HasPriv ( p_user_id, 'Item Client Admin' ) ) then
		l_fail = true;
		l_data = '{"status":"error","msg":"Not authorized to ''Item Client Admin''","code":"m4_count()","location":"m4___file__ m4___line__"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( p_user_id, 'Not authorized to ''Item Admin|n''', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
	end if;

	l_client_id = uuid_generate_v4();

	if not l_fail then

		-- function q_admin_create_token_registration ( p_description varchar, p_client_id varchar, p_role_name varchar, p_email_note varchar, p_user_id uuid, p_hmac_password varchar, p_userdata_password varchar )
		select q_admin_create_token_registration ( p_description, l_client_id::text, l_role_name, p_email_addr,  p_user_id, p_hmac_password, p_userdata_password )
			into l_data;

		select l_data::jsonb -> 'status' into l_status;
		if l_status != '"success"' then
			l_fail := true;
		else
			select l_data::jsonb ->> 'token_registration_id' into l_token_registration_id;
		end if;

	end if;

	if not l_fail then

		-- error block for dups!
		BEGIN
			insert into q_qr_client ( client_id, client_name, client_email, token_registration_id ) values ( l_client_id, p_client_name, p_email_addr, l_token_registration_id );
		EXCEPTION WHEN unique_violation THEN
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to create client - duplicate client name.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( p_user_id, 'Unable to create - duplicate client name', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		END;

	end if;


	if not l_fail then

		l_data = '{"status":"success"'
			||', "client_id":' 					||coalesce(to_json(l_client_id)::text,'""')
			||', "registration_token":' 		||coalesce(to_json(l_token_registration_id)::text,'""')
			||'}';

	end if;

	if l_debug_on then
		insert into t_output ( msg ) values ( 'In q_admin_create_client - at bottom' );
		insert into t_output ( msg ) values ( '  l_data ->'||coalesce(to_json(l_data)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;














-- stmt := "q_admin_get_registration_token ( $1, $2, $3 )"
-- RegistrationToken string `json:"registration_token,omitempty"`

CREATE OR REPLACE FUNCTION q_admin_get_registration_token (  p_user_id uuid, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data 				text;
	l_found 			text;
	l_fail 				bool;
	l_debug_on 			bool;
	l_status 			text;
	l_role_name 		text;
	l_client_id			uuid;
	l_the_token uuid;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'In q_admin_get_registration_token' );
		insert into t_output ( msg ) values ( '  ' );
	end if;

	if not ( q_admin_HasPriv ( p_user_id, 'Item Client Admin' ) ) then
		l_fail = true;
		l_data = '{"status":"error","msg":"Not authorized to ''Item Client Admin''","code":"m4_count()","location":"m4___file__ m4___line__"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( p_user_id, 'Not authorized to ''Item Admin|Item Client Admin''', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
	end if;

	if not l_fail then

		select token_registration_id
			into l_the_token
			from q_qr_token_registration
			;

		if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to find token.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( p_user_id, 'Unable to find token.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;

	end if;

	if not l_fail then

		l_data = '{"status":"success"'
			||', "token_registration":' 		||coalesce(to_json(l_the_token)::text,'""')
			||'}';

	end if;

	if l_debug_on then
		insert into t_output ( msg ) values ( 'In q_admin_create_client - at bottom' );
		insert into t_output ( msg ) values ( '  l_data ->'||coalesce(to_json(l_data)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;

















































drop function if exists q_admin_add_priv_to_role ( p_role_id uuid, p_priv_id varchar );
drop function if exists q_admin_remove_priv_from_role ( p_role_id uuid, p_priv_id varchar );
drop function if exists q_auth_v1_add_priv_to_user ( p_email varchar, p_priv varchar, p_hmac_password varchar, p_userdata_password varchar);
drop function if exists q_auth_v1_rm_priv_from_user ( p_email varchar, p_priv varchar, p_hmac_password varchar, p_userdata_password varchar);





















-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- 1. q_auth_v1_recover_password_01_setup -> change d.b. - return token. -- (( Indirctly sends email ))
CREATE OR REPLACE FUNCTION q_auth_v1_recover_password_01_setup ( p_email varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_first_name			text;
	l_last_name				text;
	l_fail					bool;
	l_recovery_token		uuid;
	v_cnt 					int;
	l_user_id				uuid;
	l_email_hmac			bytea;
	l_n6_flag				text;
	l_recovery_token_n6		text;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_recovery_token		= uuid_generate_v4();
	l_recovery_token_n6		= l_recovery_token::text;


	if not l_fail then

		l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );
		with user_row as (
			select
				  user_id
				, pgp_sym_decrypt(first_name_enc,p_userdata_password)::text as first_name
				, pgp_sym_decrypt(last_name_enc,p_userdata_password)::text as last_name
				, email_hmac
				, parent_user_id
				, account_type
				, start_date
				, end_date
				, email_validated
				, setup_complete_2fa
				, require_2fa
				, n6_flag
			from q_qr_users as t1
			where t1.email_hmac = l_email_hmac
		)
		select
			  user_id
		    , first_name
		    , last_name
			, n6_flag
		into
			  l_user_id
			, l_first_name
			, l_last_name
			, l_n6_flag
		from user_row
		where parent_user_id is null
		  and account_type = 'login'
		  and ( start_date < current_timestamp or start_date is null )
		  and ( end_date > current_timestamp or end_date is null )
		  and email_validated = 'y'
		  and ( setup_complete_2fa = 'y' or require_2fa = 'n' )
		for update
		;
		if not found then

			l_fail = true;
			l_data = '{"status":"error","msg":"Account not valided or email not validated.","code":"m4_count()","location":"m4___file__ m4___line__"}';

			-- Select to get l_user_id for email.  If it is not found above then this may not be a fully setup user.
			-- The l_user_id is used below in a delete to prevent marking of devices as having been seen.
			select user_id
				into l_user_id
				from q_qr_users as t1
				where t1.email_hmac = l_email_hmac
				;

			if not found then
				l_fail = true;
				l_data = '{"status":"error","msg":"Invalid Username / Invalid account.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			end if;

		end if;
	end if;

	if not l_fail then
		-- Delete all the id.json rows for this user - every marked device will need to 2fa after this request.
		delete from q_qr_device_track where user_id = l_user_id;
	end if;

	if not l_fail then
		update q_qr_users as t1
			set
				  password_reset_token = l_recovery_token
				, password_reset_time = current_timestamp + interval '1 hours'
			where t1.user_id = l_user_id
			;
		-- check # of rows.
		GET DIAGNOSTICS v_cnt = ROW_COUNT;
		if v_cnt != 1 then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or email not validated","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or email not validated', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;

		if l_n6_flag = 'n6' or l_n6_flag = 'n8' then
			l_recovery_token_n6 = q_auth_v1_n6_email_validate ( l_recovery_token, l_n6_flag );
		else
			l_recovery_token_n6 = l_recovery_token;
		end if;

	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "recovery_token":'   	||coalesce(to_json(l_recovery_token)::text,'""')
			||', "recovery_token_n6":'	||coalesce(to_json(l_recovery_token_n6)::text,'""')
			||', "first_name":'   		||coalesce(to_json(l_first_name)::text,'""')
			||', "last_name":'   		||coalesce(to_json(l_last_name)::text,'""')
			||', "n6_flag":'   			||coalesce(to_json(l_n6_flag)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;








-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--    q_auth_v1_recover_password_02_fetch_info -- Take token to get info about user - see if token is valid.
CREATE OR REPLACE FUNCTION q_auth_v1_recover_password_02_fetch_info ( p_email varchar, p_recovery_token varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_tmp					text;
	l_user_id				uuid;
	l_first_name			text;
	l_last_name				text;
	l_email					text;
	l_recovery_token		uuid;
	l_email_hmac			bytea;
	l_require_2fa			text;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';
	-- m4_coverage_point()

	if not l_fail then
		-- m4_comment([[[ (fixed) xyzzy-Slow!! - better to do select count - and verify where before update. ]]])
		l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );
		with user_row as (
			select
				  user_id
				, pgp_sym_decrypt(first_name_enc,p_userdata_password)::text as first_name
				, pgp_sym_decrypt(last_name_enc,p_userdata_password)::text as last_name
				, pgp_sym_decrypt(email_enc::bytea,p_userdata_password)::text email
				, password_reset_token
				, parent_user_id
				, account_type
				, start_date
				, end_date
				, email_validated
				, setup_complete_2fa
				, require_2fa
			from q_qr_users as t0
			where t0.email_hmac = l_email_hmac
		)
		select
			  user_id
		    , first_name
		    , last_name
		    , email
			, require_2fa
		into
			  l_user_id
			, l_first_name
			, l_last_name
			, l_email
			, l_require_2fa
		from user_row as t1
		where password_reset_token = p_recovery_token::uuid
		  and parent_user_id is null
		  and account_type = 'login'
		  and ( start_date < current_timestamp or t1.start_date is null )
		  and ( end_date > current_timestamp or t1.end_date is null )
		  and email_validated = 'y'
		  and ( setup_complete_2fa = 'y' or require_2fa = 'n' )
		;
		if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or email not validated","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or email not validated', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "email":'   	||coalesce(to_json(l_email)::text,'""')
			||', "first_name":'  ||coalesce(to_json(l_first_name)::text,'""')
			||', "last_name":'  ||coalesce(to_json(l_last_name)::text,'""')
			||', "require_2fa":' 	  ||coalesce(to_json(l_require_2fa)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;









-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--    q_auth_v1_recover_password_03_set_password -- Take token and new password - set it.
CREATE OR REPLACE FUNCTION q_auth_v1_recover_password_03_set_password ( p_email varchar, p_new_pw varchar, p_recovery_token varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	v_cnt 					int;
	l_user_id				uuid;
	l_first_name			text;
	l_last_name				text;
	l_email_hmac			bytea;
	l_n6_flag				text;
	l_password_reset_token 	uuid;
	l_recovery_token	 	uuid;
	l_n6_token 				int;
	l_debug_on 				bool;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';
	l_debug_on = q_get_config_bool ( 'debug' );

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_recover_password_03_set_password<- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '  p_email ->'||coalesce(to_json(p_email)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_new_pw ->'||coalesce(to_json(p_new_pw)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_recovery_token ->'||coalesce(to_json(p_recovery_token)::text,'---null---')||'<-');
	end if;

	if not l_fail then
		-- (fixed) xyzzy-Slow!! - better to do select count - and verify where before update.
		l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );
		with user_row as (
			select
				  user_id
				, pgp_sym_decrypt(first_name_enc,p_userdata_password)::text as first_name
				, pgp_sym_decrypt(last_name_enc,p_userdata_password)::text as last_name
				, password_reset_time
				, password_reset_token
				, account_type
				, start_date
				, end_date
				, email_validated
				, setup_complete_2fa
				, parent_user_id
				, require_2fa
				, n6_flag
			from q_qr_users as t0
			where t0.email_hmac = l_email_hmac
		)
		select
			  user_id
		    , first_name
		    , last_name
			, password_reset_token
			, n6_flag
		into
			  l_user_id
			, l_first_name
			, l_last_name
			, l_password_reset_token
			, l_n6_flag
		from user_row as t1
		where password_reset_time > current_timestamp
		  and account_type = 'login'
		  and ( start_date < current_timestamp or t1.start_date is null )
		  and ( end_date > current_timestamp or t1.end_date is null )
		  and email_validated = 'y'
		  and ( setup_complete_2fa = 'y' or require_2fa = 'n' )
		  and parent_user_id is null
		for update
		;
		if not found then
			-- xyzzy-Fix-Error-Message-to-be-clear
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Account Not Valid or Email Not Validated, or Password Reset Time Window (1 hour) has expired.  Please resend the email and retry the process.","code":"m4_count()","location":"m4___file__ m4___line__"}';
		end if;
		begin
			l_recovery_token = p_recovery_token::uuid;
			l_n6_flag = '';	-- if we can convert to UUID then n6 is irrelevant
		exception
			when others then
				l_n6_flag = 'n6';
		end;
		-- insert into t_output ( msg ) values ( '  l_recovery_token ->'||coalesce(to_json(l_recovery_token)::text,'---null---')||'<-');
		-- insert into t_output ( msg ) values ( '  l_n6_flag ->'||coalesce(to_json(l_n6_flag)::text,'---null---')||'<-');
		if l_n6_flag = 'n6' or l_n6_flag = 'n8' then
			begin
				l_n6_token = p_recovery_token::int;
			exception
				when others then
					l_fail = true;
					l_data = '{"status":"error","msg":"Incorrect data for token, should be a number.  Please resend the email and retry the process.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			end;
			-- insert into t_output ( msg ) values ( '  l_n6_token ->'||coalesce(to_json(l_n6_token)::text,'---null---')||'<-');
			if not l_fail then
				select email_verify_token
					into l_recovery_token
					from q_qr_n6_email_verify
					where n6_token = l_n6_token
					;
				if not found then
					l_fail = true;
					l_data = '{"status":"error","msg":"Invalid Password Reset Token.  Please resend the email and retry the process.","code":"m4_count()","location":"m4___file__ m4___line__"}';
				end if;
				-- insert into t_output ( msg ) values ( '  l_recovery_token (2) ->'||coalesce(to_json(l_recovery_token)::text,'---null---')||'<-');
			end if;
		end if;
		if not l_fail then
			-- insert into t_output ( msg ) values ( 'not fail, check to see if tokens match' );
			-- insert into t_output ( msg ) values ( '  l_password_reset_token ->'||coalesce(to_json(l_password_reset_token)::text,'---null---')||'<-');
			-- insert into t_output ( msg ) values ( '  l_recovery_token ->'||coalesce(to_json(l_recovery_token)::text,'---null---')||'<-');
			if l_password_reset_token <> l_recovery_token then
				l_fail = true;
				l_data = '{"status":"error","msg":"Invalid Password Reset Token.  Please resend the email and retry the process.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			end if;
		end if;
	end if;

	-- insert into t_output ( msg ) values ( '  l_n6_flag ->'||coalesce(to_json(l_n6_flag)::text,'---null---')||'<-');
	-- insert into t_output ( msg ) values ( '  l_fail ->'||coalesce(to_json(l_fail)::text,'---null---')||'<-');

	if not l_fail then
		insert into t_output ( msg ) values ( '  l_user_id ->'||coalesce(to_json(l_user_id)::text,'---null---')||'<-');
		update q_qr_users as t1
			set
				  password_reset_token = null
				, password_reset_time = null
				, password_hash = crypt(p_new_pw, gen_salt('bf') )
			where t1.user_id = l_user_id
			;
		-- check # of rows.
		GET DIAGNOSTICS v_cnt = ROW_COUNT;
		if v_cnt != 1 then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or email not validated","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or email not validated', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "recovery_token":'   ||coalesce(to_json(p_recovery_token)::text,'""')
			||', "first_name":'       ||coalesce(to_json(l_first_name)::text,'""')
			||', "last_name":'        ||coalesce(to_json(l_last_name)::text,'""')
			||'}';
	end if;


	RETURN l_data;
END;
$$ LANGUAGE plpgsql;







CREATE SEQUENCE if not exists t_deleted_acct_seq
  INCREMENT 1
  MINVALUE 1
  MAXVALUE 9223372036854775807
  START 1
  CACHE 1;




-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION q_auth_v1_delete_account ( p_email varchar, p_pw varchar, p_hmac_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	v_cnt 					int;
	l_user_id				uuid;
	l_email_hmac			bytea;
	l_first_name			text;
	l_last_name				text;
	l_x_email				text;
	l_x_pw					text;
	l_seq					text;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	SELECT nextval('t_deleted_acct_seq'::regclass)::text INTO l_seq;

	l_x_email = 'deleted:'||l_seq||':'||p_email;
	l_x_pw	  = uuid_generate_v4();

	if not l_fail then
		-- (fixed) xyzzy-Slow!! - better to do select count - and verify where before update.
		l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );
		with user_row as (
			select
				  user_id
				, pgp_sym_decrypt(first_name_enc,p_userdata_password)::text as first_name
				, pgp_sym_decrypt(last_name_enc,p_userdata_password)::text as last_name
				, account_type
				, password_hash
				, parent_user_id
				, validation_method
				, require_2fa
			from q_qr_users as t1
			where t1.email_hmac = l_email_hmac
		)
		select user_id
				, first_name
				, last_name
			into l_user_id
				, l_first_name
				, l_last_name
			from user_row
			where
					(
							account_type = 'login'
						and password_hash = crypt(p_pw, password_hash)
						and parent_user_id is null
						and validation_method = 'un/pw'
					)  or (
							account_type = 'login'
						and password_hash = '*'
						and parent_user_id is null
						and validation_method in ( 'sip', 'srp6a' )
					)  or (
							account_type = 'un/pw'
						and password_hash = crypt(p_pw, password_hash)
						and parent_user_id is not null
					)  or (
							account_type = 'token'
						and parent_user_id is not null
					)  or (
							account_type = 'sso'
						and parent_user_id is not null
					)
			for update
			;
		if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or email not validated","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or email not validated', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;
		if not l_fail then
			update q_qr_users as t1
				set
						start_date = current_timestamp + interval '50 years'
					  , end_date = current_timestamp - interval '1 minute'
					  , email_hmac = q_auth_v1_hmac_encode ( l_x_email, p_hmac_password )
					  , email_enc = pgp_sym_encrypt( l_x_email, p_userdata_password)
					  , password_hash = crypt( l_x_pw, gen_salt('bf') )
				where t1.user_id = l_user_id
				;
			-- check # of rows.
			GET DIAGNOSTICS v_cnt = ROW_COUNT;
			if v_cnt != 1 then
				l_fail = true;
				l_data = '{"status":"error","msg":"Invalid Username or Account not valid or email not validated","code":"m4_count()","location":"m4___file__ m4___line__"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or email not validated', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
			end if;
		end if;
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "first_name":'  	||coalesce(to_json(l_first_name)::text,'""')
			||', "last_name":'   	||coalesce(to_json(l_last_name)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;













-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--
-- 	{
-- 		CrudBaseConfig: table_crud.CrudBaseConfig{
-- 			URIPath:       "/api/table/user5",
-- 			JWTKey:        true,
-- 			TableNameList: []string{"q_qr_users"}, // not really the table that is used.
-- 			ParameterList: []table_crud.ParamListItem{
-- 				{ReqVar: "aaa", ParamName: "p_aaa"},
-- 				{ReqVar: "__user_id__", ParamName: "p_user_id"},
-- 				{ReqVar: "__email_hmac_password__", ParamName: "p_hmac_password"},
-- 				{ReqVar: "__user_password__", ParamName: "p_userdata_password"},
-- 			},
-- 			POST_InputList: []*table_crud.MuxInput{ // Validation of inputs for htis call
-- 				{Name: "aaa", Required: true, Label: "Aaa", MinLen: 1, Type: "s"},
-- 			},
-- 			EncryptPat: "e", // Refers to ParameterList
-- 		},
-- 		StoredProcedureName: "u_test_proc_call",
-- 		CallAuthPrivs:       []string{"May Register"}, // Calls HasPriv (requries JWTKey be true)
-- 	},
CREATE OR REPLACE FUNCTION u_test_proc_call ( p_aaa varchar, p_user_id varchar, p_hmac_password varchar, p_userdata_password varchar) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_junk					text;
	l_fail					bool;
	l_debug_on 				bool;
	l_user_id				uuid;
	l_role_id				uuid;
	l_user_role_id			uuid;
	l_priv_id				uuid;
	l_role_priv_id			uuid;
	l_user_priv_id			uuid;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if not l_fail then

		l_data = '{"status":"success"'
			-- ||', "user_id":' 			||coalesce(to_json(l_user_id)::text,'""')
			||'}';

		if l_debug_on then
			insert into t_output ( msg ) values ( ' l_data= '||l_data );
		end if;

	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;





-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- xyzzy99 - add 8th param -- {Method: "GET", Path: "/api/v1/auth/email-confirm", Fx: authHandlerEmailConfirm, UseLogin: PublicApiCall},                                    // token
-- xyzzy99 if n6 - 6 digit random returned by call
-- SELECT random();
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--
--CREATE TABLE if not exists q_qr_n6_email_verify (
--	n6_token 				int not null,
--	email_verify_token		uuid not null
--);
--
--CREATE UNIQUE INDEX if not exists  q_qr_n6_email_verify_u1 on q_qr_n6_email_verify ( n6_token );
--CREATE INDEX if not exists  q_qr_n6_email_verify_p1 on q_qr_n6_email_verify ( email_verify_token );

CREATE OR REPLACE FUNCTION q_auth_v1_n6_email_validate ( p_email_verify_token uuid, p_flag varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_debug_on 				bool;
	l_ran					int;
	l_done					bool;
	l_junk					text;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	if p_flag = 'n6' then

		l_done = false;

		while not l_done loop

			-- Generate random number
			select (random()*1000000)::int
				into l_ran;

			select 'found'
				into l_junk
				from q_qr_n6_email_verify
				where n6_token = l_ran
				;

			if not found then
				insert into q_qr_n6_email_verify ( n6_token, email_verify_token ) values ( l_ran, p_email_verify_token );
				l_done = true;
				l_data = LPAD(l_ran::text, 6, '0');
			end if;

		end loop;

	elsif p_flag = 'n8' then

		l_done = false;

		while not l_done loop

			-- Generate random number
			select (random()*100000000)::int
				into l_ran;

			select 'found'
				into l_junk
				from q_qr_n6_email_verify
				where n6_token = l_ran
				;

			if not found then
				insert into q_qr_n6_email_verify ( n6_token, email_verify_token ) values ( l_ran, p_email_verify_token );
				l_done = true;
				l_data = LPAD(l_ran::text, 8, '0');
			end if;

		end loop;

	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;





-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Example Call
--		select q_auth_v1_register ( 'bob41@client.com','abcdefghij','my long secret password','Mr','Bob Bob','user info password','SQLGRLVK47BGDJWK' );
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
DROP FUNCTION if exists q_auth_v1_register ( p_email varchar, p_pw varchar, p_hmac_password varchar, p_first_name varchar, p_last_name varchar, p_userdata_password varchar, p_secret varchar ) ;
DROP FUNCTION if exists q_auth_v1_register ( p_email varchar, p_pw varchar, p_hmac_password varchar, p_first_name varchar, p_last_name varchar, p_userdata_password varchar, p_secret varchar, p_n6_flag varchar ) ;


--                                              1                2             3                        4                     5                    6                            7                 8                  9                     10
CREATE OR REPLACE FUNCTION q_auth_v1_register ( p_email varchar, p_pw varchar, p_hmac_password varchar, p_first_name varchar, p_last_name varchar, p_userdata_password varchar, p_secret varchar, p_n6_flag varchar, p_agree_eula varchar, p_agree_tos varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_junk					text;
	l_fail					bool;
	l_user_id				uuid;
	l_bad_user_id			uuid;
	l_email_verify_token	uuid;
	l_tmp 					varchar(40);
	l_secret_2fa 			varchar(20);
	l_debug_on 				bool;
	l_auth_token			uuid;
	l_tmp_token				uuid;
	ii						int;
	l_otp_str				text;
	l_otp_com				text;
	l_privs					text;
	l_email_hmac			bytea;
	l_user_config			jsonb;
	l_require_2fa_bool 		bool;
	l_require_2fa 			varchar(1);
	l_admin_email			text;
	l_n6					text;
	v_cnt 					int;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );
	l_admin_email = q_get_config ( 'admin.user' );

	l_require_2fa 			= 'y';
	l_require_2fa_bool = q_get_config_bool_dflt ( 'use.2fa', true );
	if l_require_2fa_bool then
		l_require_2fa 			= 'y';
	else
		l_require_2fa 			= 'n';
	end if;

	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_email_verify_token = uuid_generate_v4();
	l_n6 = '000000';
	if p_n6_flag = 'n6' then
		l_n6 = q_auth_v1_n6_email_validate ( l_email_verify_token , p_n6_flag );
	end if;

	-- l_tmp = uuid_generate_v4()::text;
	-- l_secret_2fa = substr(l_tmp,0,7) || substr(l_tmp,10,4);
	l_secret_2fa = p_secret;

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_register<- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '  p_email ->'||coalesce(to_json(p_email)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_pw ->'||coalesce(to_json(p_pw)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||coalesce(to_json(p_hmac_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_first_name ->'||coalesce(to_json(p_first_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_last_name ->'||coalesce(to_json(p_last_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_userdata_password ->'||coalesce(to_json(p_userdata_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_secret ->'||coalesce(to_json(p_secret)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_require_2fa ->'||coalesce(to_json(l_require_2fa)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_n6_flag ->'||coalesce(to_json(p_n6_flag)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_n6 ->'||coalesce(to_json(l_n6)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_agree_tos ->'||coalesce(to_json(p_agree_tos)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_agree_eula ->'||coalesce(to_json(p_agree_eula)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	if not l_fail then

		select json_agg(t0.priv_name)::text
		into l_privs
		from (
			select json_object_keys(t1.allowed::json)::text  as priv_name
				from q_qr_role2 as t1
				where t1.role_name =  'role:user'
			) as t0
			;
		if not found then
			if l_debug_on then
				insert into t_output ( msg ) values ( 'Failed to get the privileges for the user' );
			end if;
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to get privileges for the user.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			l_privs = '';
		end if;
		if l_debug_on then
			insert into t_output ( msg ) values ( 'calculate l_privs ->'||coalesce(to_json(l_privs)::text,'---null---')||'<-');
		end if;

	end if;

	if not l_fail then
		-- create table if not exists q_qr_user_config_default (
		select value
			into l_user_config
			from q_qr_user_config_default
			where role_name = 'role:user'
			;
		if not found or l_user_config is null then
			l_user_config = '{}'::jsonb;
		end if;

	end if;


	-- Cleanup any users that have expired tokens.
	-- !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	-- !!!! race condition !!!!
	-- !!!! tranactional error !!!!
	-- !!!! Possibilities...
	--	1. if password is same and 0 login, then should just update account (set n,n)
	--	2. if y,n or n,y, then should just update account
	--	3. else - error
	-- !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );
	select q_auth_v1_delete_user ( user_id )
		into l_junk
		from q_qr_users as t1
		where t1.email_hmac = l_email_hmac
		  and t1.login_success = 0
		;
	select user_id
		into l_bad_user_id
		from q_qr_users as t1
		where t1.email_hmac = l_email_hmac
		;
	if found then
		l_fail = true;
		l_data = '{"status":"error","msg":"Account already exists.  Please login or recover password.","code":"m4_count()","location":"m4___file__ m4___line__"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_bad_user_id, 'User Attempt to Re-Register Same Account.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
	end if;


	if not l_fail then

		INSERT INTO q_qr_users (
			  email_hmac
			, email_enc
			, password_hash
			, email_verify_token
			, email_verify_expire
			, secret_2fa
			, first_name_enc
			, first_name_hmac
			, last_name_enc
			, last_name_hmac
			, privileges
			, pdf_enc_password
			, x_user_config
			, require_2fa
			, role_name
			, n6_flag
		) VALUES (
		 	  q_auth_v1_hmac_encode ( p_email, p_hmac_password )
		    , pgp_sym_encrypt(p_email, p_userdata_password)
			, crypt(p_pw, gen_salt('bf') )
			, l_email_verify_token
			, current_timestamp + interval '1 day'
			, l_secret_2fa
		    , pgp_sym_encrypt(p_first_name,p_userdata_password)
		 	, q_auth_v1_hmac_encode ( lower(p_first_name), p_hmac_password )
		    , pgp_sym_encrypt(p_last_name,p_userdata_password)
		 	, q_auth_v1_hmac_encode ( lower(p_last_name), p_hmac_password )
			, l_privs
			, q_auth_v1_hmac_encode ( p_userdata_password || '::' || p_pw || '::' || lower(p_first_name) || ' ' || lower(p_last_name), p_hmac_password )
			, l_user_config
			, l_require_2fa
			, 'role:user'
			, l_n6
		) returning user_id into l_user_id  ;

		if l_debug_on then
			insert into t_output ( msg ) values ( '  l_user_id ->'||coalesce(to_json(l_user_id)::text,'---null---')||'<-');
		end if;

		if p_agree_tos is not null then
			if p_agree_tos != '' then
				insert into q_qr_user_config ( user_id, name, value ) values ( l_user_id, 'agree_tos', p_agree_tos );
			end if;
		end if;
		if p_agree_eula is not null then
			if p_agree_eula != '' then
				insert into q_qr_user_config ( user_id, name, value ) values ( l_user_id, 'agree_eula', p_agree_eula );
			end if;
		end if;

		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'User Registered', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');

		-- Generate OTP passwords - 20 of them.
		l_otp_str = '[';
		l_otp_com = '';
		for ii in 1..20 loop
			l_tmp = uuid_generate_v4();
			l_tmp = substr(l_tmp,0,7) || substr(l_tmp,10,4);
			-- insert into q_qr_one_time_password ( user_id, otp_hash ) values ( l_user_id, crypt(l_tmp, gen_salt('bf') ) );
			insert into q_qr_one_time_password ( user_id, otp_hmac ) values ( l_user_id, q_auth_v1_hmac_encode ( l_tmp, p_hmac_password ) );
			l_otp_str = l_otp_str || l_otp_com || to_json(l_tmp);
			l_otp_com = ',';
		end loop;
		l_otp_str = l_otp_str || ']';
		if l_debug_on then
			insert into t_output ( msg ) values ( '->'||coalesce(to_json(l_otp_str)::text,'---null---')||'<-');
		end if;

	end if;

	if not l_fail then
		if l_admin_email = p_email then
			insert into q_qr_user_hierarchy ( user_id, parent_user_id )
				values ( l_user_id, null )
			;
			if l_debug_on then
				insert into t_output ( msg ) values ( ' l_admin_email= '||l_admin_email||' is equal to p_email' );
			end if;
		else
			insert into q_qr_user_hierarchy ( user_id, parent_user_id )
				select l_user_id, t1.user_id
				from q_qr_users as t1
				where t1.email_hmac = q_auth_v1_hmac_encode ( l_admin_email, p_hmac_password )
				;
			GET DIAGNOSTICS v_cnt = ROW_COUNT;
			if v_cnt = 0 then
				l_fail = true;
				l_data = '{"status":"error","msg":"Unable to create account as a part of the account hierarchy.  Please login or recover password.","code":"m4_count()","location":"m4___file__ m4___line__"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_bad_user_id, 'Unable to create account as a part of the account hierarchy.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
			end if;
			if l_debug_on then
				insert into t_output ( msg ) values ( ' l_admin_email= '||l_admin_email||' is *NOT* equal to p_email='||p_email );
			end if;
		end if;
	end if;

	if not l_fail then

		l_tmp_token = uuid_generate_v4();
		insert into q_qr_tmp_token ( user_id, token, expires ) values ( l_user_id, l_tmp_token, current_timestamp + interval '1 day' );

-- xyzzyRedisUsePubSub gCfg.RedisUsePubSub   string `json:"redis_use_pub_sub" default:"no"`
-- may need to create an auth_token and save it at this point also.

		l_data = '{"status":"success"'
			||', "user_id":' 			||coalesce(to_json(l_user_id)::text,'""')
			||', "email_verify_token":' ||coalesce(to_json(l_email_verify_token)::text,'""')
			||', "require_2fa":' 		||coalesce(to_json(l_require_2fa::text)::text,'""')
			||', "tmp_token":'   		||coalesce(to_json(l_tmp_token)::text,'""')
			||', "secret_2fa":'			||coalesce(to_json(l_secret_2fa)::text,'""')
			||', "user_config":'  		||coalesce(l_user_config,'"{}"')
			||', "otp":' 				||l_otp_str
			||', "n6":'   				||coalesce(to_json(l_n6)::text,'""')
			||'}';

		if l_debug_on then
			insert into t_output ( msg ) values ( ' l_data= '||l_data );
		end if;

	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;





























-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Regiser an account for a client.
--
-- THis is used to create accounts where a "token" has been send to a client to create an acocunt.
--
-- {Method: "POST", Path: "/api/v1/auth/register-client-admin", Fx: authHandleRegisterClientAdmin, UseLogin: PublicApiCall}, // un + pw + first_name + last_name + token to lead to client account:w
-- {Method: "POST", Path: "/api/v1/auth/register-using-auth-token", Fx: authHandleRegisterClientAdmin, UseLogin: PublicApiCall}, // un + pw + first_name + last_name + token to lead to client account
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

DROp FUNCTION if exists q_auth_v1_register_client ( p_email varchar, p_pw varchar, p_hmac_password varchar, p_first_name varchar, p_last_name varchar, p_userdata_password varchar, p_secret varchar, p_registration_token uuid );

CREATE OR REPLACE FUNCTION q_auth_v1_register_client ( p_email varchar, p_pw varchar, p_hmac_password varchar, p_first_name varchar, p_last_name varchar, p_userdata_password varchar, p_secret varchar, p_registration_token uuid, p_n6_flag varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_junk					text;
	l_fail					bool;
	l_user_id				uuid;
	l_bad_user_id			uuid;
	l_email_verify_token	uuid;
	l_tmp 					varchar(40);
	l_secret_2fa 			varchar(20);
	l_debug_on 				bool;
	l_auth_token			uuid;
	l_tmp_token				uuid;
	ii						int;
	l_otp_str				text;
	l_otp_com				text;
	l_privs					text;
	l_email_hmac			bytea;
	l_role_name				text;
	l_client_id				uuid;
	l_is_one_time			varchar(1);
	l_user_config			jsonb;
	l_admin_email			text;
	l_n6					text;
	v_cnt 					int;
	l_require_2fa_bool 		bool;
	l_require_2fa			text;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_email_verify_token = uuid_generate_v4();
	l_n6 = '000000';
	if p_n6_flag = 'n6' then
		l_n6 = q_auth_v1_n6_email_validate ( l_email_verify_token , p_n6_flag );
	end if;

	l_require_2fa 			= 'y';
	l_require_2fa_bool = q_get_config_bool_dflt ( 'use.2fa', true );
	if l_require_2fa_bool then
		l_require_2fa 			= 'y';
	else
		l_require_2fa 			= 'n';
	end if;

	-- l_tmp = uuid_generate_v4()::text;
	-- l_secret_2fa = substr(l_tmp,0,7) || substr(l_tmp,10,4);
	l_secret_2fa = p_secret;

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_register_token<- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '  p_email ->'||coalesce(to_json(p_email)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_pw ->'||coalesce(to_json(p_pw)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||coalesce(to_json(p_hmac_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_first_name ->'||coalesce(to_json(p_first_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_last_name ->'||coalesce(to_json(p_last_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_userdata_password ->'||coalesce(to_json(p_userdata_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_secret ->'||coalesce(to_json(p_secret)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_registration_token ->'||coalesce(to_json(p_registration_token)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_n6_flag ->'||coalesce(to_json(p_n6_flag)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_n6 ->'||coalesce(to_json(l_n6)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	if not l_fail then
		select role_name, client_id, is_one_time, admin_email
			into l_role_name, l_client_id, l_is_one_time, l_admin_email
			from q_qr_token_registration
			where token_registration_id = p_registration_token
			;
		if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to get identify valid registration token.","code":"m4_count()","location":"m4___file__ m4___line__"}';
		end if;
	end if;

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_register_token<- Continueed - Local Vars -- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '  l_client_id ->'||coalesce(to_json(l_client_id)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_is_one_time ->'||coalesce(to_json(l_is_one_time)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_admin_email ->'||coalesce(to_json(l_admin_email)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_role_name ->'||coalesce(to_json(l_role_name)::text,'---null---')||'<-');
	end if;

	if not l_fail then

		-- xyzzy9999
		--select json_agg(t1.priv_name)::text
		--	into l_privs
		--	from q_qr_role_to_priv as t1
		--	where t1.role_name =  l_role_name
		--	;
		select json_agg(t0.priv_name)::text
		into l_privs
		from (
			select json_object_keys(t1.allowed::json)::text  as priv_name
				from q_qr_role2 as t1
				where t1.role_name =  l_role_name
			) as t0
			;
		-- xyzzyError100 - never true iff.
		if not found then
			if l_debug_on then
				insert into t_output ( msg ) values ( 'Failed to get the privileges for the user' );
			end if;
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to get privileges for the user.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			l_privs = '';
		end if;
		if l_debug_on then
			insert into t_output ( msg ) values ( 'calculate l_privs ->'||coalesce(to_json(l_privs)::text,'---null---')||'<-');
		end if;

	end if;

	if not l_fail then
		select value
			into l_user_config
			from q_qr_user_config_default
			where role_name = l_role_name
			;
		if not found or l_user_config is null then
			l_user_config = '{}'::jsonb;
		end if;

	end if;

	-- If user has hever logged in and is attempting to register the user again - then delete old user - must have same email.
	-- PERFORM * FROM foo WHERE x = 'abc' AND y = 'xyz';
	-- IF FOUND THEN
	-- 	....
	-- END IF;
	-- , login_success = login_success + 1



	-- Cleanup any users that have expired tokens.
	-- !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	-- !!!! race condition !!!!
	-- !!!! tranactional error !!!!
	-- !!!! Possibilities...
	--	1. if password is same and 0 login, then should just update account (set n,n)
	--	2. if y,n or n,y, then should just update account
	--	3. else - error
	-- !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );
	select q_auth_v1_delete_user ( user_id )
		into l_junk
		from q_qr_users as t1
		where t1.email_hmac = l_email_hmac
		  and t1.login_success = 0
		;
	select user_id
		into l_bad_user_id
		from q_qr_users as t1
		where t1.email_hmac = l_email_hmac
		;
	if found then
		l_fail = true;
		l_data = '{"status":"error","msg":"Account already exists.  Please login or recover password.","code":"m4_count()","location":"m4___file__ m4___line__"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_bad_user_id, 'User Attempt to Re-Register Same Account.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
	end if;


	if not l_fail then

		INSERT INTO q_qr_users (
			  email_hmac
			, email_enc
			, password_hash
			, email_verify_token
			, email_verify_expire
			, secret_2fa
			, first_name_enc
			, first_name_hmac
			, last_name_enc
			, last_name_hmac
			, privileges
			, pdf_enc_password
			, client_id
			, x_user_config
			, role_name
			, org_name
		) VALUES (
		 	  q_auth_v1_hmac_encode ( p_email, p_hmac_password )
		    , pgp_sym_encrypt(p_email, p_userdata_password)
			, crypt(p_pw, gen_salt('bf') )
			, l_email_verify_token
			, current_timestamp + interval '1 day'
			, l_secret_2fa
		    , pgp_sym_encrypt(p_first_name,p_userdata_password)
		 	, q_auth_v1_hmac_encode ( lower(p_first_name), p_hmac_password )
		    , pgp_sym_encrypt(p_last_name,p_userdata_password)
		 	, q_auth_v1_hmac_encode ( lower(p_last_name), p_hmac_password )
			, l_privs
			, q_auth_v1_hmac_encode ( p_userdata_password || '::' || p_pw || '::' || lower(p_first_name) || ' ' || lower(p_last_name), p_hmac_password )
			, l_client_id
			, l_user_config
			, l_role_name
			, l_admin_email
		) returning user_id into l_user_id  ;

		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'User Registered', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');

		-- Generate OTP passwords - 20 of them.
		l_otp_str = '[';
		l_otp_com = '';
		for ii in 1..20 loop
			l_tmp = uuid_generate_v4();
			l_tmp = substr(l_tmp,0,7) || substr(l_tmp,10,4);
			-- insert into q_qr_one_time_password ( user_id, otp_hash ) values ( l_user_id, crypt(l_tmp, gen_salt('bf') ) );
			insert into q_qr_one_time_password ( user_id, otp_hmac ) values ( l_user_id, q_auth_v1_hmac_encode ( l_tmp, p_hmac_password ) );
			l_otp_str = l_otp_str || l_otp_com || to_json(l_tmp);
			l_otp_com = ',';
		end loop;
		l_otp_str = l_otp_str || ']';
		if l_debug_on then
			insert into t_output ( msg ) values ( '->'||coalesce(to_json(l_otp_str)::text,'---null---')||'<-');
		end if;

	end if;

	-- insert into q_qr_user_hierarchy ( user_id, parent_user_id ) select l_user_id, t1.user_id from q_qr_users where as t1 where ...
	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_register_token<- Before Error - Local Vars -- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '  l_user_id ->'||coalesce(to_json(l_user_id)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_admin_email ->'||coalesce(to_json(l_admin_email)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||coalesce(to_json(p_hmac_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_fail ->'||coalesce(to_json(l_fail)::text,'---null---')||'<-');
	end if;

	-- done - at this point xyzzyAJKAJKA - if token is from q q_qr_client then set this user_id as designated_user_id.
	if not l_fail then

		-- we will update 0 4ows if this is not in q_qr_client, so 0 is OK - this is a non- q_qr_client row.
		update q_qr_client
			set designated_user_id = l_user_id
			where token_registration_id = p_registration_token
			;

	end if;

	if not l_fail then
		insert into q_qr_user_hierarchy ( user_id, parent_user_id )
			select l_user_id, t1.user_id
			from q_qr_users as t1
			where t1.email_hmac = q_auth_v1_hmac_encode ( l_admin_email, p_hmac_password )
			;
		GET DIAGNOSTICS v_cnt = ROW_COUNT;
		if v_cnt = 0 then
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to create account as a part of the account hierarchy.  Please login or recover password.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_bad_user_id, 'Unable to create account as a part of the account hierarchy.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;
	end if;

	if not l_fail then

		l_tmp_token = uuid_generate_v4();
		insert into q_qr_tmp_token ( user_id, token, expires ) values ( l_user_id, l_tmp_token, current_timestamp + interval '1 day' );

		if l_is_one_time = 'y' then
			delete from q_qr_token_registration
				where token_registration_id = p_registration_token
				;
		end if;

		l_data = '{"status":"success"'
			||', "user_id":' 			||coalesce(to_json(l_user_id)::text,'""')
			||', "email_verify_token":' ||coalesce(to_json(l_email_verify_token)::text,'""')
			||', "require_2fa":' 		||coalesce(to_json(l_require_2fa::text)::text,'""')
			||', "tmp_token":'   		||coalesce(to_json(l_tmp_token)::text,'""')
			||', "secret_2fa":'			||coalesce(to_json(l_secret_2fa)::text,'""')
			||', "otp":' 				||l_otp_str
			||', "user_config":'  		||coalesce(l_user_config,'"{}"')
			||', "n6":'   				||coalesce(to_json(l_n6)::text,'""')
			||'}';

		if l_debug_on then
			insert into t_output ( msg ) values ( ' l_data= '||l_data );
		end if;

	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;



























-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- q_auth_v1_register_admin is a function for creating non user (role:user) accounts.
--
-- A few accounts are automatically built.  'root', 'admin' etc.   These accounts can then be used
-- to create other administration accounts.
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- drop function if exists q_auth_v1_register_admin ( p_email varchar, p_pw varchar, p_hmac_password varchar, p_first_name varchar, p_last_name varchar, p_userdata_password varchar, p_secret varchar, p_root_password varchar, p_specifed_role_name varchar, p_user_id uuid );

DROP FUNCTION if exists q_auth_v1_register_admin ( p_email varchar, p_pw varchar, p_hmac_password varchar, p_first_name varchar, p_last_name varchar, p_userdata_password varchar, p_secret varchar, p_admin_password varchar, p_specifed_role_name varchar, p_admin_user_id uuid ) ;

CREATE OR REPLACE FUNCTION q_auth_v1_register_admin ( p_email varchar, p_pw varchar, p_hmac_password varchar, p_first_name varchar, p_last_name varchar, p_userdata_password varchar, p_secret varchar, p_admin_password varchar, p_specifed_role_name varchar, p_admin_user_id uuid, p_n6_flag varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_junk					text;
	l_fail					bool;
	l_user_id				uuid;
	l_bad_user_id			uuid;
	l_email_verify_token	uuid;
	l_tmp 					varchar(40);
	l_secret_2fa 			varchar(20);
	l_debug_on 				bool;
	l_auth_token			uuid;
	l_tmp_token				uuid;
	ii						int;
	l_otp_str				text;
	l_otp_com				text;
	l_privs					text;
	l_email_hmac			bytea;
	l_user_config			jsonb;
	l_n6					text;
	l_require_2fa_bool 		bool;
	l_require_2fa			text;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_email_verify_token = uuid_generate_v4();
	l_n6 = '000000';
	if p_n6_flag = 'n6' then
		l_n6 = q_auth_v1_n6_email_validate ( l_email_verify_token , p_n6_flag );
	end if;

	l_require_2fa 			= 'y';
	l_require_2fa_bool = q_get_config_bool_dflt ( 'use.2fa', true );
	if l_require_2fa_bool then
		l_require_2fa 			= 'y';
	else
		l_require_2fa 			= 'n';
	end if;

	l_secret_2fa = p_secret;

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_register_admin<- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '  p_email ->'||coalesce(to_json(p_email)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_pw ->'||coalesce(to_json(p_pw)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||coalesce(to_json(p_hmac_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_first_name ->'||coalesce(to_json(p_first_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_last_name ->'||coalesce(to_json(p_last_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_userdata_password ->'||coalesce(to_json(p_userdata_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_secret ->'||coalesce(to_json(p_secret)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_specified_role_name ->'||coalesce(to_json(p_specified_role_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_admin_user_id ->'||coalesce(to_json(p_admin_user_id)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_n6_flag ->'||coalesce(to_json(p_n6_flag)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_n6 ->'||coalesce(to_json(l_n6)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	-- TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO
	-- Check the role/priv of the user that called this.... p_admin_user_id + p_admin_password

	if not q_admin_HasPriv ( p_admin_user_id, 'May Create Role Based User' ) then
		l_fail = true;
		l_data = '{"status":"error","msg":"Not authorized to create role based user.  Missing ''May Create Role Based User'' privilege","code":"m4_count()","location":"m4___file__ m4___line__"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Not authorized to change others password.  Missing ''May Create Role Based User'' privilege', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
	end if;

	if not l_fail then
		select 'found'
			from q_qr_users as t1
			where user_id = p_admin_user_id
			  and t1.password_hash = crypt(p_admin_password, password_hash)
			;
		if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"Not authorized to change create role based user","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Not authorized to create role based user ', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;
	end if;


	if not l_fail then

		l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );
		select q_auth_v1_delete_user ( user_id )
			into l_junk
			from q_qr_users as t1
			where t1.email_hmac = l_email_hmac
			  and t1.login_success = 0
			;
		select user_id
			into l_bad_user_id
			from q_qr_users as t1
			where t1.email_hmac = l_email_hmac
			;
		if found then
			l_fail = true;
			l_data = '{"status":"error","msg":"Account already exists.  Please login or recover password.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_bad_user_id, 'User Attempt to Re-Register Same Account.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;

	end if;

	if not l_fail then
		if not q_admin_HasPriv ( p_user_id, 'Admin: May Create Admin User' ) then
			if l_debug_on then
				insert into t_output ( msg ) values ( 'Failed to find priv ''Admin: May Create Admin User'' ->'||p_user_id||'<-');
			end if;
			l_fail = true;
			l_data = '{"status":"error","msg":"Account lacks ''Admin: May Create Admin User'' privilege","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account lacks ''Admin: May Create Admin User'' privilege', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;
	end if;

	if not l_fail then
		select 'found'
			into l_junk
			from q_qr_privs
			where name = p_specifed_role_name
			limit 1
			;
		if not found then
			if l_debug_on then
				insert into t_output ( msg ) values ( 'Failed to find role ->'||p_specified_role_priv||'<-');
			end if;
			l_fail = true;
			l_data = '{"status":"error","msg":"No Such Role:'''||p_speified_role_name||''' ","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'No Such Role: '''||p_specified_role_name||''' ', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;
	end if;

	if not l_fail then
		-- xyzzy9999
		--select json_agg(t1.priv_name)::text
		--	into l_privs
		--	from q_qr_role_to_priv as t1
		--	where t1.role_name = p_specifed_role_name
		--	;
		select json_agg(t0.priv_name)::text
		into l_privs
		from (
			select json_object_keys(t1.allowed::json)::text  as priv_name
				from q_qr_role2 as t1
				where t1.role_name = p_specifed_role_name
			) as t0
			;
		-- xyzzyError100 - never true iff.
		if not found then
			if l_debug_on then
				insert into t_output ( msg ) values ( 'Failed to get the privileges for the user' );
			end if;
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to get privileges for the user.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			l_privs = '';
		end if;
		if l_debug_on then
			insert into t_output ( msg ) values ( 'calculate l_privs ->'||coalesce(to_json(l_privs)::text,'---null---')||'<-');
		end if;
	end if;

	if not l_fail then
		select value
			into l_user_config
			from q_qr_user_config_default
			where role_name = p_specified_role_name
			;
		if not found or l_user_config is null then
			l_user_config = '{}'::jsonb;
		end if;

	end if;

	if not l_fail then

		INSERT INTO q_qr_users (
			  email_hmac
			, email_enc
			, password_hash
			, email_verify_token
			, email_verify_expire
			, secret_2fa
			, first_name_enc
			, first_name_hmac
			, last_name_enc
			, last_name_hmac
			, privileges
			, pdf_enc_password
			, email_validated
			, x_user_config
			, role_name
		) VALUES (
		 	  q_auth_v1_hmac_encode ( p_email, p_hmac_password )
		    , pgp_sym_encrypt(p_email, p_userdata_password)
			, crypt(p_pw, gen_salt('bf') )
			, l_email_verify_token
			, current_timestamp + interval '1 day'
			, l_secret_2fa
		    , pgp_sym_encrypt(p_first_name,p_userdata_password)
		 	, q_auth_v1_hmac_encode ( lower(p_first_name), p_hmac_password )
		    , pgp_sym_encrypt(p_last_name,p_userdata_password)
		 	, q_auth_v1_hmac_encode ( lower(p_last_name), p_hmac_password )
			, l_privs
			, q_auth_v1_hmac_encode ( p_userdata_password || '::' || p_pw || '::' || lower(p_first_name) || ' ' || lower(p_last_name), p_hmac_password )
			, 'y'
			, l_user_config
			, 'role:admin'
		) returning user_id into l_user_id  ;

		--insert into q_qr_user_role ( user_id, role_id )
		--	select l_user_id, t1.role_id
		--	from q_qr_role as t1
		--	where t1.role_name =  'role:admin'
		--	;

		insert into q_qr_auth_log ( user_id, activity, location ) values ( l_user_id, 'User Registered', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');

		-- Generate OTP passwords - 20 of them.
		l_otp_str = '[';
		l_otp_com = '';
		for ii in 1..20 loop
			l_tmp = uuid_generate_v4();
			l_tmp = substr(l_tmp,0,7) || substr(l_tmp,10,4);
			-- insert into q_qr_one_time_password ( user_id, otp_hash ) values ( l_user_id, crypt(l_tmp, gen_salt('bf') ) );
			insert into q_qr_one_time_password ( user_id, otp_hmac ) values ( l_user_id, q_auth_v1_hmac_encode ( l_tmp, p_hmac_password ) );
			l_otp_str = l_otp_str || l_otp_com || to_json(l_tmp);
			l_otp_com = ',';
		end loop;
		l_otp_str = l_otp_str || ']';
		if l_debug_on then
			insert into t_output ( msg ) values ( '->'||coalesce(to_json(l_otp_str)::text,'---null---')||'<-');
		end if;

	end if;

	insert into q_qr_user_hierarchy ( user_id ) values ( l_user_id );

	if not l_fail then

		l_tmp_token = uuid_generate_v4();
		insert into q_qr_tmp_token ( user_id, token, expires ) values ( l_user_id, l_tmp_token, current_timestamp + interval '1 day' );

		l_data = '{"status":"success"'
			||', "user_id":' 			||coalesce(to_json(l_user_id)::text,'""')
			||', "email_verify_token":' ||coalesce(to_json(l_email_verify_token)::text,'""')
			||', "require_2fa":' 		||coalesce(to_json(l_require_2fa::text)::text,'""')
			||', "tmp_token":'   		||coalesce(to_json(l_tmp_token)::text,'""')
			||', "secret_2fa":'			||coalesce(to_json(l_secret_2fa)::text,'""')
			||', "otp":' 				||l_otp_str
			||', "user_config":'  		||coalesce(l_user_config,'"{}"')
			||', "n6":'   				||coalesce(to_json(l_n6)::text,'""')
			||'}';

		if l_debug_on then
			insert into t_output ( msg ) values ( ' l_data= '||l_data );
		end if;

	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;





-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- stmt := "q_auth_v1_resend_email_register ( $1, $2, $3, $4, $5, $6, $7 )"
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
DROP FUNCTION if exists q_auth_v1_resend_email_register ( p_email varchar, p_tmp_token varchar, p_hmac_password varchar, p_userdata_password varchar ) ;

CREATE OR REPLACE FUNCTION q_auth_v1_resend_email_register ( p_email varchar, p_tmp_token varchar, p_hmac_password varchar, p_userdata_password varchar, p_n6_flag varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_junk					text;
	l_fail					bool;
	l_user_id				uuid;
	l_email_verify_token	uuid;
	l_debug_on 				bool;
	l_auth_token			uuid;
	l_tmp_token				uuid;
	l_email_hmac			bytea;
	l_first_name			text;
	l_last_name				text;
	l_n6					text;
	l_require_2fa			text;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_email_verify_token = uuid_generate_v4();
	l_n6 = '000000';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_resend_email_register<- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '  p_email ->'||coalesce(to_json(p_email)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_tmp_token ->'||coalesce(to_json(p_tmp_token)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||coalesce(to_json(p_hmac_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_userdata_password ->'||coalesce(to_json(p_userdata_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_n6_flag ->'||coalesce(to_json(p_n6_flag)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_n6 ->'||coalesce(to_json(l_n6)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_n6_flag ->'||coalesce(to_json(p_n6_flag)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_n6 ->'||coalesce(to_json(l_n6)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	if p_tmp_token <> '' then
		l_tmp_token := p_tmp_token::uuid;
	end if;

	-- Lookup User / Validate Password
	l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );
	select user_id
			, pgp_sym_decrypt(first_name_enc,p_userdata_password)::text as first_name
			, pgp_sym_decrypt(last_name_enc,p_userdata_password)::text as last_name
			, require_2fa
		into l_user_id
			, l_first_name
			, l_last_name
			, l_require_2fa
		from q_qr_users as t1
		where t1.email_hmac = l_email_hmac
		;

	if not found then
		l_fail = true;
		l_data = '{"status":"error","msg":"No account with this email address exists.  Please register again.","code":"m4_count()","location":"m4___file__ m4___line__"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_bad_user_id, 'No account with this email address exists.  Please register again.","code":"m4_count()","location":"m4___file__ m4___line__"}' );
	end if;

	if not l_fail then

		-- if email_verify_token is null then a login has occured on the account.
		-- this means that you should no long be able to get a new email.
		select t1.email_verify_token
			into l_email_verify_token
			from q_qr_users as t1
			where t1.user_id = l_user_id
			  and t1.email_verify_token is not null
			;
			--  and exists (
			--	select 'found'
			--		from q_qr_tmp_token as t2
			--		where t2.user_id = t1.user_id
			--		  and t2.token = l_tmp_token
			--	)

		if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to resend email registration.  Please register again.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_bad_user_id, 'Unable to resend email registration.  Please register again.","code":"m4_count()","location":"m4___file__ m4___line__"}' );
		end if;

		-- xyzzy99 - if l_n6_flag == 'n6', then use token to get l_email_verify_token?
		if l_email_verify_token is not null  then
			if p_n6_flag = 'n6' then
				l_n6 = q_auth_v1_n6_email_validate ( l_email_verify_token , p_n6_flag );
			end if;
			if l_debug_on then
				insert into t_output ( msg ) values ( '  p_n6_flag ->'||coalesce(to_json(p_n6_flag)::text,'---null---')||'<-');
				insert into t_output ( msg ) values ( '  l_n6 ->'||coalesce(to_json(l_n6)::text,'---null---')||'<-');
			end if;
		end if;

		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'User Email Resend Registered', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');

	end if;

	if not l_fail then

		l_data = '{"status":"success"'
			||', "user_id":' 			||coalesce(to_json(l_user_id)::text,'""')
			||', "email_verify_token":' ||coalesce(to_json(l_email_verify_token)::text,'""')
			||', "require_2fa":' 		||coalesce(to_json(l_require_2fa::text)::text,'""')
			||', "tmp_token":'   		||coalesce(to_json(l_tmp_token)::text,'""')
			||', "first_name":'   		||coalesce(to_json(l_first_name)::text,'""')
			||', "last_name":'   		||coalesce(to_json(l_last_name)::text,'""')
			||', "n6":'   				||coalesce(to_json(l_n6)::text,'""')
			||'}';

		if l_debug_on then
			insert into t_output ( msg ) values ( ' l_data= '||l_data );
		end if;

	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;






-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--	stmt := "q_auth_v1_sip_register ( $1, $2, $3, $4, $5, $6, $7 )"
--	dbgo.Fprintf(logFilePtr, "%(cyan)In handler at %(LF): %s\n", stmt)
--	rv, err := CallDatabaseJSONFunction(c, stmt, "ee.ee..", pp.Email, pp.v, gCfg.EncryptionPassword, pp.FirstName, pp.LastName, gCfg.UserdataPassword, secret)
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
DROP FUNCTION if exists q_auth_v1_sip_register ( p_email varchar, p_validator varchar, p_hmac_password varchar, p_first_name varchar, p_last_name varchar, p_userdata_password varchar, p_secret varchar ) ;

CREATE OR REPLACE FUNCTION q_auth_v1_sip_register ( p_email varchar, p_validator varchar, p_hmac_password varchar, p_first_name varchar, p_last_name varchar, p_userdata_password varchar, p_secret varchar, p_n6_flag varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_junk					text;
	l_fail					bool;
	l_user_id				uuid;
	l_bad_user_id			uuid;
	l_email_verify_token	uuid;
	l_tmp 					varchar(40);
	l_secret_2fa 			varchar(20);
	l_debug_on 				bool;
	l_auth_token			uuid;
	l_tmp_token				uuid;
	ii						int;
	l_otp_str				text;
	l_otp_com				text;
	l_privs					text;
	l_email_hmac			bytea;
	l_admin_email			text;
	l_n6					text;
	v_cnt 					int;
	l_require_2fa_bool 		bool;
	l_require_2fa			text;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );
	l_admin_email = q_get_config ( 'admin.user' );

	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_email_verify_token = uuid_generate_v4();
	l_n6 = '000000';
	if p_n6_flag = 'n6' then
		l_n6 = q_auth_v1_n6_email_validate ( l_email_verify_token , p_n6_flag );
	end if;

	l_require_2fa 			= 'y';
	l_require_2fa_bool = q_get_config_bool_dflt ( 'use.2fa', true );
	if l_require_2fa_bool then
		l_require_2fa 			= 'y';
	else
		l_require_2fa 			= 'n';
	end if;

	-- l_tmp = uuid_generate_v4()::text;
	-- l_secret_2fa = substr(l_tmp,0,7) || substr(l_tmp,10,4);
	l_secret_2fa = p_secret;

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_register<- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '  p_email ->'||coalesce(to_json(p_email)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_validator ->'||coalesce(to_json(p_validator)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||coalesce(to_json(p_hmac_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_first_name ->'||coalesce(to_json(p_first_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_last_name ->'||coalesce(to_json(p_last_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_userdata_password ->'||coalesce(to_json(p_userdata_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_secret ->'||coalesce(to_json(p_secret)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_n6_flag ->'||coalesce(to_json(p_n6_flag)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_n6 ->'||coalesce(to_json(l_n6)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	-- If user has hever logged in and is attempting to register the user again - then delete old user - must have same email.
	-- PERFORM * FROM foo WHERE x = 'abc' AND y = 'xyz';
	-- IF FOUND THEN
	-- 	....
	-- END IF;
	-- , login_success = login_success + 1
	l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );
	select q_auth_v1_delete_user ( user_id )
		into l_junk
		from q_qr_users as t1
		where t1.email_hmac = l_email_hmac
		  and t1.login_success = 0
		;
	select user_id
		into l_bad_user_id
		from q_qr_users as t1
		where t1.email_hmac = l_email_hmac
		;
	if found then
		l_fail = true;
		l_data = '{"status":"error","msg":"Account already exists.  Please login or recover password.","code":"m4_count()","location":"m4___file__ m4___line__"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_bad_user_id, 'User Attempt to Re-Register Same Account.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
	end if;

	if not l_fail then
		-- SELECT json_agg(row_to_json(t2))::text
		-- 	into l_privs
		-- 	FROM (
		-- 		select t1.priv_name
		-- 		from q_qr_role_to_priv as t1
		-- 		where t1.role_name =  'role:user'
		-- 	) t2
		-- ;

		-- xyzzy9999
		--select json_agg(t1.priv_name)::text
		--	into l_privs
		--	from q_qr_role_to_priv as t1
		--	where t1.role_name =  'role:user'
		--	;
		select json_agg(t0.priv_name)::text
		into l_privs
		from (
			select json_object_keys(t1.allowed::json)::text  as priv_name
				from q_qr_role2 as t1
				where t1.role_name =  'role:user'
			) as t0
			;
		-- xyzzyError100 - never true iff.
		if not found then
			if l_debug_on then
				insert into t_output ( msg ) values ( 'Failed to get the privileges for the user' );
			end if;
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to get privileges for the user.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			l_privs = '';
		end if;
		if l_debug_on then
			insert into t_output ( msg ) values ( 'calculate l_privs ->'||coalesce(to_json(l_privs)::text,'---null---')||'<-');
		end if;
	end if;

	if not l_fail then

		INSERT INTO q_qr_users (
			  email_hmac
			, email_enc
			, validator
			, email_verify_token
			, email_verify_expire
			, secret_2fa
			, first_name_enc
			, last_name_enc
			, privileges
			, validation_method
			, password_hash
			, role_name
			, require_2fa
		) VALUES (
		 	  q_auth_v1_hmac_encode ( p_email, p_hmac_password )
		    , pgp_sym_encrypt(p_email, p_userdata_password)
			, p_validator
			, l_email_verify_token
			, current_timestamp + interval '1 day'
			, l_secret_2fa
		    , pgp_sym_encrypt(p_first_name,p_userdata_password)
		    , pgp_sym_encrypt(p_last_name,p_userdata_password)
			, l_privs
			, 'sip'
			, '*'		-- never a valid hash - password is not used.
			, 'role:user'
			, l_require_2fa
		) returning user_id into l_user_id  ;

		--insert into q_qr_user_role ( user_id, role_id )
		--	select l_user_id, t1.role_id
		--	from q_qr_role as t1
		--	where t1.role_name =  'role:user'
		--	;

		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'User Registered', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');

		-- Generate OTP passwords - 20 of them.
		l_otp_str = '[';
		l_otp_com = '';
		for ii in 1..20 loop
			l_tmp = uuid_generate_v4();
			l_tmp = substr(l_tmp,0,7) || substr(l_tmp,10,4);
			-- insert into q_qr_one_time_password ( user_id, otp_hash ) values ( l_user_id, crypt(l_tmp, gen_salt('bf') ) );
			insert into q_qr_one_time_password ( user_id, otp_hmac ) values ( l_user_id, q_auth_v1_hmac_encode ( l_tmp, p_hmac_password ) );
			l_otp_str = l_otp_str || l_otp_com || to_json(l_tmp);
			l_otp_com = ',';
		end loop;
		l_otp_str = l_otp_str || ']';
		if l_debug_on then
			insert into t_output ( msg ) values ( '->'||coalesce(to_json(l_otp_str)::text,'---null---')||'<-');
		end if;

	end if;

	insert into q_qr_user_hierarchy ( user_id, parent_user_id )
		select l_user_id, t1.user_id
		from q_qr_users as t1
		where t1.email_hmac = q_auth_v1_hmac_encode ( l_admin_email, p_hmac_password )
		;
	GET DIAGNOSTICS v_cnt = ROW_COUNT;
	if v_cnt = 0 then
		l_fail = true;
		l_data = '{"status":"error","msg":"Unable to create account as a part of the account hierarchy.  Please login or recover password.","code":"m4_count()","location":"m4___file__ m4___line__"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_bad_user_id, 'Unable to create account as a part of the account hierarchy.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
	end if;

	if not l_fail then

		l_tmp_token = uuid_generate_v4();
		insert into q_qr_tmp_token ( user_id, token, expires ) values ( l_user_id, l_tmp_token, current_timestamp + interval '1 day' );

		l_data = '{"status":"success"'
			||', "user_id":' 			||coalesce(to_json(l_user_id)::text,'""')
			||', "email_verify_token":' ||coalesce(to_json(l_email_verify_token)::text,'""')
			||', "require_2fa":' 		||coalesce(to_json(l_require_2fa::text)::text,'""')
			||', "tmp_token":'   		||coalesce(to_json(l_tmp_token)::text,'""')
			||', "secret_2fa":' 		||coalesce(to_json(l_secret_2fa)::text,'""')
			||', "otp":' 				||l_otp_str
			||', "n6":'   				||coalesce(to_json(l_n6)::text,'""')
			||'}';

		if l_debug_on then
			insert into t_output ( msg ) values ( ' l_data= '||l_data );
		end if;

	end if;
	RETURN l_data;
END;
$$ LANGUAGE plpgsql;






-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- not apear to be called!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION q_auth_v1_register_resend_email_link ( p_email varchar, p_old_email_verify_token varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_junk					text;
	l_fail					bool;
	l_user_id				uuid;
	l_tmp_token				uuid;
	l_debug_on 				bool;
	l_email_verify_token	uuid;
	v_cnt 					int;
	l_email_hmac			bytea;
	l_n6					text;
	l_require_2fa			text;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_email_verify_token = uuid_generate_v4();
	l_n6 = '000000';
	if p_n6_flag = 'n6' then
		l_n6 = q_auth_v1_n6_email_validate ( l_email_verify_token , p_n6_flag );
	end if;

	l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );
	select t1.user_id, t1.require_2fa
		into l_user_id, l_require_2fa
		from q_qr_users as t1
		where t1.email_hmac = l_email_hmac
		  and email_verify_token = p_old_email_verify_token
		;
	if not found then
		if l_debug_on then
			insert into t_output ( msg ) values ( 'Failed to find the user' );
		end if;
		l_fail = true;
		l_data = '{"status":"error","msg":"Unable to find the user.","code":"m4_count()","location":"m4___file__ m4___line__"}';
	end if;

	update q_qr_users as t1
		set
			  t1.email_verify_token = l_email_verify_token
			, t1.email_verify_expire = current_timestamp + interval '1 day'
			, t1.email_validated = 'n'
		where t1.email_hmac = l_email_hmac
		  and email_verify_token = p_old_email_verify_token
		;
	GET DIAGNOSTICS v_cnt = ROW_COUNT;
	if v_cnt != 1 then
		l_fail = true;
		l_data = '{"status":"error","msg":"Invalid User/Email or Account not valid","code":"m4_count()","location":"m4___file__ m4___line__"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid User or Account not valid', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
	end if;

	if not l_fail then

		l_tmp_token = uuid_generate_v4();
		insert into q_qr_tmp_token ( user_id, token, expires ) values ( l_user_id, l_tmp_token, current_timestamp + interval '1 day' );

		l_data = '{"status":"success"'
			||', "email_verify_token":' ||coalesce(to_json(l_email_verify_token)::text,'""')
			||', "require_2fa":' 		||coalesce(to_json(l_require_2fa::text)::text,'""')
			||', "tmp_token":'   		||coalesce(to_json(l_tmp_token)::text,'""')
			||', "n6":'   				||coalesce(to_json(l_n6)::text,'""')
			||'}';

		if l_debug_on then
			insert into t_output ( msg ) values ( ' l_data= '||l_data );
		end if;

	end if;
END;
$$ LANGUAGE plpgsql;










-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION q_auth_v1_delete_user ( p_user_id uuid ) RETURNS text
AS $$
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()

	delete from q_qr_auth_log where user_id = p_user_id;
	delete from q_qr_auth_tokens where user_id = p_user_id;
	delete from q_qr_one_time_password where user_id = p_user_id;
	--delete from q_qr_user_role where user_id = p_user_id;
	delete from q_qr_auth_log where user_id = p_user_id;
	delete from q_qr_tmp_token where user_id = p_user_id;
	delete from q_qr_user_config where user_id = p_user_id;

	delete from q_qr_n6_email_verify where email_verify_token = ( select email_verify_token from q_qr_users where user_id = p_user_id );
	delete from q_qr_auth_log where user_id = ( select user_id from q_qr_users where parent_user_id = p_user_id );
	delete from q_qr_auth_tokens where user_id = ( select user_id from q_qr_users where parent_user_id = p_user_id );
	delete from q_qr_one_time_password where user_id = ( select user_id from q_qr_users where parent_user_id = p_user_id );
	--delete from q_qr_user_role where user_id = ( select user_id from q_qr_users where parent_user_id = p_user_id );
	delete from q_qr_auth_log where user_id = ( select user_id from q_qr_users where parent_user_id = p_user_id );
	delete from q_qr_tmp_token where user_id = ( select user_id from q_qr_users where parent_user_id = p_user_id );
	delete from q_qr_user_config where user_id = ( select user_id from q_qr_users where parent_user_id = p_user_id );
	delete from q_qr_users where parent_user_id = p_user_id;	-- delete child accounts

	delete from q_qr_users where user_id = p_user_id;

	RETURN ( 'User Deleted '||p_user_id::text );
END;
$$ LANGUAGE plpgsql;









-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION q_auth_v1_change_password ( p_email varchar, p_pw varchar, p_new_pw varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_tmp					text;
	v_cnt					int;
	l_user_id				uuid;
	l_email_hmac			bytea;
	l_first_name			text;
	l_last_name				text;
	l_debug_on 				bool;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_change_password<- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '  p_email ->'||coalesce(to_json(p_email)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	if not l_fail then
		if p_pw = p_new_pw then
			l_fail = true;
			l_data = '{"status":"error","msg":"Old and New Password must be different","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Old and New Password must be different', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;
	end if;

	if not l_fail then
		l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );
		if l_debug_on then
			insert into t_output ( msg ) values ( '  l_email_hmac ->'||coalesce(to_json(l_email_hmac)::text,'---null---')||'<-');
			insert into t_output ( msg ) values ( '  ' );
		end if;


		with user_row as (
			select
				  user_id
				, account_type
				, password_hash
			from q_qr_users as t1
			where t1.email_hmac = l_email_hmac
		)
		select 'passwd-match'
			into l_tmp
			from user_row as t8
			where t8.account_type in ( 'login', 'un/pw' )
			  and t8.password_hash = crypt(p_pw, password_hash)
			;

		if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"Existing Password did not match.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Existing Password did not match.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;

		if not l_fail then
			with user_row as (
				select
					  user_id
					, pgp_sym_decrypt(first_name_enc,p_userdata_password)::text as first_name
					, pgp_sym_decrypt(last_name_enc,p_userdata_password)::text as last_name
					, start_date
					, end_date
					, account_type
					, password_hash
					, parent_user_id
					, email_validated
					, setup_complete_2fa
					, require_2fa
				from q_qr_users as t1
				where t1.email_hmac = l_email_hmac
			)
			select user_id
				, first_name
				, last_name
				into l_user_id
					, l_first_name
					, l_last_name
				from user_row as t8
				where ( t8.start_date < current_timestamp or t8.start_date is null )
				  and ( t8.end_date > current_timestamp or t8.end_date is null )
				  and (
						(
								t8.account_type = 'login'
							and t8.password_hash = crypt(p_pw, password_hash)
							and t8.parent_user_id is null
							and t8.email_validated = 'y'
							and ( t8.setup_complete_2fa = 'y' or t8.require_2fa = 'n' )
						)  or (
								t8.account_type = 'un/pw'
							and t8.password_hash = crypt(p_pw, password_hash)
							and t8.parent_user_id is not null
							and exists (
								select 'found'
								from q_qr_users as t2
								where t2.user_id = t8.parent_user_id
								  and ( t2.start_date < current_timestamp or t2.start_date is null )
								  and ( t2.end_date > current_timestamp or t2.end_date is null )
								  and t2.email_validated = 'y'
								  and ( t2.setup_complete_2fa = 'y' or t2.require_2fa = 'n' )
							)
						)
					)
				for update
				;

				-- can not change password on 'token' account that will not use a password at all.
				--	)  or (
				--			t8.account_type = 'token'
				--		and t8.parent_user_id is not null
				--		and exists (
				--			select 'found'
				--			from q_qr_users as t3
				--			where t3.user_id = t8.parent_user_id
				--			  and ( t3.start_date < current_timestamp or t3.start_date is null )
				--			  and ( t3.end_date > current_timestamp or t3.end_date is null )
				--			  and t3.email_validated = 'y'
				--	          and ( t3.setup_complete_2fa = 'y' or t3.require_2fa = 'n' )
				--		)
				--	)

			if not found then
				l_fail = true;
				l_data = '{"status":"error","msg":"Invalid Username or Account not valid or email not validated","code":"m4_count()","location":"m4___file__ m4___line__"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or email not validated', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
			end if;

		end if;

	end if;

	if not l_fail then
		update q_qr_users as t1
			set
				  password_hash = crypt(p_new_pw, gen_salt('bf') )
			where t1.user_id = l_user_id
			;
		-- check # of rows.
		GET DIAGNOSTICS v_cnt = ROW_COUNT;
		if v_cnt != 1 then
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to update to new password.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or email not validated', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;
	end if;

	-- Delete all the id.json rows for this user - every marked device will need to 2fa after this request.
	-- Select to get l_user_id for email.  If it is not found above then this may not be a fully setup user.
	-- The l_user_id is used below in a delete to prevent marking of devices as having been seen.
	delete from q_qr_device_track
		where user_id = (
			select user_id
			from q_qr_users as t1
			where t1.email_hmac = l_email_hmac
		)
	;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "first_name":'  	||coalesce(to_json(l_first_name)::text,'""')
			||', "last_name":'   	||coalesce(to_json(l_last_name)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;







-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- drop function q_auth_v1_change_password_admin ( p_admin_user_id uuid, p_un varchar, p_new_pw varchar, p_hmac_password varchar, p_userdata_password varchar );

-- 	A. q_auth_v1_change_password_admin -- xyzzy400 (check privs)
CREATE OR REPLACE FUNCTION q_auth_v1_change_password_admin ( p_admin_user_id uuid, p_email varchar, p_new_pw varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_tmp					text;
	v_cnt					int;
	l_first_name			text;
	l_last_name				text;
	l_user_id				uuid;
	l_email_hmac				bytea;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if not q_admin_HasPriv ( p_admin_user_id, 'May Change Other Password' ) then
		l_fail = true;
		l_data = '{"status":"error","msg":"Not authorized to change others password","code":"m4_count()","location":"m4___file__ m4___line__"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Not authorized to change others password', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
	end if;

	l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );

	if not l_fail then

		with user_row as (
			select
				  user_id
				, pgp_sym_decrypt(first_name_enc,p_userdata_password)::text as first_name
				, pgp_sym_decrypt(last_name_enc,p_userdata_password)::text as last_name
				, start_date
				, end_date
				, account_type
				, password_hash
				, parent_user_id
				, email_validated
				, setup_complete_2fa
			from q_qr_users as t1
			where t1.email_hmac = l_email_hmac
		)
		select user_id
			, first_name
			, last_name
			into l_user_id
				, l_first_name
				, l_last_name
			from user_row as t8
			;
		update q_qr_users as t1
			set
				  password_hash = crypt(p_new_pw, gen_salt('bf') )
			where t1.user_id = l_user_id
			;
		-- check # of rows.
		GET DIAGNOSTICS v_cnt = ROW_COUNT;
		if v_cnt != 1 then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or email not validated","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or email not validated', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;
	end if;

	if not l_fail then
		-- Delete all the id.json rows for this user - every marked device will need to 2fa after this request.
		-- Select to get l_user_id for email.  If it is not found above then this may not be a fully setup user.
		-- The l_user_id is used below in a delete to prevent marking of devices as having been seen.
		delete from q_qr_device_track
			where user_id = l_user_id
		;
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "first_name":'  	||coalesce(to_json(l_first_name)::text,'""')
			||', "last_name":'   	||coalesce(to_json(l_last_name)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;





-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION q_auth_v1_change_password_root_cli ( p_email varchar, p_new_pw varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_tmp					text;
	v_cnt					int;
	l_first_name			text;
	l_last_name				text;
	l_user_id				uuid;
	l_email_hmac				bytea;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );

	if not l_fail then
		-- Xyzzy - better to do select count - and verify where before update.
		with user_row as (
			select
				  user_id
				, pgp_sym_decrypt(first_name_enc,p_userdata_password)::text as first_name
				, pgp_sym_decrypt(last_name_enc,p_userdata_password)::text as last_name
				, start_date
				, end_date
				, account_type
				, password_hash
				, parent_user_id
				, email_validated
				, setup_complete_2fa
			from q_qr_users as t1
			where t1.email_hmac = l_email_hmac
		)
		select user_id
			, first_name
			, last_name
			into l_user_id
				, l_first_name
				, l_last_name
			from user_row as t8
			;
		update q_qr_users as t1
			set
				  password_hash = crypt(p_new_pw, gen_salt('bf') )
			where t1.user_id = l_user_id
			;
		-- check # of rows.
		GET DIAGNOSTICS v_cnt = ROW_COUNT;
		if v_cnt != 1 then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or email not validated","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or email not validated', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;
	end if;

	if not l_fail then
		-- Delete all the id.json rows for this user - every marked device will need to 2fa after this request.
		-- Select to get l_user_id for email.  If it is not found above then this may not be a fully setup user.
		-- The l_user_id is used below in a delete to prevent marking of devices as having been seen.
		delete from q_qr_device_track
			where user_id = l_user_id
		;
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "first_name":'  	||coalesce(to_json(l_first_name)::text,'""')
			||', "last_name":'   	||coalesce(to_json(l_last_name)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;











-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--
-- Important:
--
-- Indicates partial registration, email_validated == "n", - code==="0020"			0020
-- Indicates partial registration, setup_complete_2fa == "n", - code==="0220"		0220
--
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- rv, err := CallDatabaseJSONFunction(c, stmt, "ee.!!", pp.Email, pp.Pw, pp.AmIKnown, aCfg.EncryptionPassword, aCfg.UserdataPassword, pp.FPData, pp.ScID, hashOfHeaders) //
DROP FUNCTION if exists q_auth_v1_login ( p_email varchar, p_pw varchar, p_am_i_known varchar, p_hmac_password varchar, p_userdata_password varchar ) ;
DROP FUNCTION if exists q_auth_v1_login ( p_email varchar, p_pw varchar, p_am_i_known varchar, p_hmac_password varchar, p_userdata_password varchar, p_fingerprint varchar, p_sc_id varchar, p_hash_of_headers varchar );

--                                          1                 2             3                     4                        5                            6                      7                8                          9
CREATE OR REPLACE FUNCTION q_auth_v1_login ( p_email varchar, p_pw varchar, p_am_i_known varchar, p_hmac_password varchar, p_userdata_password varchar, p_fingerprint varchar, p_sc_id varchar, p_hash_of_headers varchar, p_xsrf_id varchar ) RETURNS text
AS $$
DECLARE
	l_2fa_id				uuid;
	l_data					text;
	l_fail					bool;
  	l_user_id 				uuid;
	l_junk					text;
	l_email_validated		varchar(1);
	l_setup_complete_2fa 	varchar(1);
	l_start_date			timestamp;
	l_end_date				timestamp;
	l_require_2fa 			varchar(1);
	l_secret_2fa 			varchar(20);
	l_account_type			varchar(20);
	l_privileges			text;
	l_user_config			text;
	l_first_name			text;
	l_last_name				text;
	l_tmp					text;
	l_auth_token			uuid;
	l_tmp_token				uuid;	-- when 2fa is on this is returnd as not null (UUID)
	l_debug_on 				bool;
	l_failed_login_timeout 	timestamp;
	l_login_failures 		int;
	l_one_time_password_id 	uuid;
	v_cnt 					int;
	l_validation_method		varchar(10);
	l_manifest_id			uuid;
	l_email_hmac            bytea;
	l_otp_hmac              text;
	l_is_new_device_login	varchar(1);
	l_client_id				uuid;
	l_acct_state			text;
	l_role_name				text;
	l_is_new_device_msg		text;
	l_device_track_id		uuid;
	l_client_user_config	text;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';
	l_is_new_device_login = 'n';
	l_is_new_device_msg = '--don''t-know--';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_login<- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '  p_email ->'||coalesce(to_json(p_email)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_pw ->'||coalesce(to_json(p_pw)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_am_i_known ->'||coalesce(to_json(p_am_i_known)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||coalesce(to_json(p_hmac_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_userdata_password ->'||coalesce(to_json(p_userdata_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_fingerprint ->'||coalesce(to_json(p_fingerprint)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_sc_id ->'||coalesce(to_json(p_sc_id)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_hash_of_headers ->'||coalesce(to_json(p_hash_of_headers)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_xsrf_id ->'||coalesce(to_json(p_xsrf_id)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	-- --------------------------------------------------------------------------------------------------------------------------------------------------------
	-- New Device
	-- --------------------------------------------------------------------------------------------------------------------------------------------------------
	-- If not found, ( p_am_i_known???, p_fingerprint , p_sc_id, p_hash_of_headers )
	--		l_is_new_device_msg = 'based on: (a,b,c) not found this is a new device.
	-- IF successful login THEN : Create new row in q_qr_device_track with entries, create dependent row with l_xsrf_id into q_qr_valid_xsrf_id. 	Set loign count to 1.
	-- IF not new device THEN: if xsrf_id not in q_qr_valid_xsrf_id, for this user, then if successful login, create new row for l_xsrf_id.
	-- IF not new device THEN: if succesful login then: update login count for this device.
	-- --------------------------------------------------------------------------------------------------------------------------------------------------------
	--
	-- m4_comment([[[
	--
	-- 	autojob=# \i sql-get-device-track.sql
	--       id      |   user_id    |      etag_seen       | n_seen | n_login |         fingerprint_data         |    sc_id     |                           header_hash                            |  am_i_known
	-- --------------+--------------+----------------------+--------+---------+----------------------------------+--------------+------------------------------------------------------------------+--------------
	--  5c04a7a7-638 |              | 3ddd89982a6f06303948 |      0 |       0 |                                  |              |                                                                  |
	--  f467e984-2a1 | 524d58b1-b94 |                      |      0 |       2 | b11ba821e996ecc6b9dd1b0ca7fe139a | 06ee6e25-315 | bcaa4ba6cce30df4fc790d9c8466254d61b1ff6d0e53e5ab2fd91ea95928bcb8 | 060951a1-169
	--  060951a1-169 |              | f9fdbdb8ddf03064341b |      3 |       0 |                                  |              |                                                                  |
	--  a89d71d5-ae8 | 524d58b1-b94 |                      |      0 |       3 | b11ba821e996ecc6b9dd1b0ca7fe139a | 06ee6e25-315 | c0913a7535439615871db5a171fa7293e8f937102adb09c7d5341e3b33276e2a | 060951a1-169
	-- (4 rows)
	--
	-- Note:
	-- 	1. the am_i_known value for login matches with the "id"  in a row with etag_seen set.
	--
	-- ]]])
	--
	-- xyzzy8 - fingerprint
	select id
		into l_device_track_id
		from q_qr_device_track as t1
		where t1.fingerprint_data = p_fingerprint
		  and t1.sc_id = p_sc_id
		  and t1.header_hash = p_hash_of_headers
		limit 1
		;

	if not found then
		l_is_new_device_login = 'y';
		l_is_new_device_msg = 'new device, test 1';
	else
		l_is_new_device_login = 'n';
		l_is_new_device_msg = 'Existing device fingerprint/sc_id/header_hash match';
	end if;


	-- validation_method		varchar(10) default 'un/pw' not null check ( validation_method in ( 'un/pw', 'sip', 'srp6a', 'hw-key' ) ),
	if not l_fail then
		l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );
		-- see:(this one has been fixed) xyzzy-Slow!! - better to do select count - and verify where before update.
		with email_user as (
			select
				  user_id
				, email_validated
				, setup_complete_2fa
				, start_date
				, end_date
				, require_2fa
				, secret_2fa
				, account_type
				, pgp_sym_decrypt(first_name_enc,p_userdata_password)::text as x_first_name
				, pgp_sym_decrypt(last_name_enc,p_userdata_password)::text as x_last_name
				, failed_login_timeout
				, login_failures
				, validation_method
				, password_hash
				, parent_user_id
				, client_id
				, acct_state
				, role_name
			from q_qr_users
			where email_hmac = l_email_hmac
		)
		select
				  user_id
				, email_validated
				, setup_complete_2fa
				, start_date
				, end_date
				, require_2fa
				, secret_2fa
				, account_type
				, x_first_name
				, x_last_name
				, failed_login_timeout
				, login_failures
				, validation_method
				, client_id
				, acct_state
				, role_name
			into
				  l_user_id
				, l_email_validated
				, l_setup_complete_2fa
				, l_start_date
				, l_end_date
				, l_require_2fa
				, l_secret_2fa
				, l_account_type
				, l_first_name
				, l_last_name
				, l_failed_login_timeout
				, l_login_failures
				, l_validation_method
				, l_client_id
				, l_acct_state
				, l_role_name
			from email_user
		    where
				(
					    account_type = 'login'
					and password_hash = crypt(p_pw, password_hash)
					and parent_user_id is null
				)  or (
					    account_type = 'un/pw'
					and password_hash = crypt(p_pw, password_hash)
					and parent_user_id is not null
				)  or (
					    account_type = 'token'
					and password_hash = crypt(p_pw, password_hash)
					and parent_user_id is not null
				)
		;

		if found then
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Username/Password Found:'||p_email, 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;

		if not found then -- BBB
			select
				  user_id
				, email_validated
				, setup_complete_2fa
				, start_date
				, end_date
				, require_2fa
				, secret_2fa
				, account_type
				, pgp_sym_decrypt(first_name_enc,p_userdata_password)::text as x_first_name
				, pgp_sym_decrypt(last_name_enc,p_userdata_password)::text as x_last_name
				, failed_login_timeout
				, login_failures
				, validation_method
				, client_id
				, acct_state
				, role_name
			into l_user_id
				, l_email_validated
				, l_setup_complete_2fa
				, l_start_date
				, l_end_date
				, l_require_2fa
				, l_secret_2fa
				, l_account_type
				, l_first_name
				, l_last_name
				, l_failed_login_timeout
				, l_login_failures
				, l_validation_method
				, l_client_id
				, l_acct_state
				, l_role_name
			from q_qr_users
			where email_hmac = l_email_hmac
			;
			if not found then
				l_fail = true;
				l_data = '{"status":"error","msg":"Invalid Username or Password","code":"m4_count()","location":"m4___file__ m4___line__"}'; -- return no such account or password
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Username(email) Not Found:'||p_email, 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
			end if;

			if not l_fail then -- AAA

				-- ------------------------------------------------------------------------------------------
				-- Place to check if password is an OTP password and handle that
				-- ------------------------------------------------------------------------------------------

				-- should be an _hmac for otp - not a crypt - need to access this quickly

				l_otp_hmac = q_auth_v1_hmac_encode ( p_pw, p_hmac_password );

				select
						t2.one_time_password_id
					into
						l_one_time_password_id
					from q_qr_one_time_password as t2
					where t2.user_id = l_user_id
					  and t2.otp_hmac = l_otp_hmac
				;

				if found then
					if l_debug_on then
						insert into t_output ( msg ) values ( '  ((( Login is a successful OTP password login )))' );
					end if;
					l_require_2fa = 'n';		-- Turn off 1fa - they have the paper OTP as 2nd factor.
					delete from q_qr_one_time_password where one_time_password_id = l_one_time_password_id;
					insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Used Ont Time Password', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
				else
					l_fail = true;
					l_data = '{"status":"error","msg":"Invalid Username or Password","code":"m4_count()","location":"m4___file__ m4___line__"}'; -- return no such account or password
					insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid one-time, or bad password:'||p_email, 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
				end if;

			end if; -- AAA

		end if; -- BBB

	end if;

	if l_debug_on then
		insert into t_output ( msg ) values ( '  [[[ Additional Fields ]]]' );
		insert into t_output ( msg ) values ( '  ->'||coalesce(to_json(p_userdata_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_first_name           = ->'||coalesce(to_json(l_first_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_last_name            = ->'||coalesce(to_json(l_last_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_validation_method    = ->'||coalesce(to_json(l_validation_method)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_start_date           = ->'||coalesce(to_json(l_start_date)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_end_date             = ->'||coalesce(to_json(l_end_date)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_email_validated      = ->'||coalesce(to_json(l_email_validated)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_setup_complete_2fa   = ->'||coalesce(to_json(l_setup_complete_2fa)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_client_id            = ->'||coalesce(to_json(l_client_id)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_acct_state           = ->'||coalesce(to_json(l_acct_state)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_require_2fa          = ->'||coalesce(to_json(l_require_2fa)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_otp_hmac             = ->'||coalesce(to_json(l_otp_hmac)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_one_time_password_id = ->'||coalesce(to_json(l_one_time_password_id)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_role_name            = ->'||coalesce(to_json(l_role_name)::text,'---null---')||'<-');
	end if;

	if l_role_name is null then
		l_role_name = 'role:user';
	end if;
	if l_role_name = '' then
		l_role_name = 'role:user';
	end if;

	if not l_fail then
		if not q_admin_HasPriv ( l_user_id, 'May Login' ) then
			if l_debug_on then
				insert into t_output ( msg ) values ( 'Failed to find priv ''May Login'' ->'||l_user_id||'<-');
			end if;
			l_fail = true;
			l_data = '{"status":"error","msg":"Account lacks ''May Login'' privilege","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account lacks ''May Login'' privilege', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;
	end if;

	if not l_fail then
		if l_validation_method != 'un/pw' then
			l_fail = true;
			l_data = '{"status":"error","msg":"Account is not a un/pw authetication method","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account is not a un/pw autetication method', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;
	end if;

	if not l_fail then
		if l_email_validated = 'n' then
			-- Indicates partial registration, email_validated == "n", - code==="0020"
			l_fail = true;
			l_tmp_token = uuid_generate_v4();
			insert into q_qr_tmp_token ( user_id, token ) values ( l_user_id, l_tmp_token );
			if l_debug_on then
				insert into t_output ( msg ) values ( ' l_tmp_token ->'||coalesce(to_json(l_tmp_token)::text,'---null---')||'<-');
			end if;
			l_auth_token = NULL;
			-- xyzzyPartialReg, add tmp_token, email to message so can complete registration.
			l_data = '{"status":"error","msg":"Account has not been validated","code":"m4_count()","location":"m4___file__ m4___line__"'
				||', "tmp_token":'   		||coalesce(to_json(l_tmp_token)::text,'""')
				||', "email":'   			||coalesce(to_json(p_email)::text,'""')
				||'}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has not been validated', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;
	end if;

	if l_require_2fa = 'y' then
		if not l_fail then
			if l_setup_complete_2fa = 'n' then
				-- Indicates partial registration, setup_complete_2fa == "n", - code==="0220"
				l_fail = true;
				l_data = '{"status":"error","msg":"Account has not had 2Fa setup","code":"m4_count()","location":"m4___file__ m4___line__"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has not had 2Fa setup', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
			end if;
		end if;
	end if;

	if not l_fail then
		if l_start_date is not null then
			if l_start_date > current_timestamp then
				l_fail = true;
				l_data = '{"status":"error","msg":"Account has a start date that has not been reached","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has start date that has not been reached', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
			end if;
		end if;
	end if;

	if not l_fail then
		if l_end_date is not null then
			if l_end_date <= current_timestamp then
				l_fail = true;
				l_data = '{"status":"error","msg":"Account has an end date that has been reached","code":"m4_count()","location":"m4___file__ m4___line__"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has end date that has been reached', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
			end if;
		end if;
	end if;

	if not l_fail then
		l_auth_token = NULL;
		-- xyzzy8 - fingerprint -- add 3 params (done)
		if l_require_2fa = 'y' and p_am_i_known is not null then
			if p_am_i_known <> '' then
				-- id.json - check to see if user has been seen before on this device.
				select
						  t1.id
					into
						  l_manifest_id
					from q_qr_device_track as t1
					where t1.id = p_am_i_known::uuid
					  and t1.user_id = l_user_id
				;
				if not found then
					if l_debug_on then
						insert into t_output ( msg ) values ( ' etag not found ' );
					end if;
					l_is_new_device_login = 'y';
				else
					update q_qr_device_track as t1
						set updated = current_timestamp
						  , n_login = n_login + 1
						where t1.id = l_manifest_id
					;
					l_require_2fa = 'n';
					if l_debug_on then
						insert into t_output ( msg ) values ( ' skipping 2fa token - device is known ' );
					end if;
				end if;
			end if;
		end if;
		if l_require_2fa = 'n' then
			-- insert / create auth_token
			l_auth_token = uuid_generate_v4();
			BEGIN
				insert into q_qr_auth_tokens ( token, user_id, sc_id ) values ( l_auth_token, l_user_id, p_sc_id );
			EXCEPTION WHEN unique_violation THEN
				l_fail = true;
				l_data = '{"status":"error","msg":"Unable to create user/auth-token.","code":"m4_count()","location":"m4___file__ m4___line__"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to create user/auth-token.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
			END;
		end if;
	end if;

	if not l_fail then
		if l_login_failures >= 6 and l_failed_login_timeout >= current_timestamp then
			l_fail = true;
			l_data = '{"status":"error","msg":"Too many failed login attempts - please wait 1 minute.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Too many failed login attempts - please wait 1 minute.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
			update q_qr_users
				set failed_login_timeout = current_timestamp + interval '1 minute'
				where user_id = l_user_id
				  and failed_login_timeout is null
				;
		end if;
	end if;

	if not l_fail then
		select json_agg(t0.priv_name)::text
		into l_privileges
		from (
			select json_object_keys(t1.allowed::json)::text  as priv_name
				from q_qr_role2 as t1
				where t1.role_name = l_role_name
			) as t0
			;

		-- xyzzyError100 - never true iff.
		if not found then
			if l_debug_on then
				insert into t_output ( msg ) values ( 'Failed to get the privileges for the user' );
			end if;
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to get privileges for the user.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			l_privileges = '[]';
		end if;
	end if;

	if not l_fail then
		l_user_config = '[]';

		-- q8_user_config.sql
		select
				json_agg(
					json_build_object(
						'config_id', config_id,
						'name', name,
						'value', value
					)
				)::text as data
			into l_user_config
			from q_qr_user_config as t1
			where t1.user_id = l_user_id
			;

		if not found then
			l_user_config = '[]';
		end if;
	end if;

	if not l_fail then

		if l_debug_on then
			insert into t_output ( msg ) values ( 'function ->q_quth_v1_login<-..... Continued ...  m4___file__ m4___line__' );
			insert into t_output ( msg ) values ( 'calculate l_user_id ->'||coalesce(to_json(l_user_id)::text,'---null---')||'<-');
			insert into t_output ( msg ) values ( 'calculate l_privs ->'||coalesce(l_privileges,'---null---')||'<-');
			insert into t_output ( msg ) values ( 'calculate l_client_id ->'||coalesce(to_json(l_client_id)::text,'---null---')||'<-');
		end if;
		update q_qr_users
			set
				  failed_login_timeout = null
				, login_failures = 0
				, login_success = login_success + 1
				, privileges = l_privileges
		  		, email_verify_token = null
			where user_id = l_user_id
			;
		if l_require_2fa = 'y' then
			l_auth_token = NULL;
		end if;
		-- add tmp_token, email to message so can complete registration.
		l_tmp_token = uuid_generate_v4();
		insert into q_qr_tmp_token ( user_id, token, auth_token ) values ( l_user_id, l_tmp_token, l_auth_token );
		if l_debug_on then
			insert into t_output ( msg ) values ( ' l_tmp_token ->'||coalesce(to_json(l_tmp_token)::text,'---null---')||'<-');
		end if;
		if l_require_2fa = 'y' then
			if l_debug_on then
				insert into t_output ( msg ) values ( 'function ->q_quth_v1_login<-..... Continued ... 2fa Required  m4___file__ m4___line__' );
			end if;
			l_auth_token = NULL;
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Login - Part 1 Success tmp_token:'||l_tmp_token::text||' email:'||p_email, 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		else
			if l_debug_on then
				insert into t_output ( msg ) values ( 'function ->q_quth_v1_login<-..... Continued ... No 2fa login   m4___file__ m4___line__' );
			end if;
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Login Success email:'||p_email, 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
			if l_is_new_device_login = 'y' then

				if l_debug_on then
					insert into t_output ( msg ) values ( 'function ->q_quth_v1_login<-..... Continued ...  is a new device m4___file__ m4___line__' );
				end if;
				insert into q_qr_device_track (
					  fingerprint_data
					, sc_id
					, header_hash
					, user_id
					, am_i_known
				) values (
					  p_fingerprint
					, p_sc_id
					, p_hash_of_headers
					, l_user_id
					, p_am_i_known
				) returning id into l_device_track_id;

			else

				if l_debug_on then
					insert into t_output ( msg ) values ( 'function ->q_quth_v1_login<-..... Continued ... existing device m4___file__ m4___line__' );
				end if;
				update q_qr_device_track
					set n_login = n_login + 1
					  , am_i_known = p_am_i_known
					where id = l_device_track_id;

				GET DIAGNOSTICS v_cnt = ROW_COUNT;
				if v_cnt != 1 then

					l_is_new_device_login = 'n';
					insert into q_qr_device_track (
						  fingerprint_data
						, sc_id
						, header_hash
						, user_id
						, am_i_known
					) values (
						  p_fingerprint
						, p_sc_id
						, p_hash_of_headers
						, l_user_id
						, p_am_i_known
					) returning id into l_device_track_id;

				end if;

			end if;

			if l_debug_on then
				insert into t_output ( msg ) values ( 'function ->q_quth_v1_login<-..... Continued ... insert into q_qr_valid_xref_id m4___file__ m4___line__' );
			end if;
			insert into q_qr_valid_xsrf_id (
				  device_track_id
				, user_id
				, xsrf_id
			) values (
				  l_device_track_id
				, l_user_id
				, p_xsrf_id::uuid
			);

		end if;

		-- client_cfg				text not null default 'n',		-- if 'y' then report to client.
		l_client_user_config = '{}';
		SELECT json_agg(t1)
			INTO l_client_user_config
			FROM (
					select t2.name, t2.value
					from q_qr_user_config t2
					where t2.user_id = l_user_id
					  and t2.client_cfg = 'y'
					order by 1
				) as t1
			;
		if not found then
			l_client_user_config = '{}';
		end if;

		-- xyzzyOnSuccessfulX

		l_data = '{"status":"success"'
			||', "user_id":'     			||coalesce(to_json(l_user_id)::text,'""')
			||', "auth_token":'  			||coalesce(to_json(l_auth_token)::text,'""')
			||', "tmp_token":'   			||coalesce(to_json(l_tmp_token)::text,'""')
			||', "require_2fa":' 			||coalesce(to_json(l_require_2fa)::text,'""')
			||', "secret_2fa":'  			||coalesce(to_json(l_secret_2fa)::text,'""')
			||', "account_type":'			||coalesce(to_json(l_account_type)::text,'""')
			||', "privileges":'  			||coalesce(l_privileges,'[]') -- $TYPE$ []string
			||', "user_config":'  			||coalesce(l_user_config,'{}') -- $TYPE$ map[string]string
			||', "client_user_config":'  	||coalesce(l_client_user_config,'{}') -- $TYPE$ map[string]string
			||', "first_name":'  			||coalesce(to_json(l_first_name)::text,'""')
			||', "last_name":'   			||coalesce(to_json(l_last_name)::text,'""')
			||', "is_new_device_login":' 	||coalesce(to_json(l_is_new_device_login)::text,'"n"')
			||', "client_id":'     			||coalesce(to_json(l_client_id)::text,'""')
			||', "acct_state":'     		||coalesce(to_json(l_acct_state)::text,'""')
			||', "is_new_device_msg":' 		||coalesce(to_json(l_is_new_device_msg)::text,'"--not-set--')
			||'}';

		if l_debug_on then
			insert into t_output ( msg ) values ( 'function ->q_quth_v1_login<-..... Continued ... data==success m4___file__ m4___line__' );
		end if;

	else
		if l_user_id is not null then
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Login Failure email:'||p_email, 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
			if l_debug_on then
				insert into t_output ( msg ) values ( 'function ->q_quth_v1_login<-..... Continued ... --- has user_id, status=failed/error --- m4___file__ m4___line__' );
			end if;
			if l_failed_login_timeout is not null then
				update q_qr_users
					set login_failures = login_failures + 1
					where user_id = l_user_id
					  and failed_login_timeout is not null
					  and login_failures >= 6
					;
			else
				update q_qr_users
					set login_failures = login_failures + 1
					  , failed_login_timeout = current_timestamp + interval '1 minute'
					where user_id = l_user_id
					  and failed_login_timeout is null
					  and login_failures >= 6
					;
				update q_qr_users
					set login_failures = login_failures + 1
					where user_id = l_user_id
					  and failed_login_timeout is null
					  and login_failures < 6
					;
			end if;
		end if;
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;












-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION q_auth_v1_get_user_config ( p_user_id uuid, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_debug_on 				bool;
	l_user_config			text;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_get_user_config<- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '  p_user_id ->'||coalesce(to_json(p_user_id)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||coalesce(to_json(p_hmac_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_userdata_password ->'||coalesce(to_json(p_userdata_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;


	if not l_fail then

		select x_user_config::json
		  	into l_user_config
		 	from q_qr_users
			where user_id = p_user_id
			;

		if not found then
			l_user_config = '{}'::jsonb;
		end if;

	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "user_config":'  			||coalesce(l_user_config,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;





--			stmt := "q_auth_v1_set_user_config ( $1, $2, $3, $4, $5, $6 )"
--			rv, err := CallDatabaseJSONFunction(c, stmt, "eeeee..", vv.ConfigId, vv.Name, vv.Value, UserId, gCfg.EncryptionPassword, gCfg.UserdataPassword)

-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- drop function q_auth_v1_set_user_config ( p_config_id varchar, p_name varchar, p_value varchar, p_user_id uuid, p_hmac_password varchar, p_userdata_password varchar );

CREATE OR REPLACE FUNCTION q_auth_v1_set_user_config ( p_name varchar, p_value varchar, p_user_id uuid, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_debug_on 				bool;
	l_user_config			jsonb;
	l_config_id				uuid;
	l_path					text[];
	l_value					jsonb;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_get_user_config<- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '  p_name->'||coalesce(to_json(p_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_value ->'||coalesce(to_json(p_value)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_user_id ->'||coalesce(to_json(p_user_id)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||coalesce(to_json(p_hmac_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_userdata_password ->'||coalesce(to_json(p_userdata_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	if not l_fail then

		select x_user_config::json
		  	into l_user_config
		 	from q_qr_users
			where user_id = p_user_id
			;

		if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid user_id for setting user configuration","code":"m4_count()","location":"m4___file__ m4___line__"}';
		end if;

	end if;

	if not l_fail then

		l_path[0] = p_name;
		l_value = to_jsonb(p_value);
		select jsonb_set(l_user_config, l_path, l_value)
			into l_user_config
			;

		update q_qr_users
			set x_user_config = l_user_config
			where user_id = p_user_id
		;

	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "user_config":'  			||coalesce(l_user_config,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;

-- select q_auth_v1_set_user_config ( ' ', 'show-upload-button', 'xxx', '71fee0ec-5697-4d45-9759-5a6db492adc1'::uuid, ' ', ' ');
-- select q_auth_v1_set_user_config ( ' ', 'light-mode', 'dark', '71fee0ec-5697-4d45-9759-5a6db492adc1'::uuid, ' ', ' ');







-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- 3. q_auth_v1_regen_otp
-- drop function q_auth_v1_regen_otp ( p_email varchar, p_pw varchar, p_hmac_password varchar );

CREATE OR REPLACE FUNCTION q_auth_v1_regen_otp ( p_email varchar, p_pw varchar, p_hmac_password varchar , p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_tmp					text;
	l_fail					bool;
	l_debug_on 				bool;
	l_user_id				uuid;
	ii						int;
	l_otp_str				text;
	l_otp_com				text;
	v_cnt 					int;
	l_first_name			text;
	l_last_name				text;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if not l_fail then
		select
			  user_id
			, pgp_sym_decrypt(first_name_enc,p_userdata_password)::text as x_first_name
			, pgp_sym_decrypt(last_name_enc,p_userdata_password)::text as x_last_name
		into
			  l_user_id
			, l_first_name
			, l_last_name
		from q_qr_users as t1
		where t1.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
			and	account_type = 'login'
			and password_hash = crypt(p_pw, password_hash)
			and parent_user_id is null
		;

		if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Password/attempt to create new OTP","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Password/attempt to create new OTP', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;

	end if;

	if not l_fail then

		delete from q_qr_one_time_password where user_id = l_user_id;

		-- Generate OTP passwords - 20 of them.
		l_otp_str = '[';
		l_otp_com = '';
		for ii in 1..20 loop
			l_tmp = uuid_generate_v4();
			l_tmp = substr(l_tmp,0,7) || substr(l_tmp,10,4);
			-- insert into q_qr_one_time_password ( user_id, otp_hash ) values ( l_user_id, crypt(l_tmp, gen_salt('bf') ) );
			insert into q_qr_one_time_password ( user_id, otp_hmac ) values ( l_user_id, q_auth_v1_hmac_encode ( l_tmp, p_hmac_password ) );
			l_otp_str = l_otp_str || l_otp_com || to_json(l_tmp);
			l_otp_com = ',';
			-- insert into t_output ( msg ) values ( '->'||coalesce(to_json(l_otp_str)::text,'---null---')||'<-');
		end loop;
		l_otp_str = l_otp_str || ']';

	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "user_id":' 			||coalesce(to_json(l_user_id)::text,'""')
			||', "otp":' 				||l_otp_str
			||', "first_name":'  		||coalesce(to_json(l_first_name)::text,'""')
			||', "last_name":'   		||coalesce(to_json(l_last_name)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;












-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Create a device/api - sub-account that login occures with a "un/pw" instead of a un/pw/2fa.
--	{Method: "POST", Path: "/api/v1/auth/register-un-pw", Fx: authHandleRegisterUnPw, UseLogin: LoginRequired},               //
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION q_auth_v1_register_un_pw ( p_parent_user_id uuid, p_email varchar, p_hmac_password varchar,  p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_junk					text;
	l_user_id				uuid;
	l_bad_user_id			uuid;
	l_debug_on 				bool;
	l_pw					text;
	l_2fa_id				uuid;
	l_email_validated		varchar(1);
	l_start_date			timestamp;
	l_end_date				timestamp;
	l_privileges			jsonb;
	l_failed_login_timeout 	timestamp;
	l_login_failures 		int;
	l_tmp_token				uuid;	-- when 2fa is on this is returnd as not null (UUID)
	l_first_name			text;
	l_last_name				text;
	l_auth_token			uuid;
	l_email					uuid;
BEGIN

	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()

	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_register_un_pw<- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '  p_parent_user_id ->'||coalesce(to_json(p_parent_user_id)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_email ->'||coalesce(to_json(p_email)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||coalesce(to_json(p_hmac_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_userdata_password ->'||coalesce(to_json(p_userdata_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	l_pw = encode(digest(uuid_generate_v4()::text, 'sha256'), 'base64');

	if not l_fail then
		select
			  user_id
			, email_validated
			, start_date
			, end_date
		    , pgp_sym_decrypt(first_name_enc,p_userdata_password)::text as first_name
		    , pgp_sym_decrypt(last_name_enc,p_userdata_password)::text as last_name
			, failed_login_timeout
			, login_failures
		    , pgp_sym_decrypt(t1.email_enc,p_userdata_password)::text as email
		into
			  l_user_id
			, l_email_validated
			, l_start_date
			, l_end_date
			, l_first_name
			, l_last_name
			, l_failed_login_timeout
			, l_login_failures
			, l_email
		from q_qr_users
		where user_id = p_parent_user_id
			and account_type = 'login'
		;
		if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Password","code":"m4_count()","location":"m4___file__ m4___line__"}'; -- return no such account or password
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Password', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;
	end if;

	-- xyzzy Privs

	if l_debug_on then
		insert into t_output ( msg ) values ( '->'||coalesce(to_json(p_userdata_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( 'l_first_name = ->'||coalesce(to_json(l_first_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( 'l_last_name = ->'||coalesce(to_json(l_last_name)::text,'---null---')||'<-');
	end if;

	if not l_fail then
		if l_email_validated = 'n' then
			l_fail = true;
			l_data = '{"status":"error","msg":"Account has not not been validated","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has not been validated', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;
	end if;
	if not l_fail then
		if l_start_date is not null then
			if l_start_date > current_timestamp then
				l_fail = true;
				l_data = '{"status":"error","msg":"Account has a start date that has not been reached","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has start date that has not been reached', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
			end if;
		end if;
	end if;
	if not l_fail then
		if l_end_date is not null then
			if l_end_date <= current_timestamp then
				l_fail = true;
				l_data = '{"status":"error","msg":"Account has an end date that has been reached","code":"m4_count()","location":"m4___file__ m4___line__"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has end date that has been reached', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
			end if;
		end if;
	end if;

	if not l_fail then
		if l_require_2fa = 'n' then
			-- insert / create auth_token
			l_auth_token = uuid_generate_v4();
			BEGIN
				insert into q_qr_auth_tokens ( token, user_id, sc_id ) values ( l_auth_token, l_user_id, l_sc_id );
			EXCEPTION WHEN unique_violation THEN
				l_fail = true;
				l_data = '{"status":"error","msg":"Unable to create user/auth-token.","code":"m4_count()","location":"m4___file__ m4___line__"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to create user/auth-token.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
			END;
		end if;
	end if;
	if not l_fail then
		if l_login_failures > 6 or l_failed_login_timeout >= current_timestamp then
			l_fail = true;
			l_data = '{"status":"error","msg":"Too many failed login attempts - please wait 1 minute.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Too many failed login attempts - please wait 1 minute.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
			update q_qr_users
				set failed_login_timeout = current_timestamp + interval '1 minute'
				where user_id = l_user_id
				  and failed_login_timeout is null
				;
		end if;
	end if;

	if not l_fail then
		INSERT INTO q_qr_users (
			  email_hmac
			, password_hash
			, first_name_enc
			, last_name_enc
			, parent_user_id
			, account_type
			, email_validated
			, role_name
		) VALUES (
			  q_auth_v1_hmac_encode ( p_email, p_hmac_password )
			, crypt(l_pw, gen_salt('bf') )
		    , pgp_sym_encrypt(l_first_name,p_userdata_password)
		    , pgp_sym_encrypt(l_last_name,p_userdata_password)
			, p_parent_user_id
			, 'un/pw'
			, 'y'
			, 'role:user'
		) returning user_id into l_user_id  ;

		--insert into q_qr_user_role ( user_id, role_id )
		--	select l_user_id, t1.role_id
		--	from q_qr_role as t1
		--	where t1.role_name =  'role:user'
		--	;

		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'User Registered', 'File:m4___file__ Line No:m4___line__');

	end if;

	insert into q_qr_user_hierarchy ( user_id, parent_user_id ) values ( l_user_id, p_parent_user_id );

	if not l_fail then
		l_tmp_token = uuid_generate_v4();
		insert into q_qr_tmp_token ( user_id, token ) values ( l_user_id, l_tmp_token );

		-- xyzzyOnSuccessfulX
		-- if 'q_qr_post_register' exists then ... call with  ( l_user_id, l_tmp_token, l_pw, l_first_name, l_last_name, l_email, p_parent_user_id, p_hmac_password,  p_userdata_password );
		-- 	SELECT EXISTS (
		--         SELECT *
		--         FROM pg_catalog.pg_proc
		--         JOIN pg_namespace ON pg_catalog.pg_proc.pronamespace = pg_namespace.oid
		--         WHERE proname = 'q_qr_post_register'
		--             AND pg_namespace.nspname = 'public'
		--         );

		l_data = '{"status":"success"'
			||', "user_id":' 		||coalesce(to_json(l_user_id)::text,'""')
			||', "tmp_token":'  	||coalesce(to_json(l_tmp_token)::text,'""')
			||', "pw":' 			||coalesce(to_json(l_pw)::text,'""')
			||', "first_name":'  	||coalesce(to_json(l_first_name)::text,'""')
			||', "last_name":'   	||coalesce(to_json(l_last_name)::text,'""')
			||', "email":' 			||coalesce(to_json(l_email)::text,'""')
			||'}';

	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;







-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--	{Method: "POST", Path: "/api/v1/auth/register-token", Fx: authHandleRegisterToken, UseLogin: LoginRequired},              //
-- Create a device/api - sub-account that login occures with a "token" instead of a un/pw/2fa or a un/pw account
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION q_auth_v1_register_token ( p_parent_user_id uuid,  p_hmac_password varchar,  p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_junk					text;
	l_user_id				uuid;
	l_bad_user_id			uuid;
	l_debug_on 				bool;
	l_pw					text;
	l_un					text;
	l_2fa_id				uuid;
	l_email_validated		varchar(1);
	l_start_date			timestamp;
	l_end_date				timestamp;
	l_privileges			jsonb;
	l_failed_login_timeout 	timestamp;
	l_login_failures 		int;
	l_tmp_token				uuid;	-- when 2fa is on this is returnd as not null (UUID)
	l_first_name			text;
	l_last_name				text;
	l_auth_token			uuid;
	l_email					text;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()

	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_register_token<- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '  p_parent_user_id ->'||coalesce(to_json(p_parent_user_id)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||coalesce(to_json(p_hmac_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_userdata_password ->'||coalesce(to_json(p_userdata_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	l_un = encode(digest(uuid_generate_v4()::text, 'sha256'), 'base64');
	l_pw = encode(digest(uuid_generate_v4()::text, 'sha256'), 'base64');

	if not l_fail then
		select
			  user_id
			, email_validated
			, start_date
			, end_date
		    , pgp_sym_decrypt(first_name_enc,p_userdata_password)::text as first_name
		    , pgp_sym_decrypt(last_name_enc,p_userdata_password)::text as last_name
			, failed_login_timeout
			, login_failures
		    , pgp_sym_decrypt(t1.email_enc,p_userdata_password)::text as email
		into
			  l_user_id
			, l_email_validated
			, l_start_date
			, l_end_date
			, l_first_name
			, l_last_name
			, l_failed_login_timeout
			, l_login_failures
			, l_email
		from q_qr_users
		where user_id = p_parent_user_id
			and account_type = 'login'
		;
		if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Password","code":"m4_count()","location":"m4___file__ m4___line__"}'; -- return no such account or password
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Password', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;
	end if;

	-- xyzzy Privs

	if l_debug_on then
		insert into t_output ( msg ) values ( '->'||coalesce(to_json(p_userdata_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( 'l_first_name = ->'||coalesce(to_json(l_first_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( 'l_last_name = ->'||coalesce(to_json(l_last_name)::text,'---null---')||'<-');
	end if;

	if not l_fail then
		if l_email_validated = 'n' then
			l_fail = true;
			l_data = '{"status":"error","msg":"Account has not been validated","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has not been validated', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;
	end if;
	if not l_fail then
		if l_start_date is not null then
			if l_start_date > current_timestamp then
				l_fail = true;
				l_data = '{"status":"error","msg":"Account has a start date that has not been reached","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has start date that has not been reached', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
			end if;
		end if;
	end if;
	if not l_fail then
		if l_end_date is not null then
			if l_end_date <= current_timestamp then
				l_fail = true;
				l_data = '{"status":"error","msg":"Account has an end date that has been reached","code":"m4_count()","location":"m4___file__ m4___line__"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has end date that has been reached', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
			end if;
		end if;
	end if;

	if not l_fail then
		if l_require_2fa = 'n' then
			-- insert / create auth_token
			l_auth_token = uuid_generate_v4();
			BEGIN
				insert into q_qr_auth_tokens ( token, user_id ) values ( l_auth_token, l_user_id );
			EXCEPTION WHEN unique_violation THEN
				l_fail = true;
				l_data = '{"status":"error","msg":"Unable to create user/auth-token.","code":"m4_count()","location":"m4___file__ m4___line__"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to create user/auth-token.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
			END;
		end if;
	end if;
	if not l_fail then
		if l_login_failures > 6 or l_failed_login_timeout >= current_timestamp then
			l_fail = true;
			l_data = '{"status":"error","msg":"Too many failed login attempts - please wait 1 minute.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Too many failed login attempts - please wait 1 minute.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
			update q_qr_users
				set failed_login_timeout = current_timestamp + interval '1 minute'
				where user_id = l_user_id
				  and failed_login_timeout is null
				;
		end if;
	end if;

	if not l_fail then
		INSERT INTO q_qr_users (
			  email_hmac
			, password_hash
			, first_name_enc
			, last_name_enc
			, parent_user_id
			, account_type
			, email_validated
			, role_name
		) VALUES (
			  q_auth_v1_hmac_encode ( p_email, p_hmac_password )
			, crypt(l_pw, gen_salt('bf') )
		    , pgp_sym_encrypt(l_first_name,p_userdata_password)
		    , pgp_sym_encrypt(l_last_name,p_userdata_password)
			, p_parent_user_id
			, 'token'
			, 'y'
			, 'role:user'
		) returning user_id into l_user_id  ;

		--insert into q_qr_user_role ( user_id, role_id )
		--	select l_user_id, t1.role_id
		--	from q_qr_role as t1
		--	where t1.role_name =  'role:user'
		--	;

		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'User Registered', 'File:m4___file__ Line No:m4___line__');
	end if;

	insert into q_qr_user_hierarchy ( user_id, parent_user_id ) values ( l_user_id, p_parent_user_id );

	if not l_fail then
		l_tmp_token = uuid_generate_v4();
		insert into q_qr_tmp_token ( user_id, token ) values ( l_user_id, l_tmp_token );
		l_data = '{"status":"success"'
			||', "user_id":' 			||coalesce(to_json(l_user_id)::text,'""')
			||', "tmp_token":'   		||coalesce(to_json(l_tmp_token)::text,'""')
			||', "login_token":' 		||coalesce(to_json(l_un)::text,'""')
			||', "first_name":'  		||coalesce(to_json(l_first_name)::text,'""')
			||', "last_name":'   		||coalesce(to_json(l_last_name)::text,'""')
			||', "email":'   			||coalesce(to_json(l_email)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;













-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--		stmt := "q_auth_v1_refresh_token ( $1, $2, $3, $4 )"
--		rv, e0 := CallDatabaseJSONFunction(c, stmt, "e!..", UserID, AuthToken, gCfg.EncryptionPassword, gCfg.UserdataPassword)
--	UserId           string           `json:"user_id,omitempty"`
--	Require2fa       string           `json:"require_2fa,omitempty"`
--	AccountType      string           `json:"account_type,omitempty"`
--	Privileges       []string         `json:"privileges,omitempty"`
--	FirstName        string           `json:"first_name,omitempty"`
--	LastName         string           `json:"last_name,omitempty"`
--	AcctState        string           `json:"acct_state",omitempty"`
--	UserConfig       []UserConfigData `json:"user_config",omitempty"`
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

drop function if exists q_auth_v1_refresh_token ( p_user_id varchar, p_auth_token varchar);
drop function if exists q_auth_v1_refresh_token ( p_user_id varchar, p_auth_token varchar, p_hmac_password varchar );
drop function if exists q_auth_v1_refresh_token ( p_email varchar, p_token varchar, p_hmac_password varchar ); -- old -- dup --

CREATE OR REPLACE FUNCTION q_auth_v1_refresh_token ( p_user_id varchar, p_auth_token varchar, p_am_i_known varchar, p_hmac_password varchar,  p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_debug_on 				bool;
	l_auth_token			uuid;
	l_user_id				uuid;
	l_account_type			varchar(20);
	l_privileges			text;
	l_user_config			jsonb;
	l_first_name			text;
	l_last_name				text;
	l_tmp					text;
	l_acct_state			text;
	l_manifest_id 			uuid;
	l_email					text;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';
	l_email = '';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_auth_v1_refresh_token<- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '  p_user_id ->'||coalesce(to_json(p_user_id)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_auth_token ->'||coalesce(to_json(p_auth_token)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_am_i_known ->'||coalesce(to_json(p_am_i_known)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	-- Check current token is still valid
	-- 		Check that UserID matches with auth_token
	select t1.user_id
		  , t1.account_type
		  , pgp_sym_decrypt(first_name_enc,p_userdata_password)::text as first_name
		  , pgp_sym_decrypt(last_name_enc,p_userdata_password)::text as last_name
		  , t1.acct_state
		  , t1.x_user_config
		  , pgp_sym_decrypt(email_enc,p_userdata_password)::text as email
		into l_user_id
			, l_account_type
			, l_first_name
			, l_last_name
			, l_acct_state
			, l_user_config
			, l_email
		from q_qr_users as t1
			join q_qr_auth_tokens as t2 on ( t2.user_id = t1.user_id )
		where t1.user_id = p_user_id::uuid
		  and t2.token = p_auth_token::uuid
		;

	if not found then
		l_fail = true;
		l_data = '{"status":"error","msg":"Unable to create user/auth-token.  Current token is invalid.","code":"m4_count()","location":"m4___file__ m4___line__"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to create user/auth-token.  Current token is invalid.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
	end if;

	if not l_fail then
		if p_am_i_known is not null then
			if p_am_i_known <> '' then
				-- id.json - check to see if user has been seen before on this device.
				select
						  t1.id
					into
						  l_manifest_id
					from q_qr_device_track as t1
					where t1.id = p_am_i_known::uuid
					  and t1.user_id = l_user_id
				;
				if not found then

						insert into q_qr_device_track ( id, user_id )
							values (  p_am_i_known::uuid, l_user_id )
							on conflict (id) do
								update
									set user_id = l_user_id
							;

					l_manifest_id = p_am_i_known::uuid;

					--if l_debug_on then
					--	insert into t_output ( msg ) values ( ' etag not found ' );
					--end if;
					--l_fail = true;
					--l_data = '{"status":"401","msg":"Unable to create user/auth-token (1).  Current token is invalid.","code":"m4_count()","location":"m4___file__ m4___line__"}';
					--insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to create user/auth-token.  Current token is invalid.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
				end if;
			end if;
		end if;
	end if;

	if not l_fail then
		select token::text, expires
			into l_auth_token
			from q_qr_auth_tokens
			where expires > current_timestamp + interval '10 day'
			  and user_id = p_user_id::uuid
			  and token = p_auth_token::uuid
			;
		if not found then
			-- insert / create auth_token
			l_auth_token = uuid_generate_v4();
			BEGIN
				insert into q_qr_auth_tokens ( token, user_id ) values ( l_auth_token, l_user_id );
			EXCEPTION WHEN unique_violation THEN
				l_fail = true;
				l_data = '{"status":"error","msg":"Unable to create user/auth-token. (2)","code":"m4_count()","location":"m4___file__ m4___line__"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to create user/auth-token.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
			END;
		end if;
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "auth_token":'  			||coalesce(to_json(l_auth_token)::text,'""')
			||', "user_id":'     			||coalesce(to_json(l_user_id)::text,'""')
			||', "account_type":'			||coalesce(to_json(l_account_type)::text,'""')
			||', "first_name":'  			||coalesce(to_json(l_first_name)::text,'""')
			||', "last_name":'   			||coalesce(to_json(l_last_name)::text,'""')
			||', "email_address":'  		||coalesce(to_json(l_email)::text,'""')
			||', "acct_state":'     		||coalesce(to_json(l_acct_state)::text,'""')
			||', "user_config":'  			||coalesce(l_user_config,'"{}"')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;


-- insert into q_qr_device_track ( id, etag_seen, user_id ) values ( 'f2042a79-0df2-475a-6e35-3739cd323931', '35f2f2fd35988b400000', '11f670e5-944f-4200-99b2-874fcc964dab' );
-- select q_auth_v1_refresh_token ( '11f670e5-944f-4200-99b2-874fcc964dab', '92c8497f-fe5c-4692-b0ed-8cd5e7d62d64', 'f2042a79-0df2-475a-6e35-3739cd323931', 'my long secret password', 'user info password' );














-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- q_auth_v1_email_verify uses the token to lookup a user and confirms that the email that received the token is real.
--
-- Updates q_qr_users
--
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- drop function q_auth_v1_email_verify ( p_email_verify_token varchar );

DROP FUNCTION if exists q_auth_v1_email_verify ( p_email_verify_token varchar, p_hmac_password varchar, p_userdata_password varchar ) ;

CREATE OR REPLACE FUNCTION q_auth_v1_email_verify ( p_email_verify_token varchar, p_hmac_password varchar, p_userdata_password varchar, p_n6_flag varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_junk					text;
	l_fail					bool;
	v_cnt 					int;
	l_validated				text;
	l_email					text;
	l_debug_on 				bool;
	l_tmp_token				uuid;	-- when 2fa is on this is returnd as not null (UUID)
	l_user_id				uuid;
	l_acct_state			text;
	l_setup_complete_2fa  	varchar(1);
	l_email_verify_token	text;
	l_require_2fa			text;
	l_n6_token				int;
	l_auth_token			text;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function -> q_auth_v1_email_verify (v2) <- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '  p_email_verify_token ->'||coalesce(to_json(p_email_verify_token)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_n6_flag ->'||coalesce(to_json(p_n6_flag)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	-- check that the token is a number
	if p_n6_flag = 'n6' then
		begin
			l_n6_token = p_email_verify_token::int;
		exception
			when others then
				l_fail = true;
				l_data = '{"status":"error","msg":"Not incorrect data for token","code":"m4_count()","location":"m4___file__ m4___line__"}';
		end;
	end if;

	if not l_fail then
		-- CREATE TABLE if not exists q_qr_n6_email_verify (
		-- 	n6_token 				int not null,
		-- 	email_verify_token		uuid not null

		if p_n6_flag = 'n6' or p_n6_flag = 'n8' then
			select email_verify_token::text
				into l_email_verify_token
				from q_qr_n6_email_verify
				where n6_token = l_n6_token
				;
			if not found then
				l_fail = true;
				l_data = '{"status":"error","msg":"Token not found/invalid token.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			end if;
		else
			l_email_verify_token = p_email_verify_token;
		end if;

		if l_debug_on then
			insert into t_output ( msg ) values ( '  l_email_verify_token ->'||coalesce(to_json(l_email_verify_token)::text,'---null---')||'<-');
		end if;

	end if;

	if not l_fail then

		select t1.user_id
				, pgp_sym_decrypt(t1.email_enc,p_userdata_password)::text as email
				, setup_complete_2fa
				, acct_state
				, require_2fa
			into l_user_id
				, l_email
				, l_setup_complete_2fa
				, l_acct_state
				, l_require_2fa
			from q_qr_users as t1
			where t1.email_verify_expire > current_timestamp
				and t1.email_verify_token = l_email_verify_token::uuid
			;
		if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to validate account via email.  Please register again.","code":"m4_count()","location":"m4___file__ m4___line__"}';
		end if;
		if l_debug_on then
			insert into t_output ( msg ) values ( '  l_email ->'||coalesce(to_json(l_email)::text,'---null---')||'<-');
			insert into t_output ( msg ) values ( '  l_setup_complete_2fa ->'||coalesce(to_json(l_setup_complete_2fa)::text,'---null---')||'<-');
			insert into t_output ( msg ) values ( '  l_user_id ->'||coalesce(to_json(l_user_id)::text,'---null---')||'<-');
			insert into t_output ( msg ) values ( '  l_require_2fa ->'||coalesce(to_json(l_require_2fa)::text,'---null---')||'<-');
		end if;

	end if;

	if not l_fail then

		if l_require_2fa = 'y' then
			if l_setup_complete_2fa = 'y' and l_acct_state = 'reg0' then
				l_acct_state = 'reg1';
			end if;
		else
			if l_acct_state = 'reg0' then
				l_acct_state = 'reg1';
			end if;
		end if;

	end if;

	if not l_fail then
		if p_n6_flag = 'n6' or p_n6_flag = 'n8' then
			delete from q_qr_n6_email_verify
				where n6_token = l_n6_token
				;
		end if;
		update q_qr_users
			set email_validated = 'y'
			  , email_verify_expire = null
			  , acct_state = l_acct_state
			where email_verify_expire > current_timestamp
				and email_verify_token = l_email_verify_token::uuid
		;
		GET DIAGNOSTICS v_cnt = ROW_COUNT;
		if v_cnt != 1 then
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to validate account via email.  Please register again.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to validate account via email..', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;
	end if;

	if not l_fail then
		l_tmp_token = uuid_generate_v4();
		insert into q_qr_tmp_token ( user_id, token ) values ( l_user_id, l_tmp_token );
		if l_debug_on then
			insert into t_output ( msg ) values ( '  l_tmp_token ->'||coalesce(to_json(l_tmp_token)::text,'---null---')||'<-');
		end if;
		l_data = '{"status":"success"'
			||', "email":'   	||coalesce(to_json(l_email)::text,'""')
			||', "tmp_token":'  ||coalesce(to_json(l_tmp_token)::text,'""')
			||', "auth_token":'	||coalesce(to_json(l_auth_token)::text,'""')
			||', "user_id":'	||coalesce(to_json(l_user_id)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;





-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- q_auth_v1_logout will logout a single auth_token on a particular user.  The token is deleted.
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION q_auth_v1_logout ( p_email varchar, p_auth_token varchar, p_hmac_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_junk					text;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	delete from q_qr_auth_tokens as t1
		where t1.token = p_auth_token::uuid
		  and exists (
			select 'found'
			from q_qr_users as t2
			where t2.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
			  and t2.user_id = t1.user_id
		  )
		;

	if not l_fail then
		l_data = '{"status":"success"'
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;



-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- stmt = "q_auth_v1_setup_2fa_test ( $1 )"
-- drop function q_auth_v1_setup_2fa_test ( p_user_id uuid );

CREATE OR REPLACE FUNCTION q_auth_v1_setup_2fa_test ( p_user_id uuid, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()

	update q_qr_users as t1
		set setup_complete_2fa = 'y'
		where user_id = p_user_id
		;

	RETURN '{"status":"success"}';
END;
$$ LANGUAGE plpgsql;










-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Called as a part of login and registration.
--
-- This is called after validatio of the TOTP/HOTP token.
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION q_auth_v1_validate_2fa_token ( p_email varchar, p_tmp_token varchar, p_2fa_secret varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_user_id				uuid;
	l_auth_token 			uuid;
	l_privileges			text;
	l_secret_2fa 			varchar(20);
	l_debug_on 				bool;
	l_expires				text;
	l_email_validated		text;
	l_x2fa_validated		text;
	l_acct_state			text;
	l_login_2fa_failures 	int;
	l_role_name				text;
	l_junk					text;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';
	l_email_validated = 'n';
	l_x2fa_validated = 'n';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'In q_auth_v1_validate_2fa_token (v2)' );
		insert into t_output ( msg ) values ( '  p_email         ->'||coalesce(to_json(p_email)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_tmp_token     ->'||coalesce(to_json(p_tmp_token)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||coalesce(to_json(p_hmac_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	-- Expires is in 31 days - but tell the user that it is 30 days so that they have a day of grace.
	select (current_timestamp + interval '30 days')::text
		into l_expires
		;

	select t1.user_id
			, t1.secret_2fa
			, t1.email_validated
			, t1.setup_complete_2fa
			, t1.acct_state
			, t1.login_2fa_failures
			, t1.role_name
		into l_user_id
			, l_secret_2fa
			, l_email_validated
			, l_x2fa_validated
			, l_acct_state
			, l_login_2fa_failures
			, l_role_name
		from q_qr_users as t1
			join q_qr_tmp_token as t2 on ( t1.user_id = t2.user_id )
		where t1.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
		  and t1.secret_2fa = p_2fa_secret
		  and t2.token = p_tmp_token::uuid
		;

	if l_role_name is null then
		l_role_name = 'role:user';
	end if;
	if l_role_name = '' then
		l_role_name = 'role:user';
	end if;

	if not found then
		if l_debug_on then
			insert into t_output ( msg ) values ( 'Failed to find the user - may be expired token' );
		end if;
		l_email_validated = 'n';
		l_x2fa_validated = 'n';
		select user_id
				, secret_2fa
			into l_user_id
				, l_secret_2fa
			from q_qr_users as t1
			where t1.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
			  and t1.secret_2fa = p_2fa_secret
			;
		if not found then
			-- this is not really accurate - the l_tmp_token has expired.
			l_data = '{"status":"error","msg":"Your 2fa number has expired - please try again.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Expired 2fa number.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		else
			l_data = '{"status":"error","msg":"Your temporary login token has expired.  Please start your login process again.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Your temporary login token has expired.  Please start your login process again.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;
		l_fail = true;
	end if;

	if l_login_2fa_failures 	<= 0 then
		l_data = '{"status":"error","msg":"You have made too many attempts.  Please contact an admin to reset.","code":"m4_count()","location":"m4___file__ m4___line__"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'have made too many attempts.  Please contact an admin to reset.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		l_fail = true;
	end if;

	if not l_fail then
		-- if has not failed by this point then the user has validate and gets an 'l_auth_token'.
		if l_debug_on then
			insert into t_output ( msg ) values ( 'Seting the user up, acct_state = '||l_acct_state );
		end if;
		if l_email_validated = 'y' and l_acct_state = 'reg0' then
			l_acct_state = 'reg1';
		end if;
		-- mark login_2fa_failures to 10, this is a count-down item.
		update q_qr_users as t2
			set setup_complete_2fa 	= 'y'
			  , acct_state = l_acct_state
			  , login_2fa_failures 	= 10
			where t2.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
			;
		l_x2fa_validated = 'y';
		-- insert / create auth_token
		l_auth_token = uuid_generate_v4();
		BEGIN
			insert into q_qr_auth_tokens ( token, user_id ) values ( l_auth_token, l_user_id );
		EXCEPTION WHEN unique_violation THEN
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to create user/auth-token.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to create user/auth-token.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		END;
		-- xyzzyPartialReg
		-- Set this for use in web-socket connections that need to use tmp_token to lookup auth_token, tmp_token lasts for 20 min.
		update l_tmp_token
			set auth_token = l_auth_token
			where tmp_token = l_tmp_token
			;
	end if;

	-- Count Failures - this is on an error -
	if l_fail then
		update q_qr_users
			set login_2fa_failures = login_2fa_failures - 1
			where t1.user_id = l_user_id
			;
	end if;

	if not l_fail then

		-- xyzzy9999
		--select json_agg(t1.priv_name)::text
		--	into l_privileges
		--	from q_qr_user_to_priv as t1
		--	where t1.user_id = l_user_id
		--	;

		select json_agg(t0.priv_name)::text
		into l_privileges
		from (
			select json_object_keys(t1.allowed::json)::text  as priv_name
				from q_qr_role2 as t1
				where t1.role_name = l_role_name
			) as t0
			;

		if not found then
			if l_debug_on then
				insert into t_output ( msg ) values ( 'Failed to get the privileges for the user' );
			end if;
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to get privileges for the user.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			l_privileges = '';
		end if;
	end if;

	-- EmailConfirmed  string `json:"email_validated,omitempty"`
	if not l_fail then
		l_data = '{"status":"success"'
			||', "auth_token":'  	 	||coalesce(to_json(l_auth_token)::text,'""')
			||', "expires":'     	 	||coalesce(to_json(l_expires)::text,'""')
			||', "user_id":'     	 	||coalesce(to_json(l_user_id)::text,'""')
			||', "privileges":'  	 	||coalesce(l_privileges,'""')
			||', "secret_2fa":'  	 	||coalesce(to_json(l_secret_2fa)::text,'""')
			||', "email_validated":' 	||coalesce(to_json(l_email_validated)::text,'""')
			||', "x2fa_validated":'  	||coalesce(to_json(l_x2fa_validated)::text,'""')
			||', "acct_state":'  	 	||coalesce(to_json(l_acct_state)::text,'""')
			||', "login_2fa_remain":'  	||coalesce(to_json(l_login_2fa_failures)::text,'""')
			||'}';
	end if;

	if l_debug_on then
		insert into t_output ( msg ) values ( 'In q_auth_v1_validate_2fa_token (v2) - at bottom' );
		insert into t_output ( msg ) values ( '  l_data ->'||coalesce(to_json(l_data)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_acct_state ->'||coalesce(to_json(l_acct_state)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;







-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION q_auth_v1_create_auth_token ( p_email varchar, p_auth_token varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_user_id				uuid;
	l_auth_token 			uuid;
	l_debug_on 				bool;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';
	l_auth_token = p_auth_token::uuid;

	if l_debug_on then
		insert into t_output ( msg ) values ( 'In q_auth_v1_create_auth_token (v2)' );
		insert into t_output ( msg ) values ( '  p_email ->'||coalesce(to_json(p_email)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	select t1.user_id
		into l_user_id
		from q_qr_users as t1
		where t1.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
		;
	if not found then
		l_fail = true;
		l_data = '{"status":"error","msg":"Unable to find user.","code":"m4_count()","location":"m4___file__ m4___line__"}';
	end if;

	if not l_fail then
		update q_qr_users as t2
			set setup_complete_2fa 	= 'y'
			  , email_validated = 'y'
			where t2.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
			;
		BEGIN
			insert into q_qr_auth_tokens ( token, user_id ) values ( l_auth_token, l_user_id );
		EXCEPTION WHEN unique_violation THEN
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to create user/auth-token.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to create user/auth-token.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		END;
	end if;

	-- EmailConfirmed  string `json:"email_validated,omitempty"`
	if not l_fail then
		l_data = '{"status":"success"'
			||', "auth_token":'  	 	||coalesce(to_json(l_auth_token)::text,'""')
			||'}';
	end if;

	if l_debug_on then
		insert into t_output ( msg ) values ( 'In q_auth_v1_validate_2fa_token (v2) - at bottom' );
		insert into t_output ( msg ) values ( '  l_data ->'||coalesce(to_json(l_data)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;















-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- stmt := "q_auth_v1_2fa_get_secret ( $1, $2 )"
CREATE OR REPLACE FUNCTION q_auth_v1_2fa_get_secret ( p_email varchar, p_hmac_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_user_id				uuid;
	l_secret_2fa 			varchar(20);
	l_client_id				uuid;
	l_require_2fa 			varchar(1);
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';
	l_require_2fa 			= 'y';

	select
			  secret_2fa
			, user_id
			, client_id
			, require_2fa
		into
			  l_secret_2fa
			, l_user_id
			, l_client_id
			, l_require_2fa
		from q_qr_users as t2
		where t2.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
		;
	if not found then
		l_fail = true;
		l_data = '{"status":"error","msg":"Invalid email.","code":"m4_count()","location":"m4___file__ m4___line__"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid email number.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "secret_2fa":'       ||coalesce(to_json(l_secret_2fa)::text,'""')
			||', "user_id":'          ||coalesce(to_json(l_user_id)::text,'""')
			||', "client_id":'        ||coalesce(to_json(l_client_id)::text,'""')
			||', "require_2fa":' 	  ||coalesce(to_json(l_require_2fa)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;











-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- stmt := "q_auth_v1_change_email_address ( $1, $2, $3, $4, $5 )"
DROP FUNCTION if exists q_auth_v1_change_email_address(p_old_email character varying, p_new_email character varying, p_pw character varying, p_user_id integer, p_hmac_password character varying, p_userdata_password character varying);

CREATE OR REPLACE FUNCTION q_auth_v1_change_email_address ( p_old_email varchar, p_new_email varchar, p_pw varchar, p_user_id uuid, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_user_id				uuid;
	l_secret_2fa 			varchar(20);
	v_cnt 					int;
	l_email_hmac			bytea;
	l_first_name			text;
	l_last_name				text;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_user_id = p_user_id::uuid;

	if not l_fail then
		-- (fixed) xyzzy-Slow!! - better to do select count - and verify where before update.
		l_email_hmac = q_auth_v1_hmac_encode ( p_old_email, p_hmac_password );
		with user_row as (
			select
				  user_id
				, pgp_sym_decrypt(first_name_enc,p_userdata_password)::text as first_name
				, pgp_sym_decrypt(last_name_enc,p_userdata_password)::text as last_name
				, start_date
				, end_date
				, account_type
				, password_hash
				, parent_user_id
				, email_validated
				, setup_complete_2fa
				, email_hmac
			from q_qr_users as t1
			where t1.user_id = l_user_id
		)
		select user_id
				, first_name
				, last_name
			into l_user_id
				, l_first_name
				, l_last_name
			from user_row as t8
			where t8.email_hmac = l_email_hmac
			  and ( t8.start_date < current_timestamp or t8.start_date is null )
			  and ( t8.end_date > current_timestamp or t8.end_date is null )
			  and (
					(
							t8.account_type in ( 'login', 'sso' )
						and t8.password_hash = crypt(p_pw, password_hash)
						and t8.parent_user_id is null
					    and t8.email_validated = 'y'
					    and t8.setup_complete_2fa = 'y'
					)  or (
							t8.account_type = 'un/pw'
						and t8.password_hash = crypt(p_pw, password_hash)
						and t8.parent_user_id is not null
						and exists (
							select 'found'
							from q_qr_users as t2
							where t2.user_id = t8.parent_user_id
							  and ( t2.start_date < current_timestamp or t2.start_date is null )
							  and ( t2.end_date > current_timestamp or t2.end_date is null )
							  and t2.email_validated = 'y'
					          and t2.setup_complete_2fa = 'y'
						)
					)  or (
							t8.account_type = 'token'
						and t8.parent_user_id is not null
						and exists (
							select 'found'
							from q_qr_users as t3
							where t3.user_id = t8.parent_user_id
							  and ( t3.start_date < current_timestamp or t3.start_date is null )
							  and ( t3.end_date > current_timestamp or t3.end_date is null )
							  and t3.email_validated = 'y'
					          and t3.setup_complete_2fa = 'y'
						)
					)
				)
			for update
			;
		if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or email not validated","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or email not validated', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;
	end if;

	if not l_fail then
		update q_qr_users as t1
			set
				  email_hmac = q_auth_v1_hmac_encode ( p_new_email, p_hmac_password )
				, email_enc = pgp_sym_encrypt(p_new_email,p_userdata_password)
			where t1.user_id = l_user_id
			;
		-- check # of rows.
		GET DIAGNOSTICS v_cnt = ROW_COUNT;
		if v_cnt != 1 then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or email not validated","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or email not validated', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;

	end if;

	if not l_fail then
		-- Insert into log that email changed.
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Email Address Changed.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "email":'  				||coalesce(to_json(p_new_email)::text,'""')
			||', "first_name":'  			||coalesce(to_json(l_first_name)::text,'""')
			||', "last_name":'   			||coalesce(to_json(l_last_name)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;














-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- 	# -----------------------------------------------------------------------------------------------------------------------
-- 	# Add additional roles
-- 	psql <<XXxx
-- 	-- insert into q_qr_user_role ( user_id, role_id ) values ( '$user_id'::uuid, '$role_id'::uuid );
-- 	-- select q_auth_v1_delete_user ( user_id )
-- 	-- 	from q_qr_users as t1
-- 	-- 	where t1.email_hmac = hmac('$U1', '$QR_ENC_PASSWORD', 'sha256')
-- 	-- 	;
-- 	select q_auth_v1_add_role_to_user ( '$u1', '$role_name', '$QR_ENC_PASSWORD' );
-- XXxx
--
--
--
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

DROP FUNCTION if exists  q_auth_v1_add_role_to_user ( p_email varchar, p_role_name varchar, p_hmac_password varchar );






-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--
-- Assign a Client to a UserID that is created.   Return the client_id.
--
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION q_auth_v1_set_client ( p_email varchar, p_client_name varchar, p_hmac_password varchar ) RETURNS text
AS $$
DECLARE
	l_data				text;
	l_fail				bool;
	l_user_id			uuid;
	v_cnt 				int;
	l_email_hmac		bytea;
	l_client_id			uuid;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );

	select  client_id
		into l_client_id
		from q_qr_client as t1
		where t1.client_name = p_client_name
		;
	if not found then
		l_fail = true;
		l_data = '{"status":"error","msg":"Invalid Client Name","code":"m4_count()","location":"m4___file__ m4___line__"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Client Name', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
	end if;

	if not l_fail then

		update q_qr_users as t1
			set client_id = l_client_id
			where t1.email_hmac = l_email_hmac
			;
		-- check # of rows.
		GET DIAGNOSTICS v_cnt = ROW_COUNT;
		if v_cnt != 1 then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;

	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "client_id":'  			||coalesce(to_json(l_client_id)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;


-- select q_auth_v1_set_client ( 'bob@example.com', 'iLoves',  'my long secret password' );















-- 		// xyzzy34343455 TODO ----------------------------- Check to see if there is an usage "AUTH" token on CLI
-- 		/*
-- 			CREATE TABLE if not exists q_qr_auth_tokens (
-- 				auth_token_id 	uuid default uuid_generate_v4() primary key not null,
-- 				user_id 				uuid not null,
-- 				token			 		uuid not null,
-- 				api_encryption_key		text,
-- 				expires 				timestamp not null
-- 			);
--
-- 			UserID, AuthToken  = jwt_auth.CheckUsageAuthToken ( c )
-- 			...
-- 			// firstname := c.DefaultQuery("use_token", "")
--
-- 			// to Create...
-- 			// AuthToken  = jwt_auth.CreateUsageAuthToken ( c, UserID )
-- 		*/


CREATE OR REPLACE FUNCTION q_auth_v1_valid_use_token ( p_token varchar ) RETURNS text
AS $$
DECLARE
	l_data				text;
	l_fail				bool;
	l_user_id			uuid;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	select  user_id
		into l_user_id
		from q_qr_auth_tokens as t1
		where t1.api_encryption_key = p_token
		;
	if not found then
		l_fail = true;
		l_data = '{"status":"error","msg":"Invalid Use Token","code":"m4_count()","location":"m4___file__ m4___line__"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Use Token', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "user_id":'  			||coalesce(to_json(l_user_id)::text,'""')
			||', "auth_token":'  		||coalesce(to_json(p_token)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;


-- test - see below.






CREATE OR REPLACE FUNCTION q_auth_v1_create_use_token ( p_user_id uuid, p_token varchar ) RETURNS text
AS $$
DECLARE
	l_data				text;
	l_fail				bool;
	l_auth_token		uuid;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_auth_token = uuid_generate_v4();
	insert into q_qr_auth_tokens ( token, user_id, api_encryption_key ) values ( l_auth_token, p_user_id, p_token );

	if not l_fail then
		l_data = '{"status":"success"'
			||', "user_id":'  			||coalesce(to_json(p_user_id)::text,'""')
			||', "auth_token":'  		||coalesce(to_json(l_auth_token)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;


-- select q_auth_v1_create_use_token ( '88fc6df6-96ba-4073-b248-941af617bd58'::uuid, 'abc' );
-- select q_auth_v1_valid_use_token ( 'abc' );








--
-- Simiar to (handle.go):
--
-- URIPath:       "/api/table/user", // Only a GET request reaches this.
--
CREATE OR REPLACE FUNCTION q_qr_get_users2 ( p_hmac_password varchar, p_userdata_password varchar ) RETURNS TABLE (
        user_id uuid,
        email varchar,
        first_name varchar,
        last_name varchar
	)
AS $$
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
    RETURN QUERY
		SELECT
			  t1.user_id
		    , pgp_sym_decrypt(t1.email_enc, p_userdata_password)::text as email
		    , pgp_sym_decrypt(t1.first_name_enc, p_userdata_password)::text as first_name
		    , pgp_sym_decrypt(t1.last_name_enc, p_userdata_password)::text as last_name
		FROM q_qr_users as t1
		;
END; $$
LANGUAGE 'plpgsql';




--
--
-- 			select t1.user_id as "user_id", json_agg(t3.priv_name)::text as "privileges", coalesce(t1.client_id::text,'') as client_id
-- 				 , pgp_sym_decrypt(t1.email_enc, '4Ti5G3HmJsw+gbDbMKKVs4tnRUU=')::text as email
-- 			from q_qr_users as t1
-- 				join q_qr_auth_tokens as t2 on ( t1.user_id = t2.user_id )
-- 				left join q_qr_user_to_priv as t3 on ( t1.user_id = t3.user_id )
-- 			where t2.token = '65d26cf9-575a-42e7-971c-77eda313d145'
-- 		      and ( t1.start_date < current_timestamp or t1.start_date is null )
-- 		      and ( t1.end_date > current_timestamp or t1.end_date is null )
-- 			  and t1.email_validated = 'y'
-- 		      and ( t1.setup_complete_2fa = 'y' or t1.require_2fa = 'n' )
-- 			  and t2.expires > current_timestamp
-- 			group by t1.user_id
-- 		;
--
-- drop  function q_qr_validate_user_auth_token ( p_auth_token uuid, p_userdata_password varchar ) ;

DROP FUNCTION if exists q_qr_validate_user_auth_token(uuid,character varying);

--old-- CREATE OR REPLACE FUNCTION q_qr_validate_user_auth_token ( p_auth_token uuid, p_userdata_password varchar ) RETURNS TABLE (
--old--         user_id uuid,
--old--         "privileges" text,
--old--         client_id text,
--old--         email text,
--old-- 		expires timestamp,
--old-- 		seconds_till_expires bigint
--old-- 	)
--old-- AS $$
--old-- BEGIN
--old-- 	-- Copyright (C) Philip Schlump, 2008-2023.
--old-- 	-- BSD 3 Clause Licensed.  See LICENSE.bsd
--old-- 	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
--old--     RETURN QUERY
--old-- 			select t1.user_id as "user_id", json_agg(t3.priv_name)::text as "privileges", coalesce(t1.client_id::text,'')::text as client_id
--old-- 				 , pgp_sym_decrypt(t1.email_enc, p_userdata_password)::text as email
--old-- 				 , min(t2.expires) as expires
--old-- 				 , ceil(EXTRACT(EPOCH FROM min(t2.expires)))::bigint - ceil(extract(epoch from now()))::bigint as seconds_till_expires
--old-- 			from q_qr_users as t1
--old-- 				join q_qr_auth_tokens as t2 on ( t1.user_id = t2.user_id )
--old-- 				left join q_qr_user_to_priv as t3 on ( t1.user_id = t3.user_id )
--old-- 			where t2.token = p_auth_token
--old-- 		      and ( t1.start_date < current_timestamp or t1.start_date is null )
--old-- 		      and ( t1.end_date > current_timestamp or t1.end_date is null )
--old-- 			  and t1.email_validated = 'y'
--old-- 		      and ( t1.setup_complete_2fa = 'y' or t1.require_2fa = 'n' )
--old-- 			  and t2.expires > current_timestamp
--old-- 			group by t1.user_id
--old-- 		;
--old-- END; $$
--old-- LANGUAGE 'plpgsql';



-- json_keys_agg converts JSON data of the form {"a":true, "b":true} into ["a","b"].
CREATE OR REPLACE FUNCTION json_keys_agg ( p_json jsonb )  RETURNS text 
AS $$
DECLARE
	l_keys text[];
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()

	SELECT ARRAY(SELECT jsonb_object_keys(p_json))
		into l_keys;
	return array_to_json(l_keys)::text;
END; $$
LANGUAGE 'plpgsql';



CREATE OR REPLACE FUNCTION q_qr_validate_user_auth_token ( p_auth_token uuid, p_userdata_password varchar ) RETURNS TABLE (
        user_id uuid,
        "privileges" text,
        client_id text,
        email text,
		expires timestamp,
		seconds_till_expires bigint
	)
AS $$
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()

	-- privileges - should be an array (json) of privilages so, '["May AN", "May..."]'

	--	select json_object_keys(t1.allowed::json)  as priv_name, t1.role_name, t1.role_id, t2.user_id
	--	from q_qr_role2 as t1
	--		join q_qr_users as t2 on ( t1.role_name = t2.role_name )
	--	--
	--				left join q_qr_user_to_priv as t3 on ( t1.user_id = t3.user_id )

    RETURN QUERY
		select t5.user_id, json_keys_agg(t5.allowed) as "privileges", t5.client_id, t5.email, t5.expires, t5.seconds_till_expires
		from (
			select t1.user_id as "user_id", t4.allowed, coalesce(t1.client_id::text,'')::text as client_id
				 , pgp_sym_decrypt(t1.email_enc, p_userdata_password)::text as email
				 , min(t2.expires) as expires
				 , ceil(EXTRACT(EPOCH FROM min(t2.expires)))::bigint - ceil(extract(epoch from now()))::bigint as seconds_till_expires
			from q_qr_users as t1
				join q_qr_auth_tokens as t2 on ( t1.user_id = t2.user_id )
				left join q_qr_role2 as t4 on ( t1.role_name = t4.role_name )
			where t2.token = p_auth_token
		      and ( t1.start_date < current_timestamp or t1.start_date is null )
		      and ( t1.end_date > current_timestamp or t1.end_date is null )
			  and t1.email_validated = 'y'
		      and ( t1.setup_complete_2fa = 'y' or t1.require_2fa = 'n' )
			  and t2.expires > current_timestamp
			group by t1.user_id, t4.allowed
		) as t5
		;
END; $$
LANGUAGE 'plpgsql';



-- Note to self:
--		views select "left join q_qr_user_to_priv as t3" - could be replace with
--		"left join ( select ... +++ where user_id = CX ) as t3" - and have the external "query" criteria folded into the internal view code. (Macro Like)



-- select * from  q_qr_validate_user_auth_token ( '65d26cf9-575a-42e7-971c-77eda313d145'::uuid, '4Ti5G3HmJsw+gbDbMKKVs4tnRUU=');
-- explain analyze select * from  q_qr_validate_user_auth_token ( '65d26cf9-575a-42e7-971c-77eda313d145'::uuid, '4Ti5G3HmJsw+gbDbMKKVs4tnRUU=');


--	//                                   1                2                        3
--	// FUNCTION q_auth_v1_requires_2fa ( p_email varchar, p_hmac_password varchar, p_userdata_password varchar )
--	stmt := "q_auth_v1_requires_2fa ( $1, $2, $3 )"
--                                                  1                2                        3
CREATE OR REPLACE FUNCTION q_auth_v1_requires_2fa ( p_email varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data				text;
	l_fail				bool;
	l_user_id			uuid;
	l_require_2fa		text;
	l_email_hmac		bytea;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );
	with user_row as (
		select
			  user_id
			, require_2fa
		from q_qr_users as t1
		where t1.email_hmac = l_email_hmac
	)
	select
		  user_id
		, require_2fa
	into
		  l_user_id
		, l_require_2fa
	from user_row
	;

	if not found then
		l_fail = true;
		l_data = '{"status":"error","msg":"Invalid Email/Username Not Found","code":"m4_count()","location":"m4___file__ m4___line__"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Email/Username Not Found', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "user_id":'  			||coalesce(to_json(l_user_id)::text,'""')
			||', "require_2fa":' 	  	||coalesce(to_json(l_require_2fa)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;





CREATE OR REPLACE FUNCTION q_auth_v1_get_user_info ( p_user_id uuid, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_first_name	 		text;
	l_last_name		 		text;
	l_email			 		text;
BEGIN
	-- Copyright (C) Philip Schlump, 2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	select
			  pgp_sym_decrypt(t2.email_enc, p_userdata_password)::text as email
			, pgp_sym_decrypt(t2.first_name_enc, p_userdata_password)::text as first_name
			, pgp_sym_decrypt(t2.last_name_enc, p_userdata_password)::text as last_name
		into l_email, l_first_name, l_last_name
		from q_qr_users as t2
		where t2.user_id = p_user_id
		;

	if not found then
		l_fail = true;
		l_data = '{"status":"error","msg":"Invalid User ID","code":"m4_count()","location":"m4___file__ m4___line__"}';
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "email":' 	 				||coalesce(to_json(l_email)::text,'""')
			||', "first_name":'  			||coalesce(to_json(l_first_name)::text,'""')
			||', "last_name":'   			||coalesce(to_json(l_last_name)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;















-- --------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Update users name.
-- --------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION q_auth_v1_change_account_info ( p_user_id uuid, p_first_name varchar, p_last_name varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_user_id				uuid;
	l_secret_2fa 			varchar(20);
	v_cnt 					int;
BEGIN
	-- Copyright (C) Philip Schlump, 2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	update q_qr_users
		set
			  first_name_enc = pgp_sym_encrypt(p_first_name,p_userdata_password)
			, first_name_hmac = q_auth_v1_hmac_encode ( lower(p_first_name), p_hmac_password )
			, last_name_enc = pgp_sym_encrypt(p_last_name,p_userdata_password)
			, last_name_hmac = q_auth_v1_hmac_encode ( lower(p_last_name), p_hmac_password )
		where user_id = p_user_id
		;

	-- check # of rows.
	GET DIAGNOSTICS v_cnt = ROW_COUNT;
	if v_cnt != 1 then
		l_fail = true;
		l_data = '{"status":"error","msg":"Invalid Account","code":"m4_count()","location":"m4___file__ m4___line__"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Account', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
	end if;

	if not l_fail then
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Name Changed.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "first_name":'  			||coalesce(to_json(p_first_name)::text,'""')
			||', "last_name":'   			||coalesce(to_json(p_last_name)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;
















-- --------------------------------------------------------------------------------------------------------------------------------------------------------------------
--                              1                2                    3               4                        5
-- q_auth_v1_can_change_email ( p_email varchar, p_new_email varchar, p_user_id uuid, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
-- checks to se if p_new_email is already used.  If so then error.
-- --------------------------------------------------------------------------------------------------------------------------------------------------------------------











-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION q_auth_v1_cleanup_old_data ( ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()

	l_data = 'ok';

	begin

		delete from q_qr_one_time_password
			where user_id in (
				select user_id
				from q_qr_users
				where email_verify_expire < current_timestamp - interval '30 days'
				  and ( email_validated = 'n' or ( setup_complete_2fa = 'n'  and require_2fa = 'y' ) )
			)
			;
		delete from q_qr_user_config
			where user_id in (
				select user_id
				from q_qr_users
				where email_verify_expire < current_timestamp - interval '30 days'
				  and ( email_validated = 'n' or ( setup_complete_2fa = 'n' and require_2fa = 'y' ) )
			);
		delete from q_qr_users
			where email_verify_expire < current_timestamp - interval '30 days'
			  and ( email_validated = 'n' or ( setup_complete_2fa = 'n'  and require_2fa = 'y' ) )
			;

		delete from t_output where created < current_timestamp - interval '1 hour' ;

		delete from q_qr_auth_tokens where expires < current_timestamp ;
		delete from q_qr_device_track where expires < current_timestamp ;
		delete from q_qr_device_track where user_id is null and created < current_timestamp - interval '1 hour' ;
		delete from q_qr_n6_email_verify where created < current_timestamp - interval '2 days' ;
		delete from q_qr_saved_state where expires < current_timestamp ;
		delete from q_qr_tmp_token where expires < current_timestamp ;
		delete from q_qr_saved_state where expires < current_timestamp ;

	exception
		when others then
			l_fail = true;
	end;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;






CREATE OR REPLACE FUNCTION q_auth_v1_get_scid ( p_email varchar, p_auth_token uuid, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_user_id				uuid;
	l_scid					text;
	l_valid		 			varchar(20);
	v_cnt 					int;
	l_email_hmac			bytea;
BEGIN
	-- Copyright (C) Philip Schlump, 2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';


	-- CREATE TABLE if not exists q_qr_device_track (
	-- 	, sc_id				text 					-- ScID				scid

	-- insert into q_qr_auth_tokens ( token, user_id, sc_id ) values ( l_auth_token, l_user_id, l_sc_id );

	l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );
	select t1.sc_id, t1.user_id
		into l_scid, l_user_id
		from q_qr_auth_tokens as t1
			join q_qr_users as t2 on ( t1.user_id = t2.user_id and t2.email_hmac = l_email_hmac )
		where token = p_auth_token
		;
	if not found then
		l_valid = 'no';
	else
		l_valid = 'yes';
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "user_id":'  			||coalesce(to_json(l_user_id)::text,'""')
			||', "scid":'   			||coalesce(to_json(l_scid)::text,'""')
			||', "valid":'   			||coalesce(to_json(l_valid)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;










drop FUNCTION if exists q_auth_v1_get_email_from_auth_token ( varchar, p_auth_token uuid, p_hmac_password varchar, p_userdata_password varchar ) ;

CREATE OR REPLACE FUNCTION q_auth_v1_get_email_from_auth_token ( p_auth_token uuid, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_user_id				uuid;
	l_scid					text;
	v_cnt 					int;
	l_email					text;
	l_valid		 			varchar(20);
BEGIN
	-- Copyright (C) Philip Schlump, 2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	select t1.sc_id
			, t1.user_id
			, pgp_sym_decrypt(t2.email_enc::bytea,p_userdata_password)::text email
		into l_scid, l_user_id, l_email
		from q_qr_auth_tokens as t1
			join q_qr_users as t2 on ( t1.user_id = t2.user_id )
		where token = p_auth_token
		;
	if not found then
		l_valid = 'no';
	else
		l_valid = 'yes';
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "user_id":'  			||coalesce(to_json(l_user_id)::text,'""')
			||', "scid":'   			||coalesce(to_json(l_scid)::text,'""')
			||', "email":'   			||coalesce(to_json(l_email)::text,'""')
			||', "valid":'   			||coalesce(to_json(l_valid)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;



CREATE OR REPLACE FUNCTION q_auth_v1_get_all_tokens ( p_auth_token uuid, p_delete_act varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_user_id				uuid;
	l_scid					text;
	v_cnt 					int;
	l_email					text;
	l_token_list			text;
BEGIN
	-- Copyright (C) Philip Schlump, 2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	select json_agg(t1.token)::text as token_list, t1.user_id
		into l_token_list, l_user_id
		from q_qr_auth_tokens as t1
		where token = p_auth_token
		group by t1.user_id
		;

	if not found then
		l_fail = true;
		l_data = '{"status":"error","msg":"Invalid user","code":"m4_count()","location":"m4___file__ m4___line__"}';
	end if;

	if not ( q_admin_HasPriv ( p_user_id, 'Auth Token Admin' ) ) then
		l_fail = true;
		l_data = '{"status":"error","msg":"Not authorized to ''Item Client Admin''","code":"m4_count()","location":"m4___file__ m4___line__"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( p_user_id::uuid, 'Not authorized to ''Auth Token Admin''', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
	end if;

	if p_delete_act = '' or p_detete_act = 'auth_token' then
		update q_qr_auth_tokens set expires = current_timestamp - interval '4 minues ' where token = p_auth_token;
	end if;

	if not l_fail then
		if p_delete_act = 'all' then
			update q_qr_auth_tokens set expires = current_timestamp - interval '2 minute' where user_id in ( select user_id from q_qr_aurth_tokens where token = p_auth_token );
		elsif p_delete_act = 'both' then
			update q_qr_auth_tokens set expires = current_timestamp - interval '2 minute' where user_id in ( select user_id from q_qr_aurth_tokens where token = p_auth_token );
			update q_qr_users as t1
				set
						start_date = current_timestamp + interval '50 years'
					  , end_date = current_timestamp - interval '1 minute'
					  , email_hmac = q_auth_v1_hmac_encode ( l_x_email, p_hmac_password )
					  , email_enc = pgp_sym_encrypt( l_x_email, p_userdata_password)
					  , password_hash = crypt( l_x_pw, gen_salt('bf') )
				where t1.user_id = l_user_id
				;
			-- check # of rows.
			GET DIAGNOSTICS v_cnt = ROW_COUNT;
			if v_cnt != 1 then
				l_fail = true;
				l_data = '{"status":"error","msg":"Invalid user","code":"m4_count()","location":"m4___file__ m4___line__"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid user.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
			end if;
		end if;
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "user_id":'  			||coalesce(to_json(l_user_id)::text,'""')
			||', "token_list":' 		||coalesce(to_json(l_token_list)::text,'[]')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;







CREATE OR REPLACE FUNCTION rel_description(
     p_relname text, p_schemaname text DEFAULT NULL
 ) RETURNS text AS $f$
    SELECT obj_description((CASE
       WHEN strpos($1, '.')>0 THEN $1
       WHEN $2 IS NULL THEN 'public.'||$1
       ELSE $2||'.'||$1
            END)::regclass, 'pg_class');
 $f$ LANGUAGE SQL;









CREATE OR REPLACE FUNCTION q_auth_v1_get_user_from_tmp_token ( p_tmp_token uuid, p_email varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_debug_on 				bool;

	l_user_id				uuid;
	l_sc_id					text;		-- ScID, scid
	l_auth_token			text;
BEGIN
	-- Copyright (C) Philip Schlump, 2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()

	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->a_get_user_from_tmp_token <- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '		p_tmp_token      ->'||coalesce(to_json(p_tmp_token)::text,'""')||'<-');
		insert into t_output ( msg ) values ( '		p_email          ->'||coalesce(to_json(p_email)::text,'""')||'<-');
	end if;

	-- insert into q_qr_tmp_token ( user_id, token ) values ( l_user_id, l_tmp_token );
	-- insert into q_qr_auth_tokens ( token, user_id, sc_id ) values ( l_auth_token, l_user_id, p_sc_id );
	select
			  t3.sc_id
			, t3.token as auth_token
			, t1.user_id
		into l_sc_id, l_auth_token, l_user_id
		from q_qr_tmp_token as t1
			join q_qr_users as t2 on ( t1.user_id = t2.user_id )
			join q_qr_auth_tokens as t3 on ( t1.user_id = t3.user_id and t1.auth_token = t3.token )
		where t1.token = p_tmp_token
	      and t2.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
		;

	if not found then
		l_fail = true;
		l_data = '{"status":"error","msg":"failed to find the user based on tmp_token.","code":"m4_count()","location":"m4___file__ m4___line__"}';
	end if;

	-- example output
	-- 		{"status":"success", "auth_token":"b76a6228-d5c6-4079-820a-920ea494b00d", "user_id":"0ed721f8-2aed-42f2-8ad3-76bad390a4f4", "sc_id":"06ee6e25-3158-4f19-9335-38c9b3822389"}
	if not l_fail then

		l_data = '{"status":"success"'
			||', "auth_token":' 		||coalesce(to_json(l_auth_token)::text,'""')
			||', "user_id":' 			||coalesce(to_json(l_user_id)::text,'""')
			||', "sc_id":' 				||coalesce(to_json(l_sc_id)::text,'""')
			||'}';

	end if;
	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->a_get_user_from_tmp_token <- m4___file__ m4___line__ ***returns***' );
		insert into t_output ( msg ) values ( ' 		l_data= '||l_data );
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;






-- -- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- CREATE TABLE if not exists q_qr_user_config (
-- 	config_id 				uuid default uuid_generate_v4() not null primary key,
-- 	user_id 				uuid not null,
-- 	name					text not null,
-- 	value					text not null,
-- 	updated 				timestamp, 									 		-- Project update timestamp (YYYYMMDDHHMMSS timestamp).
-- 	created 				timestamp default current_timestamp not null 		-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
-- );


CREATE OR REPLACE FUNCTION q_auth_v1_get_1_user_config ( p_user_id uuid, p_param_name varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_debug_on 				bool;

	l_user_id				uuid;
	l_config_id             uuid;
	l_value			        text;
BEGIN
	-- Copyright (C) Philip Schlump, 2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()

	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->a_get_user_from_tmp_token <- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '		p_user_id      ->'||coalesce(to_json(p_user_id)::text,'""')||'<-');
		insert into t_output ( msg ) values ( '		p_param_name   ->'||coalesce(to_json(p_param_name)::text,'""')||'<-');
	end if;

	-- insert into q_qr_tmp_token ( user_id, token ) values ( l_user_id, l_tmp_token );
	-- insert into q_qr_auth_tokens ( token, user_id, sc_id ) values ( l_auth_token, l_user_id, p_sc_id );
	select
			  t1.value, t1.config_id
		into l_value, l_config_id
		from q_qr_user_config as t1
		where t1.user_id = p_user_id
	      and t1.name = p_param_name
		;

	if not found then
		l_fail = true;
		l_data = '{"status":"error","msg":"no configuration for this.","code":"m4_count()","location":"m4___file__ m4___line__"}';
	end if;

	if not l_fail then

		l_data = '{"status":"success"'
			||', "value":' 		      	||coalesce(to_json(l_value)::text,'""')
			||', "config_id":' 			||coalesce(to_json(l_config_id)::text,'""')
			||'}';

	end if;
	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->a_get_user_config <- m4___file__ m4___line__ ***returns***' );
		insert into t_output ( msg ) values ( ' 		l_data= '||l_data );
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;












--	stmt := "q_auth_v1_get_acct_state ( $1, $2, $3 )"
CREATE OR REPLACE FUNCTION q_auth_v1_get_acct_state ( p_email varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_debug_on 				bool;

	l_acct_state	        text;
	l_email_hmac			bytea;
BEGIN
	-- Copyright (C) Philip Schlump, 2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()

	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->a_get_user_from_tmp_token <- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '		p_email        ->'||coalesce(to_json(p_email)::text,'""')||'<-');
	end if;

	l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );
	select
			  t1.acct_state
		into l_acct_state
		from q_qr_users as t1
		where t1.email_hmac = l_email_hmac
		;

	if not found then
		l_fail = true;
		l_data = '{"status":"error","msg":"no user for this email.","code":"m4_count()","location":"m4___file__ m4___line__"}';
	end if;

	if not l_fail then

		l_data = '{"status":"success"'
			||', "acct_state":' 		      	||coalesce(to_json(l_acct_state)::text,'""')
			||'}';

	end if;
	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->a_get_user_config <- m4___file__ m4___line__ ***returns***' );
		insert into t_output ( msg ) values ( ' 		l_data= '||l_data );
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;











--	stmt := "q_auth_v1_update_acct_state ( $1, $2, $3, $4 )"
CREATE OR REPLACE FUNCTION q_auth_v1_update_acct_state ( p_email varchar, p_acct_state varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_debug_on 				bool;

	l_email_hmac			bytea;
BEGIN
	-- Copyright (C) Philip Schlump, 2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()

	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->a_get_user_from_tmp_token <- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '		p_email        ->'||coalesce(to_json(p_email)::text,'""')||'<-');
		insert into t_output ( msg ) values ( '		p_acct_state   ->'||coalesce(to_json(p_acct_state)::text,'""')||'<-');
	end if;

	l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );
	update q_qr_users as t1
		set acct_state = p_acct_state
		where t1.email_hmac = l_email_hmac
		;

	if not found then
		l_fail = true;
		l_data = '{"status":"error","msg":"no user for this email.","code":"m4_count()","location":"m4___file__ m4___line__"}';
	end if;

	if not l_fail then

		l_data = '{"status":"success"'
			||', "acct_state":' 		      	||coalesce(to_json(p_acct_state)::text,'""')
			||'}';

	end if;
	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->a_get_user_config <- m4___file__ m4___line__ ***returns***' );
		insert into t_output ( msg ) values ( ' 		l_data= '||l_data );
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;








drop FUNCTION if exists q_auth_v1_add_privlage_to ( p_user_id uuid,  p_priv_needed varchar, p_hmac_password varchar, p_userdata_password varchar ) ;



-- p_user_id - the user that has the authentication to add a privilage (AutoJob Admin)
-- p_add_to_user_id - the user that will receive the privilage
-- p_priv_needed - the privilage that will be added
CREATE OR REPLACE FUNCTION q_auth_v1_add_privlage_to ( p_user_id uuid, p_add_to_user_id uuid, p_priv_needed varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_debug_on 				bool;
	l_role_name				text;
	l_email					text;
	l_email_hmac			bytea;
	l_allowed 				bool;
	l_allowed_privs 		jsonb;
	l_priv					jsonb;
	l_path					text[];
BEGIN
	-- Copyright (C) Philip Schlump, 2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()

	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_auth_v1_add_privilage_to <- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '		p_user_id           ->'||coalesce(to_json(p_user_id)::text,'""')||'<-');
		insert into t_output ( msg ) values ( '		p_add_to_user_id    ->'||coalesce(to_json(p_add_to_user_id)::text,'""')||'<-');
		insert into t_output ( msg ) values ( '		p_priv_needed       ->'||coalesce(to_json(p_priv_needed)::text,'""')||'<-');
	end if;

	-- See: https://www.postgresqltutorial.com/postgresql-json-functions/postgresql-jsonb_insert/
	if not ( q_admin_HasPriv ( p_user_id, 'AutoJob Admin' ) ) then
		l_fail = true;
		l_data = '{"status":"error","msg":"Not authorized for ''AutoJob Admin''","code":"m4_count()","location":"m4___file__ m4___line__"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( p_user_id::uuid, 'Not authorized to ''AutoJob Admin''', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
	end if;

	if not l_fail then 

		select role_name 
			, pgp_sym_decrypt(email_enc::bytea,p_userdata_password)::text email
			into l_role_name, l_email
			from q_qr_users
			where user_id = p_add_to_user_id
			;
		if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"User not found.  Invalid user_id."}';			-- no such privilage granted.
		else

			select allowed ? p_priv_needed, allowed
				into l_allowed, l_priv
				from q_qr_role2
				where role_name = l_role_name
				;
			if found then
				insert into t_output ( msg ) values ( '		found' );
				if l_allowed then
					l_fail = true;
					l_data = '{"status":"success","msg":"already had this privelege"}';
				else
					l_path[0] = p_priv_needed;
					l_priv = jsonb_set ( l_priv, l_path, 'true'::jsonb );
					if l_role_name = l_email then
						-- select jsonb_set ( '{"a":true,"c":true}'::jsonb, '{"a"}', 'false' );
						insert into t_output ( msg ) values ( '		l_role_name == l_email, ='||l_email||' p_priv_needed='||p_priv_needed );
						update q_qr_role2
							set allowed = jsonb_set ( allowed, l_path, 'true'::jsonb )
							where role_name = l_role_name
							;
					else
						insert into t_output ( msg ) values ( '		will insert, l_role_name='||l_role_name );
						insert into q_qr_role2 ( role_name, allowed ) 
							select l_email, jsonb_set ( t1.allowed, l_path, 'true'::jsonb )
								from q_qr_role2 as t1
								where t1.role_name = l_role_name
							;
					end if;
					insert into t_output ( msg ) values ( '		set role to email, role_name='||l_email||' privleges='||l_priv::text );
					update q_qr_users 
						set role_name = l_email
							, privileges = l_priv::text
						where user_id = p_add_to_user_id
						;
				end if;
			else
				l_fail = true;
				l_data = '{"status":"success","msg":"role name was not found, no role to add to."}';
			end if;

		end if;

	end if;

	if not l_fail then

		l_data = '{"status":"success"'
			||'}';

	end if;
	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_auth_v1_add_privlage_to <- m4___file__ m4___line__ ***returns***' );
		insert into t_output ( msg ) values ( ' 		l_data= '||l_data );
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;
















-- p_suer_id is the logged in administrative user. -- User must have "Admin" priv
-- p_email is the user to add the priv to.
CREATE OR REPLACE FUNCTION q_auth_v1_add_privlage_to_email ( p_user_id uuid, p_email varchar, p_priv_needed varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_debug_on 				bool;
	l_role_name				text;
	l_email					text;
	l_add_to_user_id		uuid;
	l_email_hmac			bytea;
	l_allowed 				bool;
	l_allowed_privs 		jsonb;
	l_priv					jsonb;
	l_path					text[];
	l_txt					text;
BEGIN
	-- Copyright (C) Philip Schlump, 2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()

	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_auth_v1_add_privilage_to_email <- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '		p_user_id       ->'||coalesce(to_json(p_user_id)::text,'""')||'<-');
		insert into t_output ( msg ) values ( '		p_email         ->'||coalesce(to_json(p_email)::text,'""')||'<-');
		insert into t_output ( msg ) values ( '		p_priv_needed   ->'||coalesce(to_json(p_priv_needed)::text,'""')||'<-');
	end if;

	-- See: https://www.postgresqltutorial.com/postgresql-json-functions/postgresql-jsonb_insert/
	if not ( q_admin_HasPriv ( p_user_id, 'AutoJob Admin' ) ) then
		l_fail = true;
		l_data = '{"status":"error","msg":"Not authorized for ''AutoJob Admin''","code":"m4_count()","location":"m4___file__ m4___line__"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( p_user_id::uuid, 'Not authorized to ''AutoJob Admin''', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
	end if;

	if not l_fail then

		l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );
		select role_name 
			, pgp_sym_decrypt(email_enc::bytea,p_userdata_password)::text email
			, user_id 
			into l_role_name, l_email, l_add_to_user_id
			from q_qr_users as t1
			where t1.email_hmac = l_email_hmac
			;
		if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"User not found.  Invalid email."}';		
		else


			select allowed ? p_priv_needed, allowed
				into l_allowed, l_priv
				from q_qr_role2
				where role_name = l_role_name
				;
			if found then
				insert into t_output ( msg ) values ( '		found' );
				if l_allowed then
					l_fail = true;
					l_data = '{"status":"success","msg":"already had this privelege"}';
				else
					l_path[0] = p_priv_needed;
					l_priv = jsonb_set ( l_priv, l_path, 'true'::jsonb );
					if l_role_name = l_email then
						-- select jsonb_set ( '{"a":true,"c":true}'::jsonb, '{"a"}', 'false' );
						insert into t_output ( msg ) values ( '		l_role_name == l_email, ='||l_email||' p_priv_needed='||p_priv_needed );
						update q_qr_role2
							set allowed = jsonb_set ( allowed, l_path, 'true'::jsonb )
							where role_name = l_role_name
							;
					else
						insert into t_output ( msg ) values ( '		will insert, l_role_name='||l_role_name );
						insert into q_qr_role2 ( role_name, allowed ) 
							select l_email, jsonb_set ( t1.allowed, l_path, 'true'::jsonb )
								from q_qr_role2 as t1
								where t1.role_name = l_role_name
							;
					end if;
					l_txt = json_keys_agg ( l_priv );
					insert into t_output ( msg ) values ( '		set role to email, role_name='||l_email||' privleges='||l_priv::text||' l_txt='||l_txt );
					update q_qr_users 
						set role_name = l_email
							, privileges = l_txt
						where user_id = l_add_to_user_id
						;
				end if;
			else
				l_fail = true;
				l_data = '{"status":"success","msg":"role name was not found, no privlage to remove"}';
			end if;

		end if;

	end if;

	if not l_fail then

		l_data = '{"status":"success"'
			||'}';

	end if;
	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_auth_v1_add_privlage_to_email <- m4___file__ m4___line__ ***returns***' );
		insert into t_output ( msg ) values ( ' 		l_data= '||l_data );
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;















-- select '{"a": 1, "b": 2}'::jsonb - 'a';
-- 	rv, err := callme.CallAuthRmPrivlageFromEmail(c, UserId, pp.ForEmail, pp.Priv)

-- p_suer_id is the logged in administrative user. -- User must have "Admin" priv
-- p_email is the user to add the priv to.
CREATE OR REPLACE FUNCTION q_auth_v1_rm_privlage_from_email ( p_user_id uuid, p_email varchar, p_priv_needed varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_debug_on 				bool;
	l_role_name				text;
	l_email					text;
	l_add_to_user_id		uuid;
	l_email_hmac			bytea;
	l_allowed 				bool;
	l_allowed_privs 		jsonb;
	l_priv					jsonb;
	l_path					text[];
	l_txt					text;
BEGIN
	-- Copyright (C) Philip Schlump, 2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()

	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_auth_v1_rm_privlage_from_email <- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '		p_user_id       ->'||coalesce(to_json(p_user_id)::text,'""')||'<-');
		insert into t_output ( msg ) values ( '		p_email         ->'||coalesce(to_json(p_email)::text,'""')||'<-');
		insert into t_output ( msg ) values ( '		p_priv_needed   ->'||coalesce(to_json(p_priv_needed)::text,'""')||'<-');
	end if;

	-- See: https://www.postgresqltutorial.com/postgresql-json-functions/postgresql-jsonb_insert/
	if not ( q_admin_HasPriv ( p_user_id, 'AutoJob Admin' ) ) then
		l_fail = true;
		l_data = '{"status":"error","msg":"Not authorized for ''AutoJob Admin''","code":"m4_count()","location":"m4___file__ m4___line__"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( p_user_id::uuid, 'Not authorized to ''AutoJob Admin''', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
	end if;

	if not l_fail then

		l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );
		select role_name 
			, pgp_sym_decrypt(email_enc::bytea,p_userdata_password)::text email
			, user_id 
			into l_role_name, l_email, l_add_to_user_id
			from q_qr_users as t1
			where t1.email_hmac = l_email_hmac
			;
		if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"User not found.  Invalid email."}';		
		else


			select allowed ? p_priv_needed, allowed
				into l_allowed, l_priv
				from q_qr_role2
				where role_name = l_role_name
				;
			if found then
				insert into t_output ( msg ) values ( '		found - so removing it.' );
				if not l_allowed then
					l_fail = true;
					l_data = '{"status":"success","msg":"already had this privelege removed"}';
				else
					-- update the_table set attr['is_default'] = to_jsonb(false);
					l_priv = l_priv - p_priv_needed;
					if l_role_name = l_email then
						-- select jsonb_set ( '{"a":true,"c":true}'::jsonb, '{"a"}', 'false' );
						insert into t_output ( msg ) values ( '		l_role_name == l_email, ='||l_email||' p_priv_needed='||p_priv_needed );
						update q_qr_role2
							set allowed = allowed - p_priv_needed
							where role_name = l_role_name
							;
					else
						insert into t_output ( msg ) values ( '		will insert, l_role_name='||l_role_name );
						insert into q_qr_role2 ( role_name, allowed ) 
							select l_email, t1.allowed - p_priv_needed
								from q_qr_role2 as t1
								where t1.role_name = l_role_name
							;
					end if;
					l_txt = json_keys_agg ( l_priv );
					insert into t_output ( msg ) values ( '		set role to email, role_name='||l_email||' privleges='||l_priv::text||' l_txt='||l_txt );
					update q_qr_users 
						set role_name = l_email
							, privileges = l_txt
						where user_id = l_add_to_user_id
						;
				end if;
			else
				l_fail = true;
				l_data = '{"status":"success","msg":"role name was not found, no privlage to remove"}';
			end if;

		end if;

	end if;

	if not l_fail then

		l_data = '{"status":"success"'
			||'}';

	end if;
	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_auth_v1_rm_privlage_from_email <- m4___file__ m4___line__ ***returns***' );
		insert into t_output ( msg ) values ( ' 		l_data= '||l_data );
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;





















drop FUNCTION if exists q_auth_v1_idp_login_or_register ( p_email varchar, p_auth_source varchar, p_claims varchar, p_id_token varchar, p_access_token varchar, p_refresh_token varchar,  p_hmac_password varchar, p_userdata_password varchar, p_fingerprint varchar, p_sc_id varchar, p_hash_of_headers varchar, p_xsrf_id varchar ) ;
drop FUNCTION if exists q_auth_v1_idp_login_or_register ( p_email varchar, p_validator varchar, p_claims varchar, p_id_token varchar, p_access_token varchar, p_refresh_token varchar,  p_hmac_password varchar, p_userdata_password varchar, p_fingerprint varchar, p_sc_id varchar, p_hash_of_headers varchar, p_xsrf_id varchar ) ;
drop FUNCTION if exists q_auth_v1_idp_login_or_register ( p_email varchar, p_validator varchar, p_claims varchar, p_id_token varchar, p_access_token varchar, p_refresh_token varchar,  p_hmac_password varchar, p_userdata_password varchar, p_hash_of_headers varchar, p_email_verified varchar, p_first_name varchar, p_last_name varchar ) ;

CREATE OR REPLACE FUNCTION q_auth_v1_idp_login_or_register ( p_email varchar, p_validator varchar, p_claims varchar, p_id_token varchar, p_access_token varchar, p_refresh_token varchar,  p_hmac_password varchar, p_userdata_password varchar, p_hash_of_headers varchar, p_email_verified varchar, p_first_name varchar, p_last_name varchar, p_sc_id varchar ) RETURNS text
AS $$
DECLARE
	l_2fa_id				uuid;
	l_data					text;
	l_fail					bool;
  	l_user_id 				uuid;
	l_junk					text;
	l_email_validated		varchar(1);
	l_setup_complete_2fa 	varchar(1);
	l_start_date			timestamp;
	l_end_date				timestamp;
	l_account_type			varchar(20);
	l_privileges			text;
	l_user_config			text;
	l_first_name			text;
	l_last_name				text;
	l_token				text;
	l_tmp					text;
	l_auth_token			uuid;
	l_tmp_token				uuid;	-- when 2fa is on this is returnd as not null (UUID)
	l_debug_on 				bool;
	l_failed_login_timeout 	timestamp;
	l_login_failures 		int;
	l_one_time_password_id 	uuid;
	v_cnt 					int;
	l_validation_method		varchar(10);
	l_manifest_id			uuid;
	l_email_hmac            bytea;
	l_is_new_device_login	varchar(1);
	l_client_id				uuid;
	l_acct_state			text;
	l_role_name				text;
	l_is_new_device_msg		text;
	l_device_track_id		uuid;
	l_client_user_config	text;
	l_txt					text;
	l_new_registration		bool;
	l_parent_user_id 		uuid;
	x_account_type 			text;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2023.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';
	l_is_new_device_login = 'n';
	l_is_new_device_msg = '--don''t-know--';
	l_new_registration		= false;
	l_tmp_token = uuid_generate_v4();
	l_account_type = 'sso';
	l_acct_state = 'reg1';
	l_token = '';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_login<- m4___file__ m4___line__' );
		insert into t_output ( msg ) values ( '  p_email ->'||coalesce(to_json(p_email)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_validator ->'||coalesce(to_json(p_validator)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_claims ->'||coalesce(to_json(p_claims)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_id_token ->'||coalesce(to_json(p_id_token)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_access_token ->'||coalesce(to_json(p_access_token)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_refresh_token ->'||coalesce(to_json(p_refresh_token)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||coalesce(to_json(p_hmac_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_userdata_password ->'||coalesce(to_json(p_userdata_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_hash_of_headers ->'||coalesce(to_json(p_hash_of_headers)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_email_verified ->'||coalesce(to_json(p_email_verified)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	-- validation_method		varchar(10) default 'un/pw' not null check ( validation_method in ( 'un/pw', 'sip', 'srp6a', 'hw-key' ) ),
	if not l_fail then
		l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );
		-- see:(this one has been fixed) xyzzy-Slow!! - better to do select count - and verify where before update.
		with email_user as (
			select
				  user_id
				, email_validated
				, setup_complete_2fa
				, start_date
				, end_date
				, account_type
				, pgp_sym_decrypt(first_name_enc,p_userdata_password)::text as x_first_name
				, pgp_sym_decrypt(last_name_enc,p_userdata_password)::text as x_last_name
				, failed_login_timeout
				, login_failures
				, validation_method
				, password_hash
				, parent_user_id
				, client_id
				, role_name
			from q_qr_users
			where email_hmac = l_email_hmac
		)
		select
				  user_id
				, email_validated
				, setup_complete_2fa
				, start_date
				, end_date
				, x_first_name
				, x_last_name
				, failed_login_timeout
				, login_failures
				, validation_method
				, client_id
				, role_name
				, parent_user_id
				, account_type
			into
				  l_user_id
				, l_email_validated
				, l_setup_complete_2fa
				, l_start_date
				, l_end_date
				, l_first_name
				, l_last_name
				, l_failed_login_timeout
				, l_login_failures
				, l_validation_method
				, l_client_id
				, l_role_name
				, l_parent_user_id 		
				, x_account_type 
			from email_user
		;

		if found then

			if l_parent_user_id is not null then

				l_fail = true;
				l_data = '{"status":"error","msg":"Invalid account, a child account of a differnet login account.","code":"m4_count()","location":"m4___file__ m4___line__"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_bad_user_id, 'Invalid account, a child account of a different login account.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');

			elsif x_account_type = 'sso' then

				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'SSO Login Account Found:'||p_email, 'm4_counter()', 'File:m4___file__ Line No:m4___line__');

			else 

				l_fail = true;
				l_data = '{"status":"error","msg":"Invalid account type, try logging in with a email/password.","code":"m4_count()","location":"m4___file__ m4___line__"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_bad_user_id, 'Invalid account type, try logging in with a email/password.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');

			end if;

		else

			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'New Registration:'||p_email, 'm4_counter()', 'File:m4___file__ Line No:m4___line__');

			-- register them
			l_new_registration		= true;

			if not l_fail then
				select json_agg(t0.priv_name)::text
				into l_privileges
				from (
					select json_object_keys(t1.allowed::json)::text  as priv_name
						from q_qr_role2 as t1
						where t1.role_name =  'role:user'
					) as t0
					;
				if not found then
					if l_debug_on then
						insert into t_output ( msg ) values ( 'Failed to get the privileges for the user' );
					end if;
					l_fail = true;
					l_data = '{"status":"error","msg":"Unable to get privileges for the user.","code":"m4_count()","location":"m4___file__ m4___line__"}';
					l_privileges = '';
				end if;
				if l_debug_on then
					insert into t_output ( msg ) values ( 'calculate l_privileges ->'||coalesce(to_json(l_privileges)::text,'---null---')||'<-');
				end if;
			end if;

			if not l_fail then

				-- xyzzyInsertNew - Move to - end where update4
				l_validation_method = 'sso';
				l_role_name = 'role:user';
				l_user_id = uuid_generate_v4();

				INSERT INTO q_qr_users (
					  email_hmac
					, email_enc
					, user_id
					, validator
					, email_verify_token
					, email_verify_expire
					, first_name_hmac
					, first_name_enc
					, last_name_hmac
					, last_name_enc
					, privileges
					, validation_method
					, password_hash
					, role_name
					, require_2fa
					, login_failures 
					, login_success
					, claims 
					, id_token 
					, access_token 
					, refresh_token 
					, account_type
					, email_validated
				) VALUES (
					  l_email_hmac
					, pgp_sym_encrypt(p_email, p_userdata_password)
					, l_user_id
					, p_validator
					, null
					, current_timestamp + interval '10000 day'
					, q_auth_v1_hmac_encode ( p_first_name, p_hmac_password )
					, pgp_sym_encrypt( p_first_name, p_userdata_password )
					, q_auth_v1_hmac_encode ( p_last_name, p_hmac_password )
					, pgp_sym_encrypt( p_last_name, p_userdata_password )
					, l_privileges
					, l_validation_method	-- sso
					, '*'					-- never a valid hash - password is not used.
					, l_role_name			-- role:user
					, 'n'					-- 2fa on SSO side, not this side.
					, 0 					-- login_failures
					, 1  					-- login_success 
					, p_claims
					, p_id_token
					, p_access_token
					, p_refresh_token
					, l_account_type		-- sso
					, p_email_verified
				);

				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'User Registered', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');

				-- Generate OTP passwords - 20 of them.

			end if;

			insert into q_qr_user_hierarchy ( user_id, parent_user_id )
				select l_user_id, t1.user_id
				from q_qr_users as t1
				where t1.email_hmac = l_email_hmac
				;
			GET DIAGNOSTICS v_cnt = ROW_COUNT;
			if v_cnt = 0 then
				l_fail = true;
				l_data = '{"status":"error","msg":"Unable to create account as a part of the account hierarchy.  Please login or recover password.","code":"m4_count()","location":"m4___file__ m4___line__"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_bad_user_id, 'Unable to create account as a part of the account hierarchy.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
			end if;

		end if;

	end if;

	if l_debug_on then
		insert into t_output ( msg ) values ( '  [[[ Additional Fields ]]]' );
		insert into t_output ( msg ) values ( '  ->'||coalesce(to_json(p_userdata_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_first_name           = ->'||coalesce(to_json(l_first_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_last_name            = ->'||coalesce(to_json(l_last_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_validation_method    = ->'||coalesce(to_json(l_validation_method)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_start_date           = ->'||coalesce(to_json(l_start_date)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_end_date             = ->'||coalesce(to_json(l_end_date)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_email_validated      = ->'||coalesce(to_json(l_email_validated)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_setup_complete_2fa   = ->'||coalesce(to_json(l_setup_complete_2fa)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_client_id            = ->'||coalesce(to_json(l_client_id)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_one_time_password_id = ->'||coalesce(to_json(l_one_time_password_id)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  l_role_name            = ->'||coalesce(to_json(l_role_name)::text,'---null---')||'<-');
	end if;

	if l_role_name is null then
		l_role_name = 'role:user';
	end if;
	if l_role_name = '' then
		l_role_name = 'role:user';
	end if;

	if not l_fail then
		if not q_admin_HasPriv ( l_user_id, 'May Login' ) then
			if l_debug_on then
				insert into t_output ( msg ) values ( 'Failed to find priv ''May Login'' ->'||l_user_id||'<-');
			end if;
			l_fail = true;
			l_data = '{"status":"error","msg":"Account lacks ''May Login'' privilege","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account lacks ''May Login'' privilege', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;
	end if;

	if not l_fail then
		if l_validation_method != 'sso' then
			l_fail = true;
			l_data = '{"status":"error","msg":"Account is not a sso (single sign on) authetication method","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account is not a sso (single singn on) autetication method', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		end if;
	end if;

	if not l_fail then
		l_auth_token = uuid_generate_v4();
		BEGIN
			insert into q_qr_auth_tokens ( token, user_id, sc_id ) values ( l_auth_token, l_user_id, p_sc_id );
		EXCEPTION WHEN unique_violation THEN
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to create user/auth-token.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to create user/auth-token.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
		END;
	end if;

	if not l_fail then
		select json_agg(t0.priv_name)::text
		into l_privileges
		from (
			select json_object_keys(t1.allowed::json)::text  as priv_name
				from q_qr_role2 as t1
				where t1.role_name = l_role_name
			) as t0
			;

		-- xyzzyError100 - never true iff.
		if not found then
			if l_debug_on then
				insert into t_output ( msg ) values ( 'Failed to get the privileges for the user' );
			end if;
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to get privileges for the user.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			l_privileges = '[]';
		end if;
	end if;

	if not l_fail then
		l_user_config = '';

		-- q8_user_config.sql
		select
				json_agg(
					json_build_object(
						'config_id', config_id,
						'name', name,
						'value', value
					)
				)::text as data
			into l_user_config
			from q_qr_user_config as t1
			where t1.user_id = l_user_id
			;

		if not found then
			l_user_config = '[]';
		end if;
	end if;

	if not l_fail then

		if l_debug_on then
			insert into t_output ( msg ) values ( 'function ->q_quth_v1_login<-..... Continued ...  m4___file__ m4___line__' );
			insert into t_output ( msg ) values ( 'calculate l_user_id ->'||coalesce(to_json(l_user_id)::text,'---null---')||'<-');
			insert into t_output ( msg ) values ( 'calculate l_privileges ->'||coalesce(l_privileges,'---null---')||'<-');
			insert into t_output ( msg ) values ( 'calculate l_client_id ->'||coalesce(to_json(l_client_id)::text,'---null---')||'<-');
		end if;

		-- xyzzyInsertNew - Move to - end where update4
		if not l_new_registration then

			-- all of these fieds are set/created with insert if this is a 'registration' operation (above).
			update q_qr_users
				set
					  failed_login_timeout = null
					, login_failures = 0
					, login_success = login_success + 1
					, privileges = l_privileges
					, email_verify_token = null
					, validator = p_validator
					, claims = p_claims
					, id_token = p_id_token
					, access_token = p_access_token
					, refresh_token = p_refresh_token
				where user_id = l_user_id
				;

		end if;

		-- add tmp_token, email to message so can complete registration.
		insert into q_qr_tmp_token ( user_id, token, auth_token ) values ( l_user_id, l_tmp_token, l_auth_token );
		if l_debug_on then
			insert into t_output ( msg ) values ( ' l_tmp_token ->'||coalesce(to_json(l_tmp_token)::text,'---null---')||'<-');
		end if;

		if l_debug_on then
			insert into t_output ( msg ) values ( 'function ->q_quth_v1_login<-..... Continued ... insert into q_qr_valid_xref_id m4___file__ m4___line__' );
		end if;

		l_client_user_config = '{}';
		SELECT json_agg(t1)
			INTO l_client_user_config
			FROM (
					select t2.name, t2.value
					from q_qr_user_config t2
					where t2.user_id = l_user_id
					  and t2.client_cfg = 'y'
					order by 1
				) as t1
			;
		if not found then
			l_client_user_config = '{}';
		end if;

		l_data = '{"status":"success"'
			||', "user_id":'     			||coalesce(to_json(l_user_id)::text,'""')
			||', "auth_token":'  			||coalesce(to_json(l_auth_token)::text,'""')
			||', "token":'  				||coalesce(to_json(l_token)::text,'""')
			||', "tmp_token":'   			||coalesce(to_json(l_tmp_token)::text,'""')
			||', "require_2fa":' 			||coalesce(to_json('n'::text)::text,'""')
			||', "account_type":'			||coalesce(to_json(l_account_type)::text,'""')
			||', "privileges":'  			||coalesce(l_privileges,'[]') -- $TYPE$ []string
			||', "user_config":'  			||coalesce(l_user_config,'{}') -- $TYPE$ map[string]string
			||', "client_user_config":'  	||coalesce(l_client_user_config,'{}') -- $TYPE$ map[string]string
			||', "first_name":'  			||coalesce(to_json(l_first_name)::text,'""')
			||', "last_name":'   			||coalesce(to_json(l_last_name)::text,'""')
			||', "is_new_device_login":' 	||coalesce(to_json(l_is_new_device_login)::text,'"n"')
			||', "client_id":'     			||coalesce(to_json(l_client_id)::text,'""')
			||', "acct_state":'     		||coalesce(to_json(l_acct_state)::text,'""')
			||', "is_new_device_msg":' 		||coalesce(to_json(l_is_new_device_msg)::text,'"--not-set--')
			||'}';

		if l_debug_on then
			insert into t_output ( msg ) values ( 'function ->q_quth_v1_login<-..... Continued ... data==success m4___file__ m4___line__' );
		end if;

	else

		if l_user_id is not null then
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Login Failure email:'||p_email, 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
			if l_debug_on then
				insert into t_output ( msg ) values ( 'function ->q_quth_v1_login<-..... Continued ... --- has user_id, status=failed/error --- m4___file__ m4___line__' );
			end if;
			if l_failed_login_timeout is not null then
				update q_qr_users
					set login_failures = login_failures + 1
					where user_id = l_user_id
					  and failed_login_timeout is not null
					  and login_failures >= 6
					;
			else
				update q_qr_users
					set login_failures = login_failures + 1
					  , failed_login_timeout = current_timestamp + interval '1 minute'
					where user_id = l_user_id
					  and failed_login_timeout is null
					  and login_failures >= 6
					;
				update q_qr_users
					set login_failures = login_failures + 1
					where user_id = l_user_id
					  and failed_login_timeout is null
					  and login_failures < 6
					;
			end if;
		end if;
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;







-- rvStatus, err := callme.CallAuthIdpSsoToken(c, pp.TmpToken, pp.XsrfId, pp.FPData, hashOfHeaders, pp.ScID)
CREATE OR REPLACE FUNCTION q_auth_v1_idp_sso_token ( p_tmp_token uuid, p_xsrf_id varchar, p_fp_data varchar, p_hash_of_headers varchar, p_sc_id varchar,  p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
AS $$
DECLARE
	l_2fa_id				uuid;
	l_data					text;
	l_fail					bool;
  	l_user_id 				uuid;
	l_account_type			varchar(20);
	l_auth_token			uuid;
	l_tmp_token				uuid;	-- when 2fa is on this is returnd as not null (UUID)
	l_debug_on 				bool;
	l_email					text;
	l_client_id				text;
	l_token					text;
	l_client_user_config 	text;
	l_user_config 			text;
	l_privileges			text;
	l_first_name			text;
	l_last_name				text;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2024.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()

	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_token = p_tmp_token;

	select t1.user_id, t1.auth_token, account_type, pgp_sym_decrypt(t2.email_enc, p_userdata_password)::text as email, t2.client_id
		    , pgp_sym_decrypt(t1.first_name_enc,p_userdata_password)::text as first_name
		    , pgp_sym_decrypt(t1.last_name_enc,p_userdata_password)::text as last_name
		into l_user_id, l_auth_token, l_account_type, l_email, l_client_id, l_first_name, l_last_name
		from q_qr_tmp_token as t1
			join q_qr_users as t2 on ( t1.user_id = t2.user_id )
		where t1.token = p_tmp_token
	  	for update
		;

	if not found then
		l_fail = true;
		l_data = '{"status":"error","msg":"Invalid tmp_token - start login process again.","code":"m4_count()","location":"m4___file__ m4___line__"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid tmp_token - start login process again.', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
	end if;
		
	if not l_fail then
		delete from q_qr_tmp_token
			where token = p_tmp_token
			;
	end if;

	if not l_fail then
		select json_agg(t0.priv_name)::text
		into l_privileges
		from (
			select json_object_keys(t1.allowed::json)::text  as priv_name
				from q_qr_role2 as t1
				where t1.role_name = l_role_name
			) as t0
			;

		if not found then
			if l_debug_on then
				insert into t_output ( msg ) values ( 'Failed to get the privileges for the user' );
			end if;
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to get privileges for the user.","code":"m4_count()","location":"m4___file__ m4___line__"}';
			l_privileges = '[]';
		end if;
	end if;

	if not l_fail then
		l_user_config = '';

		select
				json_agg(
					json_build_object(
						'config_id', config_id,
						'name', name,
						'value', value
					)
				)::text as data
			into l_user_config
			from q_qr_user_config as t1
			where t1.user_id = l_user_id
			;

		if not found then
			l_user_config = '[]';
		end if;
	end if;

	if not l_fail then
		l_client_user_config = '{}';
		SELECT json_agg(t1)
			INTO l_client_user_config
			FROM (
					select t2.name, t2.value
					from q_qr_user_config t2
					where t2.user_id = l_user_id
					  and t2.client_cfg = 'y'
					order by 1
				) as t1
			;
		if not found then
			l_client_user_config = '{}';
		end if;
	end if;

	if not l_fail then

		if l_debug_on then
			insert into t_output ( msg ) values ( 'function ->q_quth_v1_idp_sso_token<-..... Continued ...  m4___file__ m4___line__' );
			insert into t_output ( msg ) values ( 'calculate l_user_id ->'||coalesce(to_json(l_user_id)::text,'---null---')||'<-');
			insert into t_output ( msg ) values ( 'calculate l_client_id ->'||coalesce(to_json(l_client_id)::text,'---null---')||'<-');
			insert into t_output ( msg ) values ( 'calculate l_authy_token ->'||coalesce(to_json(l_authy_token)::text,'---null---')||'<-');
			insert into t_output ( msg ) values ( 'calculate l_privileges ->'||coalesce(to_json(l_privileges)::text,'---null---')||'<-');
			insert into t_output ( msg ) values ( 'calculate l_user_config ->'||coalesce(to_json(l_user_config)::text,'---null---')||'<-');
			insert into t_output ( msg ) values ( 'calculate l_client_user_config ->'||coalesce(to_json(l_client_user_config)::text,'---null---')||'<-');
			insert into t_output ( msg ) values ( 'calculate l_l_email ->'||coalesce(to_json(l_l_email)::text,'---null---')||'<-');
			insert into t_output ( msg ) values ( 'calculate l_l_token ->'||coalesce(to_json(l_l_token)::text,'---null---')||'<-');
			insert into t_output ( msg ) values ( 'calculate l_first_name ->'||coalesce(to_json(l_first_name)::text,'---null---')||'<-');
			insert into t_output ( msg ) values ( 'calculate l_l_last_name ->'||coalesce(to_json(l_l_last_name)::text,'---null---')||'<-');
		end if;

		l_data = '{"status":"success"'
			||', "user_id":'     			||coalesce(to_json(l_user_id)::text,'""')
			||', "auth_token":'  			||coalesce(to_json(l_auth_token)::text,'""')
			||', "account_type":'			||coalesce(to_json(l_account_type)::text,'""')
			||', "privileges":'  			||coalesce(l_privileges,'[]') -- $TYPE$ []string
			||', "user_config":'  			||coalesce(l_user_config,'{}') -- $TYPE$ map[string]string
			||', "client_user_config":'  	||coalesce(l_client_user_config,'{}') -- $TYPE$ map[string]string
			||', "client_id":'     			||coalesce(to_json(l_client_id)::text,'""')
			||', "email":'  				||coalesce(to_json(l_email)::text,'""')
			||', "token":'  				||coalesce(to_json(l_token)::text,'""')
			||', "first_name":'  			||coalesce(to_json(l_first_name)::text,'""')
			||', "last_name":'   			||coalesce(to_json(l_last_name)::text,'""')
			||'}';

	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;







--select q_auth_v1_idp_login_or_register ( 'bob@bob.com', 'https://test.example.com', '{"claims":"yep"}', 'p_id_token', 'p_access_token', 'p_refresh_token', 'y75lR1HeI/gb4nx2ZBe69D/FtZY=', '4Ti5G3HmJsw+gbDbMKKVs4tnRUU=', 'p_hash_of_headers', 'y', 'First', 'Bob' , '337eb9f5-95b0-4894-7ac7-2427daad8e22' );
--select q_auth_v1_idp_login_or_register ( 'bob@bob.com', 'https://test.example.com', '{"claims":"yep"}', 'p_id_token', 'p_access_token', 'p_refresh_token', 'y75lR1HeI/gb4nx2ZBe69D/FtZY=', '4Ti5G3HmJsw+gbDbMKKVs4tnRUU=', 'p_hash_of_headers', 'y', 'First', 'Bob' , '337eb9f5-95b0-4894-7ac7-2427daad8e22' );








-- vim: set noai ts=4 sw=4:
