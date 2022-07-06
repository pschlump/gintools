
--
-- Remember to 
--
-- 		$ sudo apt-get install postgresql-contrib-9.5
--
-- Before running this.
--
-- Must run as "postgres" user
--       ALTER ROLE pschlump SUPERUSER;
--

--$error-fatal$ Extensions uuid-ossp and pgrypto are required.  Check permissions for creating them.

CREATE EXTENSION if not exists "uuid-ossp";
CREATE EXTENSION if not exists pgcrypto;
CREATE EXTENSION if not exists fuzzystrmatch;

--$error-reset$


-- Copyright (C) Philip Schlump, 2008-2017, 2022.
-- BSD 3 Clause Licensed.  See LICENSE.bsd





-- -----------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------
-- 
--  Do not edit this .sql file - it is a generated output of m4 macro processor
--  Do not edit this .sql file - it is a generated output of m4 macro processor
--  Do not edit this .sql file - it is a generated output of m4 macro processor
--  Do not edit this .sql file - it is a generated output of m4 macro processor
-- 
-- -----------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------


-- xyzzy - TODO xyzzy889900 - add / remove priv from user.  In Dev.

-- xyzzy-Slow!! - better to do select count - and verify where before update.


-- Length should be 14 chars on on-one-time-passwords
-- -- --			l_tmp = substr(l_tmp,0,7) || substr(l_tmp,10,2);		-- this is bad
-- -- --			l_tmp = substr(l_tmp,0,7) || substr(l_tmp,10,5);		-- Change to....


-- fix all of these
--		insert into t_output ( msg ) values ( '  l_user_id ->'||coalesce(to_json(l_user_id)::text,'""')||'<-');


-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
drop view if exists q_qr_valid_token ;
drop view if exists q_qr_expired_token ;
drop view if exists q_qr_role_to_priv ;
drop view if exists q_qr_user_to_priv ;
drop view if exists q_qr_valid_tmp_token ;
drop view if exists q_qr_expired_tmp_token ;

drop table if exists q_qr_tmp_tokens cascade ;
drop table if exists q_qr_user_pii ;
drop table if exists q_qr_user_role ;
drop table if exists q_qr_role ;
drop table if exists q_qr_role_priv ;
drop table if exists q_qr_priv ;

drop table if exists q_qr_saved_state cascade;
drop table if exists q_qr_tmp_token cascade ;
drop table if exists q_qr_track_file cascade;
drop table if exists q_qr_track_by_group cascade;
drop table if exists q_qr_track_by_id cascade;
drop table if exists q_qr_headers cascade;
drop table if exists q_qr_one_time_password cascade;
drop table if exists q_qr_code cascade;
drop table if exists q_qr_auth_tokens cascade ;
drop table if exists q_qr_users cascade;
drop table if exists q_qr_auth_security_log cascade;
drop table if exists q_qr_auth_log cascade;
drop table if exists q_qr_trace_params ;		-- depricated ?? not used ??
drop table if exists q_qr_config ;
drop table if exists q_qr_manifest_version ;

drop table if exists t_output ;
drop table if exists t_valid_cors_origin ;
drop table if exists q_qr_uploaded_files ;

CREATE EXTENSION if not exists pgcrypto;








-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- General purpose output and debuging table.
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
create table if not exists t_output (
	  seq serial not null primary key
	, msg text
	, created 	timestamp default current_timestamp not null
);

-- used for cleanup of table - Delete everything that is 
-- more than 1 hour old?
create index t_output_p1 on t_output ( created );






-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- id.json - tracking table to see if user has been seen before on this device.
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
create table if not exists q_qr_manifest_version (
	  id			uuid DEFAULT uuid_generate_v4() not null primary key
	, hash_seen		text
	, user_id		int					-- a user specified ID to join to q_qr_users.user_id
	, updated 		timestamp
	, created 		timestamp default current_timestamp not null
);

create index q_qr_user_seen_before_p1 on q_qr_manifest_version using hash ( hash_seen );
create index q_qr_user_seen_before_p2 on q_qr_manifest_version ( created );



CREATE OR REPLACE function q_qr_manifest_version_upd()
RETURNS trigger AS $$
BEGIN
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	NEW.updated := current_timestamp;
	RETURN NEW;
END
$$ LANGUAGE 'plpgsql';


CREATE TRIGGER q_qr_manifest_version_trig
BEFORE update ON "q_qr_manifest_version"
FOR EACH ROW
EXECUTE PROCEDURE q_qr_manifest_version_upd();





-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- stmt := "q_auth_v1_etag_seen ( $1, $2, $3, $4 )"
create or replace function q_auth_v1_etag_seen ( p_id varchar, p_etag varchar, p_hmac_password varchar, p_userdata_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_debug_on 				bool;
	l_user_id				int;
	l_id					uuid;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_auth_v1_etag_seen <- 001.tables.m4.sql 126' );
		insert into t_output ( msg ) values ( '		p_id ->'||p_id||'<-');
		insert into t_output ( msg ) values ( '		p_etag ->'||p_etag||'<-');
	end if;

	if not l_fail then
		select
				  t1.id			
				, t1.user_id
			into
				  l_id
				, l_user_id
			from q_qr_manifest_version as t1
			where t1.hash_seen = p_etag
		;
		if not found then
			l_fail = true;
			l_data = '{"status":"success","msg":"created"}';
			insert into q_qr_manifest_version ( id, hash_seen ) values ( p_id::uuid, p_etag );
			l_id = p_id;
			if l_debug_on then
				insert into t_output ( msg ) values ( ' etag not found ' );
			end if;
		else
			update q_qr_manifest_version as t1
				set updated = current_timestamp 
				where t1.id = l_id
			;
		end if;
	end if;

	if not l_fail then

		l_data = '{"status":"success"'
			||', "user_id":' 		||coalesce(to_json(l_user_id)::text,'""')
			||', "id":' 			||coalesce(to_json(l_id)::text,'""')
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
--
-- select * from q_qr_manifest_version ;
--
-- select q_auth_v1_etag_device_mark ( 'cf217b21-b030-4e47-59d3-6ce00174e4ea',4,'my long secret password','user info password');
--
-- select * from q_qr_manifest_version ;

drop function q_auth_v1_etag_device_mark ( p_seen_id varchar, p_user_id varchar, p_hmac_password varchar, p_userdata_password varchar );
drop function q_auth_v1_etag_device_mark ( p_seen_id varchar, p_user_id int, p_hmac_password varchar, p_userdata_password varchar );

-- to be called when you have a successful 2fa validation on a user_id
create or replace function q_auth_v1_etag_device_mark ( p_seen_id varchar, p_user_id int, p_hmac_password varchar, p_userdata_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_debug_on 				bool;
	v_cnt 					int;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_auth_v1_etag_device_mark<- 001.tables.m4.sql 206' );
		insert into t_output ( msg ) values ( '		p_seen_id ->'||p_seen_id||'<-');
		insert into t_output ( msg ) values ( '		p_user_id ->'||p_user_id||'<-');
	end if;

	if not l_fail then
		update q_qr_manifest_version as t1
			set user_id = p_user_id
			where t1.id = p_seen_id::uuid
		;
		GET DIAGNOSTICS v_cnt = ROW_COUNT;
		if v_cnt = 0 then
			insert into q_qr_manifest_version ( id, user_id, hash_seen ) values ( p_seen_id::uuid, p_user_id, p_etag );
		elsif v_cnt > 0 then
			insert into t_output ( msg ) values ( '		set p_user_id ->'||p_user_id||'<- in q_qr_manifest_version');
		else
			insert into t_output ( msg ) values ( '		set p_user_id ->'||p_user_id||'<- !! not set !! q_qr_manifest_version');
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







CREATE SEQUENCE t_order_seq
  INCREMENT 1
  MINVALUE 1
  MAXVALUE 9223372036854775807
  START 1
  CACHE 1;

-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- stmt := "insert into q_qr_uploaded_fiels ( id, original_file_name, content_type, size ) values ( $1, $2, $3, $4 )"
drop table if exists q_qr_uploaded_files ;
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
    seq 				bigint DEFAULT nextval('t_order_seq'::regclass) NOT NULL 
);

-- xyzzy - Add group_n_id		int					-- user specifed.
-- xyzzy - add URL_path for getting file			-- URL for getting file.
-- xyzzy - add local_file_path for getting file		-- ./www/files/XXXX....

create index q_qr_uploaded_files_p1 on q_qr_uploaded_files ( group_id );
create index q_qr_uploaded_files_p2 on q_qr_uploaded_files using hash ( file_hash );
create index q_qr_uploaded_files_p3 on q_qr_uploaded_files ( group_n_id );
create index q_qr_uploaded_files_p4 on q_qr_uploaded_files ( url_path );
create index q_qr_uploaded_files_p5 on q_qr_uploaded_files ( local_file_path );


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



CREATE OR REPLACE function t_valid_cors_origin_upd()
RETURNS trigger AS $$
BEGIN
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	NEW.updated := current_timestamp;
	RETURN NEW;
END
$$ LANGUAGE 'plpgsql';


CREATE TRIGGER t_valid_cors_origin_trig
BEFORE update ON "t_valid_cors_origin"
FOR EACH ROW
EXECUTE PROCEDURE t_valid_cors_origin_upd();



insert into t_valid_cors_origin ( valid ) values
	  ( 'http://localhost:[0-9][0-9]*' )
	, ( 'https://localhost:[0-9][0-9]*' )
	;

-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- QR Tables 
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

create table if not exists q_qr_code (
	qr_code_id 			serial not null primary key,
	qr_type				varchar(30) not null default 'redirect' check ( qr_type in ( 'unknown', 'redirect', 'proxy', 'direct' ) ),
	qrid10				varchar(10) not null,
	body				text not null,		-- what is encoded in the QR
	file_name			text not null,		-- local relative file name
	url_name			text not null,		-- URL path to file
	owner_user_id		int,				-- UserId for the creator
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


-- create index q_qr_code_h1 on q_qr_code using hash ( qrid10 );
create unique index q_qr_code_h1 on q_qr_code ( qrid10 );






-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Headers Tables 
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

create table if not exists q_qr_headers (
	header_id 			serial not null primary key,
	qr_code_id 			int not null references q_qr_code ( qr_code_id ),
	header_name			text not null,
	header_value		text not null,
	updated 			timestamp, 									 						-- Project update timestamp (YYYYMMDDHHMMSS timestamp).
	created 			timestamp default current_timestamp not null 						-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);



CREATE OR REPLACE function q_qr_headers_upd()
RETURNS trigger AS $$
BEGIN
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	NEW.updated := current_timestamp;
	RETURN NEW;
END
$$ LANGUAGE 'plpgsql';


CREATE TRIGGER q_qr_headers_trig
BEFORE update ON "q_qr_headers"
FOR EACH ROW
EXECUTE PROCEDURE q_qr_headers_upd();








-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Tracking Tables 
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
create table if not exists q_qr_track_by_id (
	qr_code_id 			int not null references q_qr_code ( qr_code_id ),
	created 			timestamp default current_timestamp not null 						-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);

create index q_qr_track_by_id_p1 on q_qr_track_by_id ( created, qr_code_id );
create index q_qr_track_by_id_p2 on q_qr_track_by_id ( qr_code_id, created );


create table if not exists q_qr_track_by_group (
	qr_code_id 			int not null references q_qr_code ( qr_code_id ),
	group_id			int not null,
	created 			timestamp default current_timestamp not null 						-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);

create index q_qr_track_by_group_p1 on q_qr_track_by_group ( created, group_id );
create index q_qr_track_by_group_p2 on q_qr_track_by_group ( group_id, created );

create table if not exists q_qr_track_file (
	qr_code_id 			int not null references q_qr_code ( qr_code_id ),
	file_name			text not null,		-- local relative file name
	created 			timestamp default current_timestamp not null 						-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);

create index q_qr_track_file_p1 on q_qr_track_file ( created, qr_code_id );
create index q_qr_track_file_p2 on q_qr_track_file ( qr_code_id, created );

create index q_qr_track_file_p3 on q_qr_track_file ( file_name, created );
create index q_qr_track_file_p4 on q_qr_track_file ( created, file_name );






-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- State Table
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- SavedStateVars      map[string]string // uses cookie on client to save a set of state vars to d.b. -> g_quth_saved_state table
CREATE TABLE if not exists q_qr_saved_state (
	saved_state_id		uuid DEFAULT uuid_generate_v4() not null primary key, -- this is the X-Saved-State cookie
	user_id 			int not null,	-- should FK to user
	data				jsonb,			-- the data.
	expires 			timestamp not null,
	updated 			timestamp, 									 						-- Project update timestamp (YYYYMMDDHHMMSS timestamp).
	created 			timestamp default current_timestamp not null 						-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);

create index q_qr_saved_state_p1 on q_qr_saved_state ( expires );



CREATE OR REPLACE function q_qr_saved_state_upd()
RETURNS trigger AS $$
BEGIN
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	NEW.updated := current_timestamp;
	RETURN NEW;
END
$$ LANGUAGE 'plpgsql';


CREATE TRIGGER q_qr_saved_state_trig
BEFORE update ON "q_qr_saved_state"
FOR EACH ROW
EXECUTE PROCEDURE q_qr_saved_state_upd();



-- trigger to set expires

CREATE OR REPLACE function q_qr_saved_state_expires()
RETURNS trigger AS $$
BEGIN
	NEW.expires := current_timestamp + interval '92 days';
	RETURN NEW;
END
$$ LANGUAGE 'plpgsql';


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
-- 	auth_cfg				text default 'password' not null,		// 'sid' => use RFC 8235 => Use Validator, "password" => use passwrod_hash
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
-- alter table q_qr_users add column acct_state				varchar(40) default 'registered' check ( acct_state in ( 'registered', 'change-pw', 'change-2fa', 'change-email', 'other' ) );

CREATE TABLE if not exists q_qr_users (
	user_id 				serial not null primary key,
	email_hmac 				text not null,
	email_enc 				bytea not null,										-- encrypted/decryptable email address
	password_hash 			text not null,
	validation_method		varchar(10) default 'un/pw' not null check ( validation_method in ( 'un/pw', 'sip', 'srp6a', 'hw-key', 'webauthn' ) ),
	validator				text, -- p, q, a, v? -- Store as JSON and decode as necessary? { "typ":"sip", "ver":"v0.0.1", "v":..., "p":... }
	e_value					text,
	x_value					text,
	y_value					text,
	pdf_enc_password		text,	-- Password used for encryption of .pdf files - per user.
	first_name_enc			bytea not null,
	first_name_hmac 		text not null,
	last_name_enc			bytea not null,
	last_name_hmac 			text not null,
	acct_state				varchar(40) default 'registered' not null check ( acct_state in ( 'registered', 'change-pw', 'change-2fa', 'change-email', 'other' ) ),
	email_validated			varchar(1) default 'n' not null,
	email_verify_token		uuid,
	email_verify_expire 	timestamp,
	password_reset_token	uuid,
	password_reset_time		timestamp,
	failed_login_timeout 	timestamp,
	login_failures 			int default 0 not null,
	login_success 			int default 0 not null,
	parent_user_id 			int,
	account_type			varchar(20) default 'login' not null check ( account_type in ( 'login', 'un/pw', 'token', 'other' ) ),
	require_2fa 			varchar(1) default 'y' not null,
	secret_2fa 				varchar(20),
	setup_complete_2fa 		varchar(1) default 'n' not null,					-- Must be 'y' to login / set by q_auth_v1_validate_2fa_token 
	start_date				timestamp default current_timestamp not null,
	end_date				timestamp,
	privileges				text,
	updated 				timestamp, 									 		-- Project update timestamp (YYYYMMDDHHMMSS timestamp).
	created 				timestamp default current_timestamp not null 		-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);

CREATE UNIQUE INDEX q_qr_users_u1 on q_qr_users ( email_hmac );

CREATE INDEX q_qr_users_enc_u2 on q_qr_users ( email_verify_token )
	where email_verify_token is not null;

CREATE INDEX q_qr_users_enc_p1 on q_qr_users using HASH ( email_hmac );

CREATE INDEX q_qr_users_enc_p2 on q_qr_users ( email_verify_expire, email_validated )
	where email_verify_expire is not null;

CREATE INDEX q_qr_users_enc_p3 on q_qr_users ( password_reset_token )
	where password_reset_token is not null;

CREATE INDEX q_qr_users_enc_p4 on q_qr_users using HASH ( first_name_hmac );

CREATE INDEX q_qr_users_enc_p5 on q_qr_users using HASH ( last_name_hmac );



CREATE OR REPLACE function q_qr_users_upd()
RETURNS trigger AS $$
BEGIN
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	NEW.updated := current_timestamp;
	RETURN NEW;
END
$$ LANGUAGE 'plpgsql';


CREATE TRIGGER q_qr_users_trig
BEFORE update ON "q_qr_users"
FOR EACH ROW
EXECUTE PROCEDURE q_qr_users_upd();





-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- 	
-- 	 Personal informaiton related to user.  Data is encrypted JSON text in each field.
-- 	
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE if not exists q_qr_user_pii (
	user_id 				int not null primary key,
	pii_0					bytea,
	pii_1					bytea,
	pii_2					bytea,
	pii_3					bytea,
	pii_4					bytea,
	pii_5					bytea,
	pii_6					bytea,
	pii_7					bytea,
	pii_8					bytea,
	pii_9					bytea,
	updated 				timestamp, 									 		-- Project update timestamp (YYYYMMDDHHMMSS timestamp).
	created 				timestamp default current_timestamp not null 		-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);



CREATE OR REPLACE function q_qr_user_pii_upd()
RETURNS trigger AS $$
BEGIN
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	NEW.updated := current_timestamp;
	RETURN NEW;
END
$$ LANGUAGE 'plpgsql';


CREATE TRIGGER q_qr_user_pii_trig
BEFORE update ON "q_qr_user_pii"
FOR EACH ROW
EXECUTE PROCEDURE q_qr_user_pii_upd();




DROP FUNCTION if exists get_user_list(character varying,character varying);

CREATE OR REPLACE FUNCTION get_user_list( p_hmac_password varchar, p_userdata_password varchar )
RETURNS TABLE(
    user_id int,
    email text,
	first_name text,
	last_name text
)
AS $$
BEGIN
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








drop function q_auth_v1_hmac_encode_email ( p_email varchar, p_hmac_password varchar );

create or replace function q_auth_v1_hmac_encode ( p_email varchar, p_hmac_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
BEGIN
	-- insert into t_output ( msg ) values ( 'function ->q_quth_v1_hmac_encode_email<- 001.tables.m4.sql 569' );
	-- insert into t_output ( msg ) values ( 'In q_auth_v1_hmac_encode p_email ->'||p_email||'<-');
	-- insert into t_output ( msg ) values ( 'In q_auth_v1_hmac_encode p_hmac_password ->'||p_hmac_password||'<-');
	l_data = encode(hmac(p_email, p_hmac_password, 'sha256'), 'base64');
	-- l_data = encode(digest(p_hmac_password||p_email, 'sha256'), 'base64');
	-- l_data = p_email;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;

INSERT INTO q_qr_users (email_hmac, password_hash, first_name_enc, last_name_enc, email_enc ) VALUES
	    ( 
			 q_auth_v1_hmac_encode ( 'testAcct1@email.com', 'my-long-secret' )
			, crypt('Think Pink Ink 9434', gen_salt('bf') )
		    , pgp_sym_encrypt('Test User 1','p_userdata_password')
		    , pgp_sym_encrypt('Test User 1','p_userdata_password')
		    , pgp_sym_encrypt('testAcct1@email.com','p_userdata_password')
		)
	,   ( 
			 q_auth_v1_hmac_encode ( 'testAcct2@email.com', 'my--other-long-secret' )
			, crypt('Mimsey!81021', gen_salt('bf') )
		    , pgp_sym_encrypt('Test User 1','p_userdata_password')
		    , pgp_sym_encrypt('Test User 1','p_userdata_password')
		    , pgp_sym_encrypt('testAcct2@email.com','p_userdata_password')
		)
;



-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Auth Token Table
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE if not exists q_qr_auth_tokens (
	auth_token_id 	serial primary key not null,
	user_id 				int not null,
	token			 		uuid not null,
	api_encryption_key		text,
	expires 				timestamp not null
);

create unique index q_qr_auth_tokens_u1 on q_qr_auth_tokens ( token );
create index q_qr_auth_tokens_p1 on q_qr_auth_tokens ( user_id );
create index q_qr_auth_tokens_p2 on q_qr_auth_tokens ( expires );

ALTER TABLE q_qr_auth_tokens
	ADD CONSTRAINT q_qr_auth_tokens_fk1
	FOREIGN KEY (user_id)
	REFERENCES q_qr_users (user_id)
;


CREATE OR REPLACE function q_qr_auth_token_expires()
RETURNS trigger AS $$
BEGIN
	NEW.expires := current_timestamp + interval '31 days';
	RETURN NEW;
END
$$ LANGUAGE 'plpgsql';


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

CREATE TABLE if not exists q_qr_tmp_token (
	tmp_token_id 		serial primary key not null,
	user_id 			int not null,
	token			 	uuid not null,
	expires 			timestamp not null
);

--	sip_x_value				text,
--	sip_e_value				text,
--	sip_v_value				text,
--	sip_y_value				text,

create unique index q_qr_tmp_token_u1 on q_qr_tmp_token ( token );
create index q_qr_tmp_token_p1 on q_qr_tmp_token ( user_id );
create index q_qr_tmp_token_p2 on q_qr_tmp_token ( expires );

ALTER TABLE q_qr_tmp_token
	ADD CONSTRAINT q_qr_tmp_token_fk1
	FOREIGN KEY (user_id)
	REFERENCES q_qr_users (user_id)
;


CREATE OR REPLACE function q_qr_tmp_token_expires()
RETURNS trigger AS $$
BEGIN
	if NEW.expires is null then
		NEW.expires := current_timestamp + interval '20 minutes';
	end if;
	RETURN NEW;
END
$$ LANGUAGE 'plpgsql';


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
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE if not exists q_qr_auth_security_log (
	security_log_id 	serial primary key not null,
	user_id 			int not null,
	activity			text,
	location			text,
	created 			timestamp default current_timestamp not null 						-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);





-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE if not exists q_qr_auth_log (
	security_log_id 	serial primary key not null,
	user_id 			int,
	activity			text,
	code				text,
	location			text,
	created 			timestamp default current_timestamp not null 						-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);





-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- CREATE TABLE if not exists q_qr_trace_params (
-- 	trace_params_id 	serial primary key not null,
-- 	json_data			text,
-- 	created 			timestamp default current_timestamp not null 						-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
-- );





-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE if not exists q_qr_one_time_password (
	one_time_password_id 	serial primary key not null,
	user_id					int not null,
	otp_hmac				text
);

create unique index q_qr_one_time_password_u1 on q_qr_one_time_password ( user_id, otp_hmac );

ALTER TABLE q_qr_one_time_password 
	ADD CONSTRAINT q_qr_one_time_password_fk1
	FOREIGN KEY (user_id)
	REFERENCES q_qr_users (user_id)
;









-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE if not exists q_qr_config (
	config_id 		serial primary key not null,
	name			text,
	value	 		text,
	b_value	 		bool,
	updated 		timestamp, 									 						-- Project update timestamp (YYYYMMDDHHMMSS timestamp).
	created 		timestamp default current_timestamp not null 						-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);

create unique index q_qr_config_u1 on q_qr_config ( name ) ;



CREATE OR REPLACE function q_qr_config_upd()
RETURNS trigger AS $$
BEGIN
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	NEW.updated := current_timestamp;
	RETURN NEW;
END
$$ LANGUAGE 'plpgsql';


CREATE TRIGGER q_qr_config_trig
BEFORE update ON "q_qr_config"
FOR EACH ROW
EXECUTE PROCEDURE q_qr_config_upd();



insert into q_qr_config ( name, value, b_value ) values 
	  ( 'debug', 'yes', true )
	, ( 'trace', 'yes', true )
	, ( 'config.test', 'yes', true )
;






-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

-- M:N join from users to roles.   The set of roles that a user has.
create table if not exists q_qr_user_role (
	user_role_id serial not null primary key,
	role_id int not null,
	user_id int not null
);

create unique index q_qr_user_role_u1 on q_qr_user_role ( role_id, user_id );
create unique index q_qr_user_role_u2 on q_qr_user_role ( user_id, role_id );

-- A list of all the possible roles that a user can have.
create table if not exists q_qr_role (
	  role_id serial not null primary key
	, role_name text not null
	-- , role_name_tokens tsvector
);

create unique index q_qr_role_u1 on q_qr_role ( role_name );

-- M:N join from roles to privileges - the set of privileges that each role has.
create table if not exists q_qr_role_priv (
	role_priv_id serial not null primary key,
	role_id int not null,
	priv_id int not null
);

create unique index q_qr_role_priv_u1 on q_qr_role_priv ( priv_id, role_id );
create unique index q_qr_role_priv_u2 on q_qr_role_priv ( role_id, priv_id );

-- A talbe containing all the possible things that a person can have a permission to do.
create table if not exists q_qr_priv (
	  priv_id serial not null primary key
	, priv_name text not null
	-- , priv_name_tokens tsvector
);

create unique index q_qr_priv_u1 on q_qr_priv ( priv_name );


CREATE OR REPLACE view q_qr_role_to_priv as
	select t1.role_name, t3.priv_name, t1.role_id, t3.priv_id
	from q_qr_role as t1
		join q_qr_role_priv as t2 on ( t2.role_id = t1.role_id )
		join q_qr_priv as t3 on ( t2.priv_id = t3.priv_id )
	;

CREATE OR REPLACE view q_qr_user_to_priv as
	select t1.user_id, t5.priv_name, t5.priv_id, t3.role_name, t3.role_id, t4.role_priv_id, t2.user_role_id
	from q_qr_users as t1
		join q_qr_user_role as t2 on ( t1.user_id = t2.user_id )
		join q_qr_role      as t3 on ( t2.role_id = t3.role_id )
		join q_qr_role_priv as t4 on ( t3.role_id = t4.role_id )
		join q_qr_priv      as t5 on ( t4.priv_id = t5.priv_id )
	;


-- https://rudra.dev/posts/generate-beautiful-json-from-postgresql/
-- xyzzy - TODO - xyzzy89232323 - Add in triggers gor generation of keywords / tsvector
select row_to_json("t2")
	from (
		select t1.priv_name, true as istrue 
		from q_qr_user_to_priv as t1
	) as t2
	;

SELECT json_agg(row_to_json(t2))
      FROM (
		select t1.priv_name, true as istrue 
		from q_qr_user_to_priv as t1
      ) t2
	;

SELECT json_agg(row_to_json(t2))
      FROM (
		select t1.priv_name
		from q_qr_user_to_priv as t1
      ) t2
	;


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
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
delete from q_qr_priv cascade;
delete from q_qr_role cascade;
delete from q_qr_role_priv cascade;
delete from q_qr_user_role cascade;
insert into q_qr_priv ( priv_id, priv_name ) values 
	  ( 2001, 'May Change Other Password' )
	, ( 2002, 'May Shutdown Server' )
	, ( 2003, 'May Change Password' )
	, ( 2004, 'May Call Test' )

	, ( 2005, 'Create New Priv' )
	, ( 2006, 'Modify Priv' )
	, ( 2007, 'List Priv' )
	, ( 2008, 'Delete Priv' )

	, ( 2009, 'Create New Role' )
	, ( 2010, 'Modify Role' )
	, ( 2011, 'List Role' )
	, ( 2012, 'Delete Role' )

	, ( 2013, 'May Login' )
	, ( 2014, 'May Add/Rmeove Role From User' )
	, ( 2015, 'May Insert BOL' )
	, ( 2016, 'May Update BOL' )
	, ( 2017, 'May Delete BOL' )
	, ( 2020, 'May Select BOL' )
	, ( 2018, 'May Register' )
	, ( 2019, 'May BOL' )
;
insert into q_qr_role ( role_id, role_name ) values
	  ( 1001, 'role:admin' )
	, ( 1002, 'role:server-maint' )
	, ( 1003, 'role:user' )
;
insert into q_qr_role_priv ( role_id,  priv_id ) values
	  ( 1001, 2001 )
	, ( 1001, 2002 )
	, ( 1001, 2003 )
	, ( 1001, 2004 )
	, ( 1001, 2006 )
	, ( 1001, 2007 )
	, ( 1001, 2008 )
	, ( 1001, 2009 )
	, ( 1001, 2010 )
	, ( 1001, 2011 )
	, ( 1001, 2012 )
	, ( 1001, 2013 )
	, ( 1001, 2014 )
	, ( 1001, 2018 )
	, ( 1001, 2019 )

	, ( 1002, 2002 )
	, ( 1002, 2004 )
	, ( 1002, 2013 )

	, ( 1003, 2003 )
	, ( 1003, 2004 )
	, ( 1003, 2013 )
	, ( 1003, 2018 )
	, ( 1003, 2019 )
;

-- ALTER SEQUENCE i_role_priv_seq RESTART WITH 10;


-- Reset the sequence to 1
ALTER SEQUENCE q_qr_priv_priv_id_seq RESTART;
SELECT nextval('q_qr_priv_priv_id_seq');

-- Login to psql and run the following

-- What is the result?
SELECT MAX(priv_id) FROM q_qr_priv;

-- Then run...
-- This should be higher than the last result.
SELECT nextval('q_qr_priv_priv_id_seq');

-- If it's not higher... run this set the sequence last to your highest id.
-- (wise to run a quick pg_dump first...)

BEGIN;
-- protect against concurrent inserts while you update the counter
LOCK TABLE q_qr_priv IN EXCLUSIVE MODE;
-- Update the sequence
SELECT setval('q_qr_priv_priv_id_seq', COALESCE((SELECT MAX(priv_id)+1 FROM q_qr_priv), 1), false);
COMMIT;

-- Validate the sequence at the end.
SELECT nextval('q_qr_priv_priv_id_seq');




-- Reset the sequence to 1
ALTER SEQUENCE q_qr_role_role_id_seq RESTART;
SELECT nextval('q_qr_role_role_id_seq');

-- Login to psql and run the following

-- What is the result?
SELECT MAX(role_id) FROM q_qr_role;

-- Then run...
-- This should be higher than the last result.
SELECT nextval('q_qr_role_role_id_seq');

-- If it's not higher... run this set the sequence last to your highest id.
-- (wise to run a quick pg_dump first...)

BEGIN;
-- protect against concurrent inserts while you update the counter
LOCK TABLE q_qr_role IN EXCLUSIVE MODE;
-- Update the sequence
SELECT setval('q_qr_role_role_id_seq', COALESCE((SELECT MAX(role_id)+1 FROM q_qr_role), 1), false);
COMMIT;

-- Validate the sequence at the end.
SELECT nextval('q_qr_role_role_id_seq');




-- Reset the sequence to 1
ALTER SEQUENCE q_qr_user_role_user_role_id_seq RESTART;
SELECT nextval('q_qr_user_role_user_role_id_seq');

-- Login to psql and run the following

-- What is the result?
SELECT MAX(user_role_id) FROM q_qr_user_role;

-- Then run...
-- This should be higher than the last result.
SELECT nextval('q_qr_user_role_user_role_id_seq');

-- If it's not higher... run this set the sequence last to your highest id.
-- (wise to run a quick pg_dump first...)

BEGIN;
-- protect against concurrent inserts while you update the counter
LOCK TABLE q_qr_user_role IN EXCLUSIVE MODE;
-- Update the sequence
SELECT setval('q_qr_user_role_user_role_id_seq', COALESCE((SELECT MAX(user_role_id)+1 FROM q_qr_user_role), 1), false);
COMMIT;

-- Validate the sequence at the end.
SELECT nextval('q_qr_user_role_user_role_id_seq');




-- Reset the sequence to 1
ALTER SEQUENCE q_qr_role_priv_role_priv_id_seq RESTART;
SELECT nextval('q_qr_role_priv_role_priv_id_seq');

-- Login to psql and run the following

-- What is the result?
SELECT MAX(role_priv_id) FROM q_qr_role_priv;

-- Then run...
-- This should be higher than the last result.
SELECT nextval('q_qr_role_priv_role_priv_id_seq');

-- If it's not higher... run this set the sequence last to your highest id.
-- (wise to run a quick pg_dump first...)

BEGIN;
-- protect against concurrent inserts while you update the counter
LOCK TABLE q_qr_role_priv IN EXCLUSIVE MODE;
-- Update the sequence
SELECT setval('q_qr_role_priv_role_priv_id_seq', COALESCE((SELECT MAX(role_priv_id)+1 FROM q_qr_role_priv), 1), false);
COMMIT;

-- Validate the sequence at the end.
SELECT nextval('q_qr_role_priv_role_priv_id_seq');



-- Assign default privileges to each user.
insert into q_qr_user_role ( user_id, role_id ) 
	select t1.user_id, t2.role_id
	from q_qr_users as t1
 		, q_qr_role as t2 
	where t2.role_name = 'role:user'
;







-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- if not HasPriv ( p_admin_user_id, 'May Change Other Password' ) then
create or replace function q_amdin_HasPriv ( p_user_id int, p_priv_needed varchar )
	returns bool
	as $$
DECLARE
	l_data bool;
	l_found text;
BEGIN
	l_data = false;

	if exists (
 			select 'found'
 			from q_qr_user_to_priv
 			where user_id = p_user_id
 			  and priv_name = p_priv_needed
		) then
 		l_data = true;
 	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;









create or replace function q_amdin_add_priv_to_role ( p_role_id int, p_priv_id varchar )
	returns text
	as $$
DECLARE
	l_data text;
	l_found text;
	l_fail bool;
BEGIN
	l_data = '{"status":"failed"}';
	l_fail = false;

	-- xyzzyAuth , ( 2013, , ( 2010, 'Modify Role' )
	if not q_amdin_HasPriv ( p_user_id, 'Modify Role' ) then
		l_fail = true;
		l_data = '{"status":"error","msg":"Not authoriazed to ''Modify Role''","code":"0001","location":"001.tables.m4.sql 1058"}'; 
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Not authorized to ''Modify Role''', '0001', 'File:001.tables.m4.sql Line No:1059');
	end if;

	if not l_fail then
		select 'found' 
			into l_found
			where exists ( 
				select 'found' 
			)
			;
		if not found then
			insert into q_qr_role_priv ( role_id, priv_id ) values ( p_role_id, p_priv_id );
			l_data = '{"status":"success"}';
		else
			l_data = '{"status":"error","msg":"Duplicate Privilege"}';
		end if;
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;



create or replace function q_amdin_remove_priv_from_role ( p_role_id int, p_priv_id varchar )
	returns text
	as $$
DECLARE
	l_data text;
	l_found text;
	l_fail bool;
BEGIN
	l_data = '{"status":"failed"}';
	l_fail = false;

	-- xyzzyAuth , ( 2013, , ( 2010, 'Modify Role' )
	if not q_amdin_HasPriv ( p_user_id, 'Modify Role' ) then
		l_fail = true;
		l_data = '{"status":"error","msg":"Not authoriazed to ''Modify Role''","code":"0002","location":"001.tables.m4.sql 1097"}'; 
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Not authorized to ''Modify Role''', '0002', 'File:001.tables.m4.sql Line No:1098');
	end if;

	if not l_fail then
		delete from q_qr_role_priv
			where role_id = p_role_id
			  and priv_id = p_priv_id
			;

		if found then
			l_data = '{"status":"success"}';
		else
			l_data = '{"status":"error","msg":"Nonexistent Privilege"}';
		end if;
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;


-- Give User Role
-- Revoke User Role
-- Add New Role
-- Remove role






-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
create or replace function q_get_config ( p_name varchar )
	returns text
	as $$
DECLARE
	l_data text;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	select value into l_data from q_qr_config where name = p_name;
	if not found then
		l_data = '';
	end if;
	RETURN l_data;
END;
$$ LANGUAGE plpgsql;

drop function q_get_config_bool ( p_name varchar );
create or replace function q_get_config_bool ( p_name varchar )
	returns bool
	as $$
DECLARE
	l_data bool;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	select b_value into l_data from q_qr_config where name = p_name;
	if not found then
		l_data = false;
	end if;
	RETURN l_data;
END;
$$ LANGUAGE plpgsql;








-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- 1. q_auth_v1_recover_password_01_setup -> change d.b. - return token. -- (( Indirctly sends email ))
create or replace function q_auth_v1_recover_password_01_setup ( p_email varchar, p_hmac_password varchar, p_userdata_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_first_name			text;
	l_last_name				text;
	l_fail					bool;
	l_recovery_token		uuid;
	v_cnt 					int;
	l_user_id				int;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_recovery_token		= uuid_generate_v4();


	if not l_fail then
		select
			  user_id
		    , pgp_sym_decrypt(first_name_enc,p_userdata_password)::text
		    , pgp_sym_decrypt(last_name_enc,p_userdata_password)::text
		into
			  l_user_id
			, l_first_name
			, l_last_name
		from q_qr_users as t1
		where t1.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
		  and t1.parent_user_id is null
		  and t1.account_type = 'login'
		  and ( t1.start_date < current_timestamp or t1.start_date is null )
		  and ( t1.end_date > current_timestamp or t1.end_date is null )
		  and t1.email_validated = 'y'
		  and t1.setup_complete_2fa = 'y'
		;
		if not found then

			-- Select to get l_user_id for email.  If it is not found above then this may not be a fully setup user.
			-- The l_user_id is used below in a delete to prevet marking of devices as having been seen.
			select
				  user_id
			into
				  l_user_id
			from q_qr_users as t1
			where t1.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
			;

			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or not email validated","code":"0003","location":"001.tables.m4.sql 1228"}'; 
		end if;
	end if;

	-- Delete all the id.json rows for this user - every marked device will nedd to 2fa after this request.
	delete from q_qr_manifest_version where user_id = l_user_id;

	if not l_fail then
		update q_qr_users as t1
			set 
				  password_reset_token = l_recovery_token		
				, password_reset_time = current_timestamp + interval '4 hours'
			where t1.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
			  and t1.user_id = l_user_id
			  and t1.account_type = 'login'
			  and ( t1.start_date < current_timestamp or t1.start_date is null )
			  and ( t1.end_date > current_timestamp or t1.end_date is null )
			  and t1.email_validated = 'y'
			  and t1.setup_complete_2fa = 'y'
			  and t1.parent_user_id is null
			;
		-- check # of rows.
		GET DIAGNOSTICS v_cnt = ROW_COUNT;
		if v_cnt != 1 then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or not email validated","code":"0004","location":"001.tables.m4.sql 1253"}'; 
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or not email validated', '0004', 'File:001.tables.m4.sql Line No:1254');
		end if;
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "recovery_token":'   ||coalesce(to_json(l_recovery_token)::text,'""')
			||', "first_name":'   ||coalesce(to_json(l_first_name)::text,'""')
			||', "last_name":'   ||coalesce(to_json(l_last_name)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;








-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--    q_auth_v1_recover_password_02_fetch_info -- Take token to get info about user - see if token is valid.
create or replace function q_auth_v1_recover_password_02_fetch_info ( p_email varchar, p_recovery_token varchar, p_hmac_password varchar, p_userdata_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_tmp					text;
	l_user_id				int;
	l_first_name			text;
	l_last_name				text;
	l_email					text;
	l_recovery_token		uuid;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if not l_fail then
		select
			  user_id
		    , pgp_sym_decrypt(first_name_enc,p_userdata_password)::text
		    , pgp_sym_decrypt(last_name_enc,p_userdata_password)::text
		    , pgp_sym_decrypt(email_enc::bytea,p_userdata_password)::text
		into
			  l_user_id
			, l_first_name
			, l_last_name
			, l_email					
		from q_qr_users as t1
		where t1.password_reset_token = p_recovery_token::uuid
		  and t1.parent_user_id is null
		  and t1.account_type = 'login'
		  and ( t1.start_date < current_timestamp or t1.start_date is null )
		  and ( t1.end_date > current_timestamp or t1.end_date is null )
		  and t1.email_validated = 'y'
		  and t1.setup_complete_2fa = 'y'
		;
		if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or not email validated","code":"0005","location":"001.tables.m4.sql 1321"}'; 
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or not email validated', '0005', 'File:001.tables.m4.sql Line No:1322');
		end if;
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "email":'   	||coalesce(to_json(l_email)::text,'""')
			||', "first_name":'  ||coalesce(to_json(l_first_name)::text,'""')
			||', "last_name":'  ||coalesce(to_json(l_last_name)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;









-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--    q_auth_v1_recover_password_03_set_password -- Take token and new password - set it.
create or replace function q_auth_v1_recover_password_03_set_password ( p_email varchar, p_new_pw varchar, p_recovery_token varchar, p_hmac_password varchar, p_userdata_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_fail					bool;
	v_cnt 					int;
	l_user_id				int;
	l_first_name				text;
	l_last_name				text;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if not l_fail then
		select
			  user_id
		    , pgp_sym_decrypt(first_name_enc,p_userdata_password)::text
		    , pgp_sym_decrypt(last_name_enc,p_userdata_password)::text
		into
			  l_user_id
			, l_first_name
			, l_last_name
		from q_qr_users as t1
		where t1.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
		  and t1.password_reset_time > current_timestamp
		  and t1.password_reset_token = p_recovery_token::uuid
		  and t1.account_type = 'login'
		  and ( t1.start_date < current_timestamp or t1.start_date is null )
		  and ( t1.end_date > current_timestamp or t1.end_date is null )
		  and t1.email_validated = 'y'
		  and t1.setup_complete_2fa = 'y'
		  and t1.parent_user_id is null
		;
		if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or not email validated","code":"0006","location":"001.tables.m4.sql 1388"}'; 
		end if;
	end if;

	if not l_fail then
		update q_qr_users as t1
			set 
				  password_reset_token = null
				, password_reset_time = null
				, password_hash = crypt(p_new_pw, gen_salt('bf') )
			where t1.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
			  and t1.password_reset_time > current_timestamp
			  and t1.password_reset_token = p_recovery_token::uuid
		  	  and t1.account_type = 'login'
		  	  and ( t1.start_date < current_timestamp or t1.start_date is null )
		  	  and ( t1.end_date > current_timestamp or t1.end_date is null )
			  and t1.email_validated = 'y'
			  and t1.setup_complete_2fa = 'y'
		  	  and t1.parent_user_id is null
			;
		-- check # of rows.
		GET DIAGNOSTICS v_cnt = ROW_COUNT;
		if v_cnt != 1 then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or not email validated","code":"0007","location":"001.tables.m4.sql 1412"}'; 
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or not email validated', '0007', 'File:001.tables.m4.sql Line No:1413');
		end if;
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "recovery_token":'   ||coalesce(to_json(p_recovery_token)::text,'""')
			||', "first_name":'        ||coalesce(to_json(l_first_name)::text,'""')
			||', "last_name":'        ||coalesce(to_json(l_last_name)::text,'""')
			||'}';
	end if;


	RETURN l_data;
END;
$$ LANGUAGE plpgsql;










-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
create or replace function q_auth_v1_delete_account ( p_email varchar, p_pw varchar, p_hmac_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_fail					bool;
	v_cnt 					int;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	-- Other Checks for valid account login.

	-- xyzzy - SIP accounts fail to do validation that this is a legitimate user.  This is done in the Go code with a "logged" in user.

	if not l_fail then
		update q_qr_users as t1
			set 
				    start_date = current_timestamp + interval '10 years'
				  , end_date = current_timestamp - interval '1 minute'
			where t1.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
				and (
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
					)
				 )
			;
		-- check # of rows.
		GET DIAGNOSTICS v_cnt = ROW_COUNT;
		if v_cnt != 1 then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or not email validated","code":"0008","location":"001.tables.m4.sql 1490"}'; 
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or not email validated', '0009', 'File:001.tables.m4.sql Line No:1491');
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
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--	tgo_add_priv_to_user.sh -> q_qr_add_priv_to_user(...)
create or replace function q_auth_v1_add_priv_to_user ( p_email varchar, p_priv varchar, p_hmac_password varchar, p_userdata_password varchar)
	returns text
	as $$
DECLARE
	l_data					text;
	l_junk					text;
	l_fail					bool;
	l_debug_on 				bool;
	l_user_id				int;
	l_role_id				int;
	l_user_role_id			int;
	l_priv_id				int;
	l_role_priv_id			int;
	l_user_priv_id			int;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	select t1.user_id
		into l_user_id
		from q_qr_users as t1
		where t1.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
		;
	if not found then
		l_fail = true;
		l_data = '{"status":"error","msg":"Missing Account.","code":"0011","location":"001.tables.m4.sql 1545"}';
	end if;

	if not l_fail then

		-- -----------------------------------------------------------------------------------
		-- Insert new role for this user if not exists.
		-- -----------------------------------------------------------------------------------
		select role_id
			into l_role_id
			from q_qr_role as t1
			where t1.role_name = 'user_role:'||l_user_id::text
			;
		-- ) returning user_id into l_user_id  ;
		if not found then
			insert into q_qr_role ( role_name ) values ( 'user_role:'||l_user_id::text ) returning ( user_role_id ) into l_role_id;
		end if;

		-- -----------------------------------------------------------------------------------
		-- Insert new role_priv if not exists.
		-- -----------------------------------------------------------------------------------
		select role_id
			into l_user_role_id
			from q_qr_user_role as t1
			where t1.role_id = l_role_id
			  and t1.user_id = l_user_id
			;
		if not found then
			insert into q_qr_user_role ( role_id, user_id ) values ( l_role_id, l_user_id ) returning ( user_role_id ) into l_user_role_id;
		end if;

		-- -----------------------------------------------------------------------------------
		-- Insert new priv if not exists.
		-- -----------------------------------------------------------------------------------
		select priv_id
			into l_priv_id
			from q_qr_priv as t1
			where t1.priv_name = p_priv
			;
		if not found then
			insert into q_qr_priv ( priv_name ) values ( p_priv ) returning ( user_priv_id ) into l_priv_id;
		end if;

		-- -----------------------------------------------------------------------------------
		-- Insert link from role to priv
		-- -----------------------------------------------------------------------------------
		select priv_id
			into l_priv_id
			from q_qr_role_priv as t1
			where t1.role_id = l_role_id
			  and t1.priv_id = l_priv_id
			;
		if not found then
			insert into q_qr_role_priv ( priv_id, role_id ) values ( l_priv_id, l_role_id ) returning ( user_priv_id ) into l_user_priv_id;
		end if;

	end if;

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
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--	tgo_rm_priv_from_user.sh -> q_qr_rm_priv_from_user(...)
create or replace function q_auth_v1_rm_priv_from_user ( p_email varchar, p_priv varchar, p_hmac_password varchar, p_userdata_password varchar)
	returns text
	as $$
DECLARE
	l_data					text;
	l_junk					text;
	l_fail					bool;
	l_debug_on 				bool;
	l_user_id				int;
	l_role_id				int;
	l_user_role_id			int;
	l_priv_id				int;
	l_role_priv_id			int;
	l_user_priv_id			int;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	select t1.user_id
		into l_user_id
		from q_qr_users as t1
		where t1.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
		;
	if not found then
		l_fail = true;
		l_data = '{"status":"error","msg":"Missing Account.","code":"0011","location":"001.tables.m4.sql 1658"}';
	end if;

	if not l_fail then

		-- xyzzy - TODO xyzzy889900

		-- If found then the priv is a per-user role priv and easy to delete.
		select role_id, priv_id
			into l_role_id, l_priv_id
			from q_qr_user_to_priv as t1
			where t1.role_name = 'user_role:'||l_user_id::text
			  and t1.user_id = l_user_id
			  and t1.priv_name = p_priv
			limit 1
			;

		if not found then

			-- Convert all privs to per-user-role privs. (Except the one we want to delete)

			-- -----------------------------------------------------------------------------------
			-- Insert new role for this user if not exists.
			-- -----------------------------------------------------------------------------------
			select role_id
				into l_role_id
				from q_qr_role as t1
				where t1.role_name = 'user_role:'||l_user_id::text
				;
			if not found then
				insert into q_qr_role ( role_name ) values ( 'user_role:'||l_user_id::text ) returning ( user_role_id ) into l_role_id;
			end if;

			-- -----------------------------------------------------------------------------------
			-- Insert new user_role if not exists.
			-- -----------------------------------------------------------------------------------
			select role_id
				into l_user_role_id
				from q_qr_user_role as t1
				where t1.role_id = l_role_id
				  and t1.user_id = l_user_id
				;
			if not found then
				insert into q_qr_user_role ( role_id, user_id ) values ( l_role_id, l_user_id ) returning ( user_role_id ) into l_user_role_id;
			end if;

			-- -----------------------------------------------------------------------------------
			-- Insert link from role to priv
			-- -----------------------------------------------------------------------------------
			insert into q_qr_role_priv ( priv_id, role_id ) 
				select t1.priv_id, t1.role_id
				from q_qr_user_to_priv as t1
				where t1.role_name = 'user_role:'||l_user_id::text
				  and t1.user_id = l_user_id
				  and t1.role_id = l_role_id
				  and not exists (
					select 'found'
					from q_qr_role_priv as t2
					where t2.role_id = t1.role_id
					  and t2.priv_id = t1.priv_id
				  ) and not exists (
					select t3.priv_id
					from q_qr_priv as t3
					where t3.priv_name = p_priv
				  )
				;
			delete from q_qr_user_role as t1
				where t1.user_id = l_user_id
				  and t1.role_id <> l_role_id
				;

		else

			-- -----------------------------------------------------------------------------------
			-- Insert new role for this user if not exists.
			-- -----------------------------------------------------------------------------------
			select role_id
				into l_role_id
				from q_qr_role as t1
				where t1.role_name = 'user_role:'||l_user_id::text
				;

			-- -----------------------------------------------------------------------------------
			-- Insert new role_priv if not exists.
			-- -----------------------------------------------------------------------------------
			select role_id
				into l_user_role_id
				from q_qr_user_role as t1
				where t1.role_id = l_role_id
				  and t1.user_id = l_user_id
				;

			-- -----------------------------------------------------------------------------------
			-- Insert new priv if not exists.
			-- -----------------------------------------------------------------------------------
			select priv_id
				into l_priv_id
				from q_qr_priv as t1
				where t1.priv_name = p_priv
				;

			-- -----------------------------------------------------------------------------------
			-- Insert link from role to priv
			-- -----------------------------------------------------------------------------------
			select priv_id
				into l_priv_id
				from q_qr_role_priv as t1
				where t1.role_id = l_role_id
				  and t1.priv_id = l_priv_id
				;

			delete from q_qr_user_role as t1
				where t1.user_id = l_user_id
				  and t1.role_id = l_role_id
				;

		end if;

	end if;

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
create or replace function u_test_proc_call ( p_aaa varchar, p_user_id varchar, p_hmac_password varchar, p_userdata_password varchar)
	returns text
	as $$
DECLARE
	l_data					text;
	l_junk					text;
	l_fail					bool;
	l_debug_on 				bool;
	l_user_id				int;
	l_role_id				int;
	l_user_role_id			int;
	l_priv_id				int;
	l_role_priv_id			int;
	l_user_priv_id			int;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
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
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

create or replace function q_auth_v1_register ( p_email varchar, p_pw varchar, p_hmac_password varchar, p_first_name varchar, p_last_name varchar, p_userdata_password varchar, p_secret varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_junk					text;
	l_fail					bool;
	l_user_id				int;
	l_bad_user_id			int;
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
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_email_verify_token = uuid_generate_v4();

	-- l_tmp = uuid_generate_v4()::text;
	-- l_secret_2fa = substr(l_tmp,0,7) || substr(l_tmp,10,4);
	l_secret_2fa = p_secret;

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_register<- 001.tables.m4.sql 1901' );
		insert into t_output ( msg ) values ( '  p_email ->'||p_email||'<-');
		insert into t_output ( msg ) values ( '  p_pw ->'||p_pw||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||p_hmac_password||'<-');
		insert into t_output ( msg ) values ( '  p_first_name ->'||p_first_name||'<-');
		insert into t_output ( msg ) values ( '  p_last_name ->'||p_last_name||'<-');
		insert into t_output ( msg ) values ( '  p_userdata_password ->'||p_userdata_password||'<-');
		insert into t_output ( msg ) values ( '  p_secret ->'||p_secret||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	-- Cleanup any users that have expired tokens.
	delete from q_qr_users
		where email_verify_expire < current_timestamp - interval '30 days'
		  and email_validated = 'n'
		;
	-- Cleanup any users that have expired saved state
	delete from q_qr_saved_state
		where expires < current_timestamp
		;

	-- Cleanup old tmp tokens.
	delete from q_qr_tmp_token 
		where expires < current_timestamp
		;

	-- If user has hever logged in and is attempting to register the user again - then delete old user - must have same email.
	-- PERFORM * FROM foo WHERE x = 'abc' AND y = 'xyz';
	-- IF FOUND THEN
	-- 	....
	-- END IF;
	-- , login_success = login_success + 1
	select q_auth_v1_delete_user ( user_id )
		into l_junk
		from q_qr_users as t1
		where t1.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
		  and t1.login_success = 0
		;
	select user_id
		into l_bad_user_id
		from q_qr_users as t1
		where t1.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
		;
	if found then
		l_fail = true;
		l_data = '{"status":"error","msg":"Account already exists.  Please login or recover password.","code":"0011","location":"001.tables.m4.sql 1946"}';
		-- insert into q_qr_auth_security_log ( user_id, activity, location ) values ( l_bad_user_id, 'User Attempt to Re-Register Same Accont', 'File:001.tables.m4.sql Line No:1947');
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_bad_user_id, 'User Attempt to Re-Register Same Account.', '0011', 'File:001.tables.m4.sql Line No:1948');
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

		select json_agg(t1.priv_name)::text
			into l_privs
			from q_qr_role_to_priv as t1
			where t1.role_name =  'role:user' 
			;
		if not found then
			if l_debug_on then
				insert into t_output ( msg ) values ( 'Failed to get the privilages for the user' );
			end if;
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to get privilages for the user.","code":"0012","location":"001.tables.m4.sql 1971"}';
			l_privs = '';
		end if;
		if l_debug_on then
			insert into t_output ( msg ) values ( 'calculate l_privs ->'||l_privs||'<-');
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
		) returning user_id into l_user_id  ;

		insert into q_qr_user_role ( user_id, role_id ) 
			select l_user_id, t1.role_id 
			from q_qr_role as t1
			where t1.role_name =  'role:user' 
			;

		insert into q_qr_auth_security_log ( user_id, activity, location ) values ( l_user_id, 'User Registered', 'File:001.tables.m4.sql Line No:2015');

		-- Generate OTP passwords - 20 of them.
		l_otp_str = '[';
		l_otp_com = '';
		for ii in 1..20 loop
			l_tmp = uuid_generate_v4();
			l_tmp = substr(l_tmp,0,7) || substr(l_tmp,10,2);
			-- insert into q_qr_one_time_password ( user_id, otp_hash ) values ( l_user_id, crypt(l_tmp, gen_salt('bf') ) );
			insert into q_qr_one_time_password ( user_id, otp_hmac ) values ( l_user_id, q_auth_v1_hmac_encode ( l_tmp, p_hmac_password ) );
			l_otp_str = l_otp_str || l_otp_com || to_json(l_tmp);
			l_otp_com = ',';
		end loop;
		l_otp_str = l_otp_str || ']';
		if l_debug_on then
			insert into t_output ( msg ) values ( '->'||l_otp_str||'<-');
		end if;

	end if;

	if not l_fail then

		l_tmp_token = uuid_generate_v4();
		insert into q_qr_tmp_token ( user_id, token, expires ) values ( l_user_id, l_tmp_token, current_timestamp + interval '1 day' );

		l_data = '{"status":"success"'
			||', "user_id":' 			||coalesce(to_json(l_user_id)::text,'""')
			||', "email_verify_token":' ||coalesce(to_json(l_email_verify_token)::text,'""')
			||', "require_2fa":' 		||coalesce(to_json('y'::text)::text,'""')
			||', "tmp_token":'   		||coalesce(to_json(l_tmp_token)::text,'""')
			||', "secret_2fa":'			||coalesce(to_json(l_secret_2fa)::text,'""')
			||', "otp":' 				||l_otp_str
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
create or replace function q_auth_v1_sip_register ( p_email varchar, p_validator varchar, p_hmac_password varchar, p_first_name varchar, p_last_name varchar, p_userdata_password varchar, p_secret varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_junk					text;
	l_fail					bool;
	l_user_id				int;
	l_bad_user_id			int;
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
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_email_verify_token = uuid_generate_v4();

	-- l_tmp = uuid_generate_v4()::text;
	-- l_secret_2fa = substr(l_tmp,0,7) || substr(l_tmp,10,4);
	l_secret_2fa = p_secret;

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_register<- 001.tables.m4.sql 2104' );
		insert into t_output ( msg ) values ( '  p_email ->'||p_email||'<-');
		insert into t_output ( msg ) values ( '  p_validator ->'||p_validator||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||p_hmac_password||'<-');
		insert into t_output ( msg ) values ( '  p_first_name ->'||p_first_name||'<-');
		insert into t_output ( msg ) values ( '  p_last_name ->'||p_last_name||'<-');
		insert into t_output ( msg ) values ( '  p_userdata_password ->'||p_userdata_password||'<-');
		insert into t_output ( msg ) values ( '  p_secret ->'||p_secret||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	-- Cleanup any users that have expired tokens.
	delete from q_qr_users
		where email_verify_expire < current_timestamp - interval '30 days'
		  and email_validated = 'n'
		;
	-- Cleanup any users that have expired saved state
	delete from q_qr_saved_state
		where expires < current_timestamp
		;

	-- Cleanup old tmp tokens.
	delete from q_qr_tmp_token 
		where expires < current_timestamp
		;

	-- If user has hever logged in and is attempting to register the user again - then delete old user - must have same email.
	-- PERFORM * FROM foo WHERE x = 'abc' AND y = 'xyz';
	-- IF FOUND THEN
	-- 	....
	-- END IF;
	-- , login_success = login_success + 1
	select q_auth_v1_delete_user ( user_id )
		into l_junk
		from q_qr_users as t1
		where t1.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
		  and t1.login_success = 0
		;
	select user_id
		into l_bad_user_id
		from q_qr_users as t1
		where t1.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
		;
	if found then
		l_fail = true;
		l_data = '{"status":"error","msg":"Account already exists.  Please login or recover password.","code":"1011","location":"001.tables.m4.sql 2149"}';
		-- insert into q_qr_auth_security_log ( user_id, activity, location ) values ( l_bad_user_id, 'User Attempt to Re-Register Same Accont', 'File:001.tables.m4.sql Line No:2150');
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_bad_user_id, 'User Attempt to Re-Register Same Account.', '1011', 'File:001.tables.m4.sql Line No:2151');
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

		select json_agg(t1.priv_name)::text
			into l_privs
			from q_qr_role_to_priv as t1
			where t1.role_name =  'role:user' 
			;
		if not found then
			if l_debug_on then
				insert into t_output ( msg ) values ( 'Failed to get the privilages for the user' );
			end if;
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to get privilages for the user.","code":"1012","location":"001.tables.m4.sql 2174"}';
			l_privs = '';
		end if;
		if l_debug_on then
			insert into t_output ( msg ) values ( 'calculate l_privs ->'||l_privs||'<-');
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
		) returning user_id into l_user_id  ;

		insert into q_qr_user_role ( user_id, role_id ) 
			select l_user_id, t1.role_id 
			from q_qr_role as t1
			where t1.role_name =  'role:user' 
			;

		insert into q_qr_auth_security_log ( user_id, activity, location ) values ( l_user_id, 'User Registered', 'File:001.tables.m4.sql Line No:2216');

		-- Generate OTP passwords - 20 of them.
		l_otp_str = '[';
		l_otp_com = '';
		for ii in 1..20 loop
			l_tmp = uuid_generate_v4();
			l_tmp = substr(l_tmp,0,7) || substr(l_tmp,10,2);
			-- insert into q_qr_one_time_password ( user_id, otp_hash ) values ( l_user_id, crypt(l_tmp, gen_salt('bf') ) );
			insert into q_qr_one_time_password ( user_id, otp_hmac ) values ( l_user_id, q_auth_v1_hmac_encode ( l_tmp, p_hmac_password ) );
			l_otp_str = l_otp_str || l_otp_com || to_json(l_tmp);
			l_otp_com = ',';
		end loop;
		l_otp_str = l_otp_str || ']';
		if l_debug_on then
			insert into t_output ( msg ) values ( '->'||l_otp_str||'<-');
		end if;

	end if;

	if not l_fail then

		l_tmp_token = uuid_generate_v4();
		insert into q_qr_tmp_token ( user_id, token, expires ) values ( l_user_id, l_tmp_token, current_timestamp + interval '1 day' );

		l_data = '{"status":"success"'
			||', "user_id":' 			||coalesce(to_json(l_user_id)::text,'""')
			||', "email_verify_token":' ||coalesce(to_json(l_email_verify_token)::text,'""')
			||', "require_2fa":' 		||coalesce(to_json('y'::text)::text,'""')
			||', "tmp_token":'   		||coalesce(to_json(l_tmp_token)::text,'""')
			||', "secret_2fa":' 			||coalesce(to_json(l_secret_2fa)::text,'""')
			||', "otp":' 				||l_otp_str
			||'}';

		if l_debug_on then
			insert into t_output ( msg ) values ( ' l_data= '||l_data );
		end if;

	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;






-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
create or replace function q_auth_v1_register_resend_email_link ( p_email varchar, p_old_email_verify_token varchar, p_hmac_password varchar, p_userdata_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_junk					text;
	l_fail					bool;
	l_user_id				int;
	l_tmp_token				uuid;
	l_debug_on 				bool;
	l_email_verify_token	uuid;
	v_cnt 					int;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_email_verify_token = uuid_generate_v4();


	-- Cleanup any users that have expired tokens.
	delete from q_qr_users
		where email_verify_expire < current_timestamp - interval '30 days'
		  and email_validated = 'n'
		;
	-- Cleanup any users that have expired saved state
	delete from q_qr_saved_state
		where expires < current_timestamp
		;

	-- Cleanup old tmp tokens.
	delete from q_qr_tmp_token 
		where expires < current_timestamp
		;

	select t1.user_id
		into l_user_id
		from q_qr_users as t1
		where t1.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
		  and email_verify_token = p_old_email_verify_token 
		;
	if not found then
		if l_debug_on then
			insert into t_output ( msg ) values ( 'Failed to find the user' );
		end if;
		l_fail = true;
		l_data = '{"status":"error","msg":"Unable to find the user.","code":"0013","location":"001.tables.m4.sql 2317"}';
	end if;

	update q_qr_users as t1
		set
			  t1.email_verify_token = l_email_verify_token
			, t1.email_verify_expire = current_timestamp + interval '1 day'
			, t1.email_validated = 'n'
		where t1.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
		  and email_verify_token = p_old_email_verify_token 
		;
	GET DIAGNOSTICS v_cnt = ROW_COUNT;
	if v_cnt != 1 then
		l_fail = true;
		l_data = '{"status":"error","msg":"Invalid User/Email or Account not valid","code":"0014","location":"001.tables.m4.sql 2331"}'; 
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid User or Account not valid', '0014', 'File:001.tables.m4.sql Line No:2332');
	end if;

	if not l_fail then

		l_tmp_token = uuid_generate_v4();
		insert into q_qr_tmp_token ( user_id, token, expires ) values ( l_user_id, l_tmp_token, current_timestamp + interval '1 day' );

		l_data = '{"status":"success"'
			||', "email_verify_token":' ||coalesce(to_json(l_email_verify_token)::text,'""')
			||', "require_2fa":' 		||coalesce(to_json('y'::text)::text,'""')
			||', "tmp_token":'   		||coalesce(to_json(l_tmp_token)::text,'""')
			||'}';

		if l_debug_on then
			insert into t_output ( msg ) values ( ' l_data= '||l_data );
		end if;

	end if;
END;
$$ LANGUAGE plpgsql;










-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
create or replace function q_auth_v1_delete_user ( p_user_id int )
	returns text
	as $$
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022

	delete from q_qr_auth_security_log where user_id = p_user_id;
	delete from q_qr_auth_tokens where user_id = p_user_id;
	delete from q_qr_one_time_password where user_id = p_user_id;
	delete from q_qr_user_role where user_id = p_user_id;
	delete from q_qr_auth_log where user_id = p_user_id;
	delete from q_qr_tmp_token where user_id = p_user_id;

	delete from q_qr_auth_security_log where user_id = ( select user_id from q_qr_users where parent_user_id = p_user_id );
	delete from q_qr_auth_tokens where user_id = ( select user_id from q_qr_users where parent_user_id = p_user_id );
	delete from q_qr_one_time_password where user_id = ( select user_id from q_qr_users where parent_user_id = p_user_id );
	delete from q_qr_user_role where user_id = ( select user_id from q_qr_users where parent_user_id = p_user_id );
	delete from q_qr_auth_log where user_id = ( select user_id from q_qr_users where parent_user_id = p_user_id );
	delete from q_qr_tmp_token where user_id = ( select user_id from q_qr_users where parent_user_id = p_user_id );
	delete from q_qr_users where parent_user_id = p_user_id;	-- delete child accounts

	delete from q_qr_users where user_id = p_user_id;

	RETURN ( 'User Deleted '||p_user_id::text );
END;
$$ LANGUAGE plpgsql;


-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
drop function q_auth_v1_change_password ( p_un varchar, p_pw varchar, p_new_pw varchar, p_hmac_password varchar, p_userdata_password varchar );

-- 2. q_auth_v1_change_password
create or replace function q_auth_v1_change_password ( p_email varchar, p_pw varchar, p_new_pw varchar, p_hmac_password varchar, p_userdata_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_tmp					text;
	v_cnt					int;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if not l_fail then
		if p_pw = p_new_pw then
			l_fail = true;
			l_data = '{"status":"error","msg":"Old and New Password should be different","code":"0025","location":"001.tables.m4.sql 2418"}'; 
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Old and New Password should be different', '0025', 'File:001.tables.m4.sql Line No:2419');
		end if;
	end if;

	if not l_fail then
		-- xyzzy-Slow!! - better to do select count - and verify where before update.
		update q_qr_users as t1
			set 
				  password_hash = crypt(p_new_pw, gen_salt('bf') )
			where t1.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
		  	  and ( t1.start_date < current_timestamp or t1.start_date is null )
		      and ( t1.end_date > current_timestamp or t1.end_date is null )
			  and (
					(
							t1.account_type = 'login'
						and t1.password_hash = crypt(p_pw, password_hash)
						and t1.parent_user_id is null
					    and t1.email_validated = 'y'
					    and t1.setup_complete_2fa = 'y'
					)  or (
							t1.account_type = 'un/pw' 
						and t1.password_hash = crypt(p_pw, password_hash)
						and t1.parent_user_id is not null
						and exists (
							select 'found'
							from q_qr_users as t2
							where t2.user_id = t1.parent_user_id
							  and ( t1.start_date < current_timestamp or t1.start_date is null )
							  and ( t1.end_date > current_timestamp or t1.end_date is null )
							  and t2.email_validated = 'y'
					          and t2.setup_complete_2fa = 'y'
						)
					)  or (
							t1.account_type = 'token'
						and t1.parent_user_id is not null
						and exists (
							select 'found'
							from q_qr_users as t3
							where t3.user_id = t1.parent_user_id
							  and ( t1.start_date < current_timestamp or t1.start_date is null )
							  and ( t1.end_date > current_timestamp or t1.end_date is null )
							  and t3.email_validated = 'y'
					          and t3.setup_complete_2fa = 'y'
						)
					)
				)
			;
		-- check # of rows.
		GET DIAGNOSTICS v_cnt = ROW_COUNT;
		if v_cnt != 1 then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or not email validated","code":"0015","location":"001.tables.m4.sql 2470"}'; 
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or not email validated', '0015', 'File:001.tables.m4.sql Line No:2471');
		end if;
	end if;

	-- Delete all the id.json rows for this user - every marked device will nedd to 2fa after this request.
	-- Select to get l_user_id for email.  If it is not found above then this may not be a fully setup user.
	-- The l_user_id is used below in a delete to prevet marking of devices as having been seen.
	delete from q_qr_manifest_version 
		where user_id = (
			select user_id
			from q_qr_users as t1
			where t1.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
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
drop function q_auth_v1_change_password_admin ( p_admin_user_id int, p_un varchar, p_new_pw varchar, p_hmac_password varchar, p_userdata_password varchar );

-- 	A. q_auth_v1_change_password_admin -- xyzzy400 (check privs)
-- From 2. q_auth_v1_change_password
create or replace function q_auth_v1_change_password_admin ( p_admin_user_id int, p_email varchar, p_new_pw varchar, p_hmac_password varchar, p_userdata_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_tmp					text;
	v_cnt					int;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if not q_amdin_HasPriv ( p_admin_user_id, 'May Change Other Password' ) then
		l_fail = true;
		l_data = '{"status":"error","msg":"Not authoriazed to change others passwrod","code":"0016","location":"001.tables.m4.sql 2524"}'; 
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Not authorized to change others password', '0016', 'File:001.tables.m4.sql Line No:2525');
	end if;

	if not l_fail then
		-- Xyzzy - better to do select count - and verify where before update.
		update q_qr_users as t1
			set 
				  password_hash = crypt(p_new_pw, gen_salt('bf') )
			where t1.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
			;
		-- check # of rows.
		GET DIAGNOSTICS v_cnt = ROW_COUNT;
		if v_cnt != 1 then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or not email validated","code":"0017","location":"001.tables.m4.sql 2539"}'; 
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or not email validated', '0017', 'File:001.tables.m4.sql Line No:2540');
		end if;
	end if;

	-- Delete all the id.json rows for this user - every marked device will nedd to 2fa after this request.
	-- Select to get l_user_id for email.  If it is not found above then this may not be a fully setup user.
	-- The l_user_id is used below in a delete to prevet marking of devices as having been seen.
	delete from q_qr_manifest_version 
		where user_id = (
			select user_id
			from q_qr_users as t1
			where t1.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
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

create or replace function q_auth_v1_login ( p_email varchar, p_pw varchar, p_am_i_known varchar, p_hmac_password varchar, p_userdata_password varchar )
	returns text
	as $$
DECLARE
	l_2fa_id				uuid;
	l_data					text;
	l_fail					bool;
  	l_user_id 				int;
	l_email_validated		varchar(1);
	l_start_date			timestamp;
	l_end_date				timestamp;
	l_require_2fa 			varchar(1);
	l_secret_2fa 			varchar(20);
	l_account_type			varchar(20);
	l_privileges			text;
	l_first_name			text;
	l_last_name				text;
	l_tmp					text;
	l_auth_token			uuid;
	l_tmp_token				uuid;	-- when 2fa is on this is returnd as not null (UUID)
	l_debug_on 				bool;
	l_failed_login_timeout 	timestamp;
	l_login_failures 		int;
	l_one_time_password_id 	int;
	v_cnt 					int;
	l_validation_method		varchar(10);
	l_manifet_id			uuid;
	l_email_hmac            text;
	l_otp_hmac              text;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_login<- 001.tables.m4.sql 2612' );
		insert into t_output ( msg ) values ( '  p_email ->'||p_email||'<-');
		insert into t_output ( msg ) values ( '  p_pw ->'||p_pw||'<-');
		insert into t_output ( msg ) values ( '  p_am_i_known ->'||p_am_i_known||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||p_hmac_password||'<-');
		insert into t_output ( msg ) values ( '  p_userdata_password ->'||p_userdata_password||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	-- Cleanup old debug t_outupt data.
	delete from t_output
		where created < current_timestamp - interval '1 hour'
		;

	-- Cleanup old auth tokens.
	delete from q_qr_auth_tokens 
		where expires < current_timestamp
		;

	-- Cleanup old tmp tokens.
	delete from q_qr_tmp_token 
		where expires < current_timestamp
		;

	-- validation_method		varchar(10) default 'un/pw' not null check ( validation_method in ( 'un/pw', 'sip', 'srp6a', 'hw-key' ) ),
	if not l_fail then
		l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );
		with email_user as (
			select
				  user_id
				, email_validated
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
			from q_qr_users 
			where email_hmac = l_email_hmac
		)
		select
				  user_id
				, email_validated
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
			into
				  l_user_id
				, l_email_validated
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
					and parent_user_id is not null
				)
		;
		
		if not found then -- BBB
			select
				  user_id
				, email_validated
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
			into l_user_id
				, l_email_validated
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
			from q_qr_users
			where email_hmac = l_email_hmac
			;
			if not found then
				l_fail = true;
				l_data = '{"status":"error","msg":"Invalid Username or Password","code":"0055","location":"001.tables.m4.sql 2731"}'; -- return no such account or password
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Password', '0055', 'File:001.tables.m4.sql Line No:2732');
			end if;

			if not l_fail then -- AAA

				-- ------------------------------------------------------------------------------------------
				-- Place to check if password is an OTP password and handle that
				-- ------------------------------------------------------------------------------------------

	-- should be an _hmac for otp - not a crypt - need to access this quickley

				l_otp_hmac = q_auth_v1_hmac_encode ( l_tmp, p_hmac_password );

				select
						t2.one_time_password_id 	
					into
						l_one_time_password_id 	
					from q_qr_one_time_password as t2 
					where t2.user_id = l_user_id
					  and t2.otp_hmac = l_otp_hmac
				;

				if found then
					delete from q_qr_one_time_password where one_time_password_id = l_one_time_password_id;
					insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Used Ont Time Password', '0011', 'File:001.tables.m4.sql Line No:2756');
				else 
					l_fail = true;
					l_data = '{"status":"error","msg":"Invalid Username or Password","code":"0018","location":"001.tables.m4.sql 2759"}'; -- return no such account or password
					insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Password', '0018', 'File:001.tables.m4.sql Line No:2760');
				end if;

			end if; -- AAA

		end if; -- BBB

	end if;

	if l_debug_on then
		insert into t_output ( msg ) values ( '->'||p_userdata_password||'<-');
		insert into t_output ( msg ) values ( 'l_first_name = ->'||l_first_name||'<-');
		insert into t_output ( msg ) values ( 'l_last_name = ->'||l_last_name||'<-');
		insert into t_output ( msg ) values ( 'l_validation_method = ->'||l_validation_method||'<-');
	end if;

	if not l_fail then
		if not q_amdin_HasPriv ( l_user_id, 'May Login' ) then
			if l_debug_on then
				insert into t_output ( msg ) values ( 'failed to find priv ''May Login'' ->'||l_user_id||'<-');
			end if;
			l_fail = true;
			l_data = '{"status":"error","msg":"Account lacks ''May Login'' privilege","code":"0019","location":"001.tables.m4.sql 2782"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account lacks ''May Login'' privilege', '0019', 'File:001.tables.m4.sql Line No:2783');
		end if;
	end if;

	if not l_fail then
		if l_validation_method != 'un/pw' then
			l_fail = true;
			l_data = '{"status":"error","msg":"Account is not a un/pw authetication method","code":"0027","location":"001.tables.m4.sql 2790"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account is not a un/pw autetication method', '0027', 'File:001.tables.m4.sql Line No:2791');
		end if;
	end if;

	if not l_fail then
		if l_email_validated = 'n' then
			l_fail = true;
			l_data = '{"status":"error","msg":"Account has not not been validated","code":"0020","location":"001.tables.m4.sql 2798"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has not been validated', '0020', 'File:001.tables.m4.sql Line No:2799');
		end if;
	end if;
	if not l_fail then
		if l_start_date is not null then
			if l_start_date > current_timestamp then
				l_fail = true;
				l_data = '{"status":"error","msg":"Account has a start date that has not been reached","code":"0028","location":"001.tables.m4.sql 2806"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has start date that has not bee reached', '0028', 'File:001.tables.m4.sql Line No:2807');
			end if;
		end if;
	end if;
	if not l_fail then
		if l_end_date is not null then
			if l_end_date <= current_timestamp then
				l_fail = true;
				l_data = '{"status":"error","msg":"Account has a end date that has been reached","code":"0029","location":"001.tables.m4.sql 2815"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has ned date that has bee reached', '0029', 'File:001.tables.m4.sql Line No:2816');
			end if;
		end if;
	end if;

	if not l_fail then
		l_auth_token = NULL;
		if l_require_2fa = 'y' and p_am_i_known is not null then
			if p_am_i_known <> '' then
				-- id.json - check to see if user has been seen before on this device.
				select
						  t1.id			
					into
						  l_manifet_id
					from q_qr_manifest_version as t1
					where t1.id = p_am_i_known::uuid
					  and t1.user_id = l_user_id
				;
				if not found then
					if l_debug_on then
						insert into t_output ( msg ) values ( ' etag not found ' );
					end if;
				else
					update q_qr_manifest_version as t1
						set updated = current_timestamp 
						where t1.id = l_manifet_id
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
				insert into q_qr_auth_tokens ( token, user_id ) values ( l_auth_token, l_user_id );
			EXCEPTION WHEN unique_violation THEN
				l_fail = true;
				l_data = '{"status":"error","msg":"Unable to create user/auth-token.","code":"0030","location":"001.tables.m4.sql 2857"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to crate user/auth-token.', '0030', 'File:001.tables.m4.sql Line No:2858');
			END;
		end if;
	end if;
	if not l_fail then
		if l_login_failures >= 6 and l_failed_login_timeout >= current_timestamp then
			l_fail = true;
			l_data = '{"status":"error","msg":"Too many failed login attempts - please wait 1 minute.","code":"0031","location":"001.tables.m4.sql 2865"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Too many failed login attempts - please wait 1 minute.', '0031', 'File:001.tables.m4.sql Line No:2866');
			update q_qr_users
				set failed_login_timeout = current_timestamp + interval '1 minute'
				where user_id = l_user_id
				  and failed_login_timeout is null
				;
		end if;
	end if;

	if not l_fail then
		select json_agg(t1.priv_name)::text
			into l_privileges
			from q_qr_user_to_priv as t1
			where t1.user_id = l_user_id
			;

		if not found then
			if l_debug_on then
				insert into t_output ( msg ) values ( 'Failed to get the privilages for the user' );
			end if;
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to get privilages for the user.","code":"0032","location":"001.tables.m4.sql 2887"}';
			l_privileges = '';
		end if;
	end if;

	if not l_fail then

		if l_debug_on then
			insert into t_output ( msg ) values ( 'function ->q_quth_v1_login<-..... Continued ...  001.tables.m4.sql 2895' );
			insert into t_output ( msg ) values ( 'calculate l_user_id ->'||coalesce(to_json(l_user_id)::text,'""')||'<-');
			insert into t_output ( msg ) values ( 'calculate l_privs ->'||coalesce(to_json(l_privileges)::text,'""')||'<-');
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
		l_tmp_token = uuid_generate_v4();
		insert into q_qr_tmp_token ( user_id, token ) values ( l_user_id, l_tmp_token );
		if l_require_2fa = 'y' then
			l_auth_token = NULL;
			insert into q_qr_auth_security_log ( user_id, activity, location ) values ( l_user_id, 'Login - Part 1 Success: '||l_tmp_token::text, 'File:001.tables.m4.sql Line No:2912');
		else
			insert into q_qr_auth_security_log ( user_id, activity, location ) values ( l_user_id, 'Successful Login', 'File:001.tables.m4.sql Line No:2914');
		end if;
		l_data = '{"status":"success"'
			||', "user_id":'     ||coalesce(to_json(l_user_id)::text,'""')
			||', "auth_token":'  ||coalesce(to_json(l_auth_token)::text,'""')
			||', "tmp_token":'   ||coalesce(to_json(l_tmp_token)::text,'""')
			||', "require_2fa":' ||coalesce(to_json(l_require_2fa)::text,'""')
			||', "secret_2fa":'  ||coalesce(to_json(l_secret_2fa)::text,'""')
			||', "account_type":'||coalesce(to_json(l_account_type)::text,'""')
			||', "privileges":'  ||coalesce(to_json(l_privileges)::text,'""')
			||', "first_name":'  ||coalesce(to_json(l_first_name)::text,'""')
			||', "last_name":'   ||coalesce(to_json(l_last_name)::text,'""')
			||'}';
	else 
		if l_user_id is not null then
			insert into q_qr_auth_security_log ( user_id, activity, location ) values ( l_user_id, 'Login Failure', 'File:001.tables.m4.sql Line No:2929');
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
-- 3. q_auth_v1_regen_otp
create or replace function q_auth_v1_regen_otp ( p_email varchar, p_pw varchar, p_hmac_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_tmp					text;
	l_fail					bool;
	l_debug_on 				bool;
	l_user_id				int;
	ii						int;
	l_otp_str				text;
	l_otp_com				text;
	v_cnt 					int;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if not l_fail then
		select
			  user_id
		into
			  l_user_id
		from q_qr_users as t1
		where t1.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
			and	account_type = 'login'
			and password_hash = crypt(p_pw, password_hash)
			and parent_user_id is null
		;
		
		if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Password/attempt to create new OTP","code":"0034","location":"001.tables.m4.sql 3004"}'; 
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Password/attempt to create new OTP', '0034', 'File:001.tables.m4.sql Line No:3005');
		end if;

	end if;

	if not l_fail then

		delete from q_qr_one_time_password where user_id = l_user_id;

		-- Generate OTP passwords - 20 of them.
		l_otp_str = '[';
		l_otp_com = '';
		for ii in 1..20 loop
			l_tmp = uuid_generate_v4();
			l_tmp = substr(l_tmp,0,7) || substr(l_tmp,10,2);
			-- insert into q_qr_one_time_password ( user_id, otp_hash ) values ( l_user_id, crypt(l_tmp, gen_salt('bf') ) );
			insert into q_qr_one_time_password ( user_id, otp_hmac ) values ( l_user_id, q_auth_v1_hmac_encode ( l_tmp, p_hmac_password ) );
			l_otp_str = l_otp_str || l_otp_com || to_json(l_tmp);
			l_otp_com = ',';
			-- insert into t_output ( msg ) values ( '->'||l_otp_str||'<-');
		end loop;
		l_otp_str = l_otp_str || ']';

	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "user_id":' ||coalesce(to_json(l_user_id)::text,'""')
			||', "otp":' ||l_otp_str
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;












-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

create or replace function q_auth_v1_register_un_pw ( p_parent_user_id int, p_email varchar, p_hmac_password varchar,  p_userdata_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_user_id				int;
	l_bad_user_id			int;
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
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022

	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_register_un_pw<- 001.tables.m4.sql 3086' );
		insert into t_output ( msg ) values ( '  p_parent_user_id ->'||p_parent_user_id||'<-');
		insert into t_output ( msg ) values ( '  p_email ->'||p_email||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||p_hmac_password||'<-');
		insert into t_output ( msg ) values ( '  p_userdata_password ->'||p_userdata_password||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	l_pw = encode(digest(uuid_generate_v4()::text, 'sha256'), 'base64');

	-- Cleanup any users that have expired tokens.
	delete from q_qr_users
		where email_verify_expire < current_timestamp - interval '30 days'
		  and email_validated = 'n'
		;

	-- Cleanup old auth tokens.
	delete from q_qr_auth_tokens 
		where expires < current_timestamp
		;

	if not l_fail then
		select
			  user_id
			, email_validated
			, start_date
			, end_date
		    , pgp_sym_decrypt(first_name_enc,p_userdata_password)::text
		    , pgp_sym_decrypt(last_name_enc,p_userdata_password)::text
			, failed_login_timeout 	
			, login_failures 		
		into
			  l_user_id
			, l_email_validated
			, l_start_date
			, l_end_date
			, l_first_name
			, l_last_name
			, l_failed_login_timeout 	
			, l_login_failures 	
		from q_qr_users
		where user_id = p_parent_user_id
			and account_type = 'login'
		;
		if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Password","code":"0035","location":"001.tables.m4.sql 3132"}'; -- return no such account or password
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Password', '0035', 'File:001.tables.m4.sql Line No:3133');
		end if;
	end if;

	-- xyzzy Privs

	if l_debug_on then
		insert into t_output ( msg ) values ( '->'||p_userdata_password||'<-');
		insert into t_output ( msg ) values ( 'l_first_name = ->'||l_first_name||'<-');
		insert into t_output ( msg ) values ( 'l_last_name = ->'||l_last_name||'<-');
	end if;

	if not l_fail then
		if l_email_validated = 'n' then
			l_fail = true;
			l_data = '{"status":"error","msg":"Account has not not been validated","code":"0036","location":"001.tables.m4.sql 3148"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has not been validated', '0036', 'File:001.tables.m4.sql Line No:3149');
		end if;
	end if;
	if not l_fail then
		if l_start_date is not null then
			if l_start_date > current_timestamp then
				l_fail = true;
				l_data = '{"status":"error","msg":"Account has a start date that has not been reached","code":"0036","location":"001.tables.m4.sql 3156"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has start date that has not bee reached', '0036', 'File:001.tables.m4.sql Line No:3157');
			end if;
		end if;
	end if;
	if not l_fail then
		if l_end_date is not null then
			if l_end_date <= current_timestamp then
				l_fail = true;
				l_data = '{"status":"error","msg":"Account has a end date that has been reached","code":"0037","location":"001.tables.m4.sql 3165"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has ned date that has bee reached', '0037', 'File:001.tables.m4.sql Line No:3166');
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
				l_data = '{"status":"error","msg":"Unable to create user/auth-token.","code":"0038","location":"001.tables.m4.sql 3179"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to crate user/auth-token.', '0038', 'File:001.tables.m4.sql Line No:3180');
			END;
		end if;
	end if;
	if not l_fail then
		if l_login_failures > 6 or l_failed_login_timeout >= current_timestamp then
			l_fail = true;
			l_data = '{"status":"error","msg":"Too many failed login attempts - please wait 1 minute.","code":"0039","location":"001.tables.m4.sql 3187"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Too many failed login attempts - please wait 1 minute.', '0039', 'File:001.tables.m4.sql Line No:3188');
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
		) VALUES (
			  q_auth_v1_hmac_encode ( p_email, p_hmac_password )
			, crypt(l_pw, gen_salt('bf') )
		    , pgp_sym_encrypt(l_first_name,p_userdata_password)
		    , pgp_sym_encrypt(l_last_name,p_userdata_password)
			, p_parent_user_id
			, 'un/pw'
			, 'y'
		) returning user_id into l_user_id  ;

		insert into q_qr_user_role ( user_id, role_id ) 
			select l_user_id, t1.role_id 
			from q_qr_role as t1
			where t1.role_name =  'role:user' 
			;

		insert into q_qr_auth_security_log ( user_id, activity, location ) values ( l_user_id, 'User Registered', 'File:001.tables.m4.sql Line No:3222');
	end if;

	if not l_fail then
		l_tmp_token = uuid_generate_v4();
		insert into q_qr_tmp_token ( user_id, token ) values ( l_user_id, l_tmp_token );
		l_data = '{"status":"success"'
			||', "user_id":' 	||coalesce(to_json(l_user_id)::text,'""')
			||', "tmp_token":'  ||coalesce(to_json(l_tmp_token)::text,'""')
			||', "pw":' 		||coalesce(to_json(l_pw)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;







-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
create or replace function q_auth_v1_register_token ( p_parent_user_id int,  p_hmac_password varchar,  p_userdata_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_user_id				int;
	l_bad_user_id			int;
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
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022

	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_register_token<- 001.tables.m4.sql 3279' );
		insert into t_output ( msg ) values ( '  p_parent_user_id ->'||p_parent_user_id||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||p_hmac_password||'<-');
		insert into t_output ( msg ) values ( '  p_userdata_password ->'||p_userdata_password||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	l_un = encode(digest(uuid_generate_v4()::text, 'sha256'), 'base64');
	l_pw = encode(digest(uuid_generate_v4()::text, 'sha256'), 'base64');

	-- Cleanup any users that have expired tokens.
	delete from q_qr_users
		where email_verify_expire < current_timestamp - interval '30 days'
		  and email_validated = 'n'
		;

	-- Cleanup old auth tokens.
	delete from q_qr_auth_tokens 
		where expires < current_timestamp
		;

	if not l_fail then
		select
			  user_id
			, email_validated
			, start_date
			, end_date
		    , pgp_sym_decrypt(first_name_enc,p_userdata_password)::text
		    , pgp_sym_decrypt(last_name_enc,p_userdata_password)::text
			, failed_login_timeout 	
			, login_failures 		
		into
			  l_user_id
			, l_email_validated
			, l_start_date
			, l_end_date
			, l_first_name
			, l_last_name
			, l_failed_login_timeout 	
			, l_login_failures 	
		from q_qr_users
		where user_id = p_parent_user_id
			and account_type = 'login'
		;
		if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Password","code":"0040","location":"001.tables.m4.sql 3325"}'; -- return no such account or password
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Password', '0040', 'File:001.tables.m4.sql Line No:3326');
		end if;
	end if;

	-- xyzzy Privs

	if l_debug_on then
		insert into t_output ( msg ) values ( '->'||p_userdata_password||'<-');
		insert into t_output ( msg ) values ( 'l_first_name = ->'||l_first_name||'<-');
		insert into t_output ( msg ) values ( 'l_last_name = ->'||l_last_name||'<-');
	end if;

	if not l_fail then
		if l_email_validated = 'n' then
			l_fail = true;
			l_data = '{"status":"error","msg":"Account has not not been validated","code":"0041","location":"001.tables.m4.sql 3341"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has not been validated', '0041', 'File:001.tables.m4.sql Line No:3342');
		end if;
	end if;
	if not l_fail then
		if l_start_date is not null then
			if l_start_date > current_timestamp then
				l_fail = true;
				l_data = '{"status":"error","msg":"Account has a start date that has not been reached","code":"0043","location":"001.tables.m4.sql 3349"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has start date that has not bee reached', '0043', 'File:001.tables.m4.sql Line No:3350');
			end if;
		end if;
	end if;
	if not l_fail then
		if l_end_date is not null then
			if l_end_date <= current_timestamp then
				l_fail = true;
				l_data = '{"status":"error","msg":"Account has a end date that has been reached","code":"0044","location":"001.tables.m4.sql 3358"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has ned date that has bee reached', '0044', 'File:001.tables.m4.sql Line No:3359');
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
				l_data = '{"status":"error","msg":"Unable to create user/auth-token.","code":"0045","location":"001.tables.m4.sql 3372"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to crate user/auth-token.', '0045', 'File:001.tables.m4.sql Line No:3373');
			END;
		end if;
	end if;
	if not l_fail then
		if l_login_failures > 6 or l_failed_login_timeout >= current_timestamp then
			l_fail = true;
			l_data = '{"status":"error","msg":"Too many failed login attempts - please wait 1 minute.","code":"0046","location":"001.tables.m4.sql 3380"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Too many failed login attempts - please wait 1 minute.', '0046', 'File:001.tables.m4.sql Line No:3381');
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
		) VALUES (
			  q_auth_v1_hmac_encode ( p_email, p_hmac_password )
			, crypt(l_pw, gen_salt('bf') )
		    , pgp_sym_encrypt(l_first_name,p_userdata_password)
		    , pgp_sym_encrypt(l_last_name,p_userdata_password)
			, p_parent_user_id
			, 'token'
			, 'y'
		) returning user_id into l_user_id  ;

		insert into q_qr_user_role ( user_id, role_id ) 
			select l_user_id, t1.role_id 
			from q_qr_role as t1
			where t1.role_name =  'role:user' 
			;

		insert into q_qr_auth_security_log ( user_id, activity, location ) values ( l_user_id, 'User Registered', 'File:001.tables.m4.sql Line No:3415');
	end if;

	if not l_fail then
		l_tmp_token = uuid_generate_v4();
		insert into q_qr_tmp_token ( user_id, token ) values ( l_user_id, l_tmp_token );
		l_data = '{"status":"success"'
			||', "user_id":' ||coalesce(to_json(l_user_id)::text,'""')
			||', "tmp_token":'   ||coalesce(to_json(l_tmp_token)::text,'""')
			||', "login_token":' ||coalesce(to_json(l_un)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;






-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- q_auth_v1_email_verify uses the token to lookup a user and confirms that the email that received the token is real.
-- 
-- Updates q_qr_users
--
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
drop function q_auth_v1_email_verify ( p_email_verify_token varchar );

create or replace function q_auth_v1_email_verify ( p_email_verify_token varchar, p_hmac_password varchar, p_userdata_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_fail					bool;
	v_cnt 					int;
	l_validated				text;
	l_email					text;
	l_debug_on 				bool;
	l_tmp_token				uuid;	-- when 2fa is on this is returnd as not null (UUID)
	l_user_id				int;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function -> q_auth_v1_email_verify (v2) <- 001.tables.m4.sql 3466' );
		insert into t_output ( msg ) values ( '  p_email_verify_token ->'||p_email_verify_token||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	select t1.user_id
		    , pgp_sym_decrypt(t1.email_enc,p_userdata_password)::text as email
		into l_user_id 
			, l_email
		from q_qr_users as t1
		where t1.email_verify_expire > current_timestamp
			and t1.email_verify_token = p_email_verify_token::uuid
		;
	if not found then
		l_fail = true;
		l_data = '{"status":"error","msg":"Unable to validate account via email.  Please register again.","code":"0058","location":"001.tables.m4.sql 3481"}'; 
	end if;
	if l_debug_on then
		insert into t_output ( msg ) values ( '  l_user_id ->'||coalesce(to_json(l_user_id)::text,'""')||'<-');
	end if;

	if not l_fail then
		update q_qr_users 
			set email_validated = 'y'
			  , email_verify_expire = null
		where email_verify_expire > current_timestamp
			and email_verify_token = p_email_verify_token::uuid
		;
		GET DIAGNOSTICS v_cnt = ROW_COUNT;
		if v_cnt != 1 then
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to validate account via email.  Please register again.","code":"0059","location":"001.tables.m4.sql 3497"}'; 
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to validate account via email..', '0059', 'File:001.tables.m4.sql Line No:3498');
			-- Cleanup any users that have expired tokens more than 30 days ago.
			delete from q_qr_users
				where email_verify_expire < current_timestamp - interval '30 days'
				  and email_validated = 'n'
				  and account_type	= 'login'
				;
		end if;
	end if;

	if not l_fail then
		l_tmp_token = uuid_generate_v4();
		insert into q_qr_tmp_token ( user_id, token ) values ( l_user_id, l_tmp_token );
		if l_debug_on then
			insert into t_output ( msg ) values ( '  l_tmp_token ->'||l_tmp_token||'<-');
		end if;
		l_data = '{"status":"success"'
			||', "email":'   	||coalesce(to_json(l_email)::text,'""')
			||', "tmp_token":'  ||coalesce(to_json(l_tmp_token)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;





-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- q_auth_v1_logout will logout a single auth_token on a particular user.  The token is deleted.
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

create or replace function q_auth_v1_logout ( p_email varchar, p_auth_token varchar, p_hmac_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_fail					bool;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	-- Cleanup any users that have expired tokens.
	delete from q_qr_users
		where email_verify_expire < current_timestamp - interval '30 days'
		  and email_validated = 'n'
		;
	-- Cleanup any users that have expired saved state
	delete from q_qr_saved_state
		where expires < current_timestamp
		;

	-- Cleanup old tmp tokens.
	delete from q_qr_tmp_token 
		where expires < current_timestamp
		;

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
drop function q_auth_v1_setup_2fa_test ( p_user_id int );

create or replace function q_auth_v1_setup_2fa_test ( p_user_id int, p_hmac_password varchar, p_userdata_password varchar )
	returns text
	as $$
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022

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

drop function q_auth_v1_validate_2fa_token ( p_email varchar, p_tmp_token varchar, p_2fa_secret varchar, p_hmac_password varchar );

create or replace function q_auth_v1_validate_2fa_token ( p_email varchar, p_tmp_token varchar, p_2fa_secret varchar, p_hmac_password varchar, p_userdata_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_user_id				int;
	l_auth_token 			uuid;
	l_privileges			text;
	l_secret_2fa 			varchar(20);
	l_debug_on 				bool;
	l_expires				text;
	l_email_validated		text;
	l_x2fa_validated		text;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';
	l_email_validated = 'n';
	l_x2fa_validated = 'n';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'In q_auth_v1_validate_2fa_token (v2)' );
		insert into t_output ( msg ) values ( '  p_email ->'||p_email||'<-');
		insert into t_output ( msg ) values ( '  p_tmp_token ->'||p_tmp_token||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||p_hmac_password||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	-- Cleanup old debug t_outupt data.
	delete from t_output
		where created < current_timestamp - interval '1 hour'
		;

	-- Cleanup old auth tokens.
	delete from q_qr_auth_tokens 
		where expires < current_timestamp
		;

	-- Cleanup old tmp tokens.
	delete from q_qr_tmp_token 
		where expires < current_timestamp
		;

	-- Expires is in 31 days - but tell the user that it is 30 days so that they have a day of grace.
	select (current_timestamp + interval '30 days')::text
		into l_expires
		;

	select t1.user_id
			, t1.secret_2fa
			, t1.email_validated	
			, t1.setup_complete_2fa 
		into l_user_id
			, l_secret_2fa
			, l_email_validated 
			, l_x2fa_validated	
		from q_qr_users as t1
			join q_qr_tmp_token as t2 on ( t1.user_id = t2.user_id )
		where t1.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
		  and t1.secret_2fa = p_2fa_secret
		  and t2.token = p_tmp_token::uuid
		;
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
			l_data = '{"status":"error","msg":"Your 2fa number has epired - please try again.","code":"0060","location":"001.tables.m4.sql 3695"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Expired 2fa number.', '0060', 'File:001.tables.m4.sql Line No:3696');
		else
			l_data = '{"status":"error","msg":"Your temporary login token has expired.  Please start your login process again.","code":"0061","location":"001.tables.m4.sql 3698"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Your temporary login token has expired.  Please start your login process again.', '0061', 'File:001.tables.m4.sql Line No:3699');
		end if;
		l_fail = true;
	end if;

	if not l_fail then
		if l_debug_on then
			insert into t_output ( msg ) values ( 'Seting the user up' );
		end if;
		update q_qr_users as t2
			set setup_complete_2fa 	= 'y'
			where t2.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
			;
		l_x2fa_validated = 'y';
		-- insert / create auth_token
		l_auth_token = uuid_generate_v4();
		BEGIN
			insert into q_qr_auth_tokens ( token, user_id ) values ( l_auth_token, l_user_id );
		EXCEPTION WHEN unique_violation THEN
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to create user/auth-token.","code":"0063","location":"001.tables.m4.sql 3719"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to create user/auth-token.', '0063', 'File:001.tables.m4.sql Line No:3720');
		END;
	end if;

	if not l_fail then
		select json_agg(t1.priv_name)::text
			into l_privileges			
			from q_qr_user_to_priv as t1
			where t1.user_id = l_user_id
			;
		if not found then
			if l_debug_on then
				insert into t_output ( msg ) values ( 'Failed to get the privilages for the user' );
			end if;
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to get privilages for the user.","code":"0064","location":"001.tables.m4.sql 3735"}';
			l_privileges = '';
		end if;
	end if;

	-- EmailConfirmed  string `json:"email_validated,omitempty"`
	if not l_fail then
		l_data = '{"status":"success"'
			||', "auth_token":'  	 ||coalesce(to_json(l_auth_token)::text,'""')
			||', "expires":'     	 ||coalesce(to_json(l_expires)::text,'""')
			||', "user_id":'     	 ||coalesce(to_json(l_user_id)::text,'""')
			||', "privileges":'  	 ||coalesce(to_json(l_privileges)::text,'""')
			||', "secret_2fa":'  	 ||coalesce(to_json(l_secret_2fa)::text,'""')
			||', "email_validated":' ||coalesce(to_json(l_email_validated)::text,'""')
			||', "x2fa_validated":'  ||coalesce(to_json(l_x2fa_validated)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;


-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
create or replace function q_auth_v1_refresh_token ( p_email varchar, p_token varchar, p_hmac_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_user_id				int;
	l_auth_token 			uuid;
	l_debug_on 				bool;
	l_expires				text;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'In q_auth_v1_refresh_token (v2)' );
		insert into t_output ( msg ) values ( '  p_email ->'||p_email||'<-');
		insert into t_output ( msg ) values ( '  p_token ->'||p_token||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||p_hmac_password||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	-- Cleanup old debug t_outupt data.
	delete from t_output
		where created < current_timestamp - interval '1 hour'
		;

	-- Cleanup old auth tokens.
	delete from q_qr_auth_tokens 
		where expires < current_timestamp
		;

	-- Cleanup old tmp tokens.
	delete from q_qr_tmp_token 
		where expires < current_timestamp
		;

	-- Expires is in 31 days - but tell the user that it is 30 days so that they have a day of grace.
	select (current_timestamp + interval '30 days')::text
		into l_expires
		;

	select user_id
		into l_user_id
		from q_qr_auth_tokens
		where token = p_token
		;
	if not found then
		l_fail = true;
		l_data = '{"status":"error","msg":"Unable to refresh auth-token.","code":"0065","location":"001.tables.m4.sql 3813"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to refresh auth-token.', '0065', 'File:001.tables.m4.sql Line No:3814');
	end if;

	if not l_fail then
		if l_debug_on then
			insert into t_output ( msg ) values ( 'Seting the user up' );
		end if;
		-- insert / create auth_token
		l_auth_token = uuid_generate_v4();
		BEGIN
			insert into q_qr_auth_tokens ( token, user_id ) values ( l_auth_token, l_user_id );
		EXCEPTION WHEN unique_violation THEN
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to create user/auth-token.","code":"0066","location":"001.tables.m4.sql 3827"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to create user/auth-token.', '0066', 'File:001.tables.m4.sql Line No:3828');
		END;
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "auth_token":'  ||coalesce(to_json(l_auth_token)::text,'""')
			||', "expires":'     ||coalesce(to_json(l_expires)::text,'""')
			||', "user_id":'     ||coalesce(to_json(l_user_id)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;


-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- stmt := "q_auth_v1_2fa_get_secret ( $1, $2 )"
create or replace function q_auth_v1_2fa_get_secret ( p_email varchar, p_hmac_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_user_id				int;
	l_secret_2fa 			varchar(20);
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	select
			  secret_2fa
			, user_id
		into
			  l_secret_2fa
			, l_user_id
		from q_qr_users as t2
		where t2.email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
		;
	if not found then
		l_fail = true;
		l_data = '{"status":"error","msg":"Invalid email.","code":"0067","location":"001.tables.m4.sql 3874"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid email number.', '0067', 'File:001.tables.m4.sql Line No:3875');
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "secret_2fa":'  ||coalesce(to_json(l_secret_2fa)::text,'""')
			||', "user_id":'  ||coalesce(to_json(l_user_id)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;



-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- stmt := "q_auth_v1_change_email_address ( $1, $2, $3, $4, $5 )"
create or replace function q_auth_v1_change_email_address ( p_old_email varchar, p_new_email varchar, p_pw varchar, p_user_id varchar, p_hmac_password varchar, p_userdata_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_user_id				int;
	l_secret_2fa 			varchar(20);
	v_cnt 					int;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: d8567842c437cda050059b0ad4e3ee9e817e5ce4 tag: v1.0.2 build_date: Tue Jul  5 19:42:43 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_user_id = p_user_id::int;

	if not l_fail then
		update q_qr_users as t1
			set 
				  email_hmac = q_auth_v1_hmac_encode ( p_new_email, p_hmac_password )
				, email_enc = pgp_sym_encrypt(p_email,p_userdata_password)
			where t1.email_hmac = q_auth_v1_hmac_encode ( p_old_email, p_hmac_password )
			  and t1.user_id = l_user_id
			  and ( t1.start_date < current_timestamp or t1.start_date is null )
			  and ( t1.end_date > current_timestamp or t1.end_date is null )
			  and (
					(
							t1.account_type = 'login'
						and t1.password_hash = crypt(p_pw, password_hash)
						and t1.parent_user_id is null
					    and t1.email_validated = 'y'
					    and t1.setup_complete_2fa = 'y'
					)  or (
							t1.account_type = 'un/pw' 
						and t1.password_hash = crypt(p_pw, password_hash)
						and t1.parent_user_id is not null
						and exists (
							select 'found'
							from q_qr_users as t2
							where t2.user_id = t1.parent_user_id
							  and ( t1.start_date < current_timestamp or t1.start_date is null )
							  and ( t1.end_date > current_timestamp or t1.end_date is null )
							  and t2.email_validated = 'y'
					          and t2.setup_complete_2fa = 'y'
						)
					)  or (
							t1.account_type = 'token'
						and t1.parent_user_id is not null
						and exists (
							select 'found'
							from q_qr_users as t3
							where t3.user_id = t1.parent_user_id
							  and ( t1.start_date < current_timestamp or t1.start_date is null )
							  and ( t1.end_date > current_timestamp or t1.end_date is null )
							  and t3.email_validated = 'y'
					          and t3.setup_complete_2fa = 'y'
						)
					)
				)
			;
		-- check # of rows.
		GET DIAGNOSTICS v_cnt = ROW_COUNT;
		if v_cnt != 1 then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or not email validated","code":"0070","location":"001.tables.m4.sql 3960"}'; 
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or not email validated', '0070', 'File:001.tables.m4.sql Line No:3961');
		end if;


	end if;

	if not l_fail then
		-- Insert into log that email changed.
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Email Addres Changed.', '0099', 'File:001.tables.m4.sql Line No:3969');
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "secret_2fa":'  ||coalesce(to_json(l_secret_2fa)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;





-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Tests
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

delete from q_qr_users cascade;
delete from t_output;

select q_auth_v1_register ( 'bob@example.com', 'bob the builder', 'my long secret password', 'Bob', 'the Builder', 'user info password', 'RRFRUD6NOPVVO2ZV' );

select * from t_output;
delete from t_output;

select * from q_qr_users;

select q_auth_v1_login ( 'bob@example.com', 'bob the builder', '181d4e23-9595-47ec-9a26-1c8313d321f9', 'my long secret password', 'user info password' ); 
-- select q_auth_v1_login ( 'bob@truckcoinswap.com', 'i-am-bob', '181d4e23-9595-47ec-9a26-1c8313d321f9', 'my long secret password', 'user info password' ) as "x";
--  {"status":"error","msg":"Account has not not been validated"}

select * from t_output;
delete from t_output;

-- create or replace function q_auth_v1_email_verify ( p_email_verify_token varchar, p_hmac_password varchar, p_userdata_password varchar )
select q_auth_v1_email_verify ( t2.email_verify_token::text , 'my long secret password', 'user info password' ) 
	from q_qr_users as t2
	where t2.email_hmac = q_auth_v1_hmac_encode ( 'bob@example.com', 'my long secret password' )
;

select * from t_output;
delete from t_output;

select q_auth_v1_login ( 'bob@example.com', 'bob the builder', '181d4e23-9595-47ec-9a26-1c8313d321f9', 'my long secret password', 'user info password' );
--                               q_auth_v1_login
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

select * from t_output;
delete from t_output;


-- check priv on user (check privs)
select 'should be ''f''';
select q_amdin_HasPriv ( 3::int, 'May X' );
select 'should be ''t''';
select q_amdin_HasPriv ( 3::int, 'May Change Password' );






drop table if exists x_tmp_values ;
create table if not exists x_tmp_values (
	name text,
	value text
);
drop table if exists x_tmp_pass_fail ;
create table if not exists x_tmp_pass_fail (
	name text
);







-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Tests - Procedure/Inline
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
DO $$
DECLARE
	p_email text;
	p_hmac_password text;
	p_userdata_password text;
	p_first_name text;
	p_last_name text;
	p_pw text;
	l_user_id int;
	l_status text;
	l_r1 text;
	l_r2 text;
	l_cnt1 int;
	l_cnt2 int;
	l_fail bool;
	l_bool bool;
	n_err int;
	l_email_verify_token text;
	l_secret_2fa text;
	v_cnt int;
	l_auth_token uuid;
	l_junk1 int;
	l_privilage text;
	l_cnt_auth_tokens int;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2017, 2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	l_fail = false;
	n_err = 0;


	-- Check Data (Privileges) ------------------------------------------------------------------------------------------
	select count(1) into l_cnt1 from q_qr_role;
	if l_cnt1 = 0 then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:4088 -- missing data in q_qr_role' );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	select count(1) into l_cnt1 from q_qr_priv;
	if l_cnt1 = 0 then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:4095 -- missing data in q_qr_priv' );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	select count(1) into l_cnt1 from q_qr_role_priv;
	if l_cnt1 = 0 then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:4102 -- missing data in q_qr_role_priv' );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	select count(1) into l_cnt1 from q_qr_user_role;
	if l_cnt1 = 0 then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:4109 -- missing data in q_qr_user_role' );
		l_fail = true;
		n_err = n_err + 1;
	end if;











	p_email = 'bob@example.com';
	p_pw = 'bob the builder';
	p_first_name = 'Bob';
	p_last_name = 'the Builder';
	p_hmac_password = 'my long secret password';	-- Using const passords in the tests will prevent this from interfering with...
	p_userdata_password = 'user info password';		-- ...any regular login accounts.




	-- Cleanup previous runs --------------------------------------------------------------------------------------------
	delete from t_output; -- Discard output from prevous runs.
	select user_id
		into l_user_id
		from q_qr_users 
		where email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password )
	;
	delete from q_qr_auth_security_log
		where user_id = l_user_id;
	delete from q_qr_auth_log
		where user_id = l_user_id;
	delete from q_qr_one_time_password 
		where user_id = l_user_id;
	delete from q_qr_auth_tokens
		where user_id = l_user_id;
	delete from q_qr_tmp_token
		where user_id = l_user_id;
	delete from q_qr_users 
		where user_id = l_user_id;




	-- test 0 -----------------------------------------------------------------------------------------------------------
	-- Test the boolean config functions.

	update q_qr_config set b_value = false, value = 'no' where name = 'config.test';
	GET DIAGNOSTICS v_cnt = ROW_COUNT;
	if v_cnt = 0 then
		insert into q_qr_config ( name, value, b_value ) values ( 'config.test', 'no', false );
	end if;

	l_bool = q_get_config_bool ( 'confg.test' );
	if l_bool = true then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:4168 -- config not working' );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	update q_qr_config set b_value = true, value = 'yes' where name = 'config.test';
	GET DIAGNOSTICS v_cnt = ROW_COUNT;
	if v_cnt != 1 then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:4176 -- config not working' );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	l_bool = q_get_config_bool ( 'config.test' );
	if l_bool = false then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:4183 -- config not working' );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	l_bool = q_get_config_bool ( 'missing.test' );
	if l_bool != false then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:4190 -- config not working' );
		l_fail = true;
		n_err = n_err + 1;
	end if;





	-- test 1 -----------------------------------------------------------------------------------------------------------
	-- Test 
	--		register
	--		login - should fail
	--		validate with email / token
	--		login - should succede
	--		2FA token -- should succede
	--		logout

	select count(1) into l_cnt1 from q_qr_users ;
	-- select q_auth_v1_register ( 'bob@example.com', 'bob the builder', 'my long secret password', 'Bob the Builder', 'user info password' )
	select q_auth_v1_register ( p_email, p_pw, p_hmac_password, p_first_name, p_last_name, p_userdata_password, 'RRFRUD6NOPVVO2ZV' )
		into l_r1;
	select count(1) into l_cnt2 from q_qr_users ;
	select l_r1::jsonb -> 'status' into l_status;
	-- Sample Output
	--  	Register Output:   {"status":"success", "user_id":4, "email_verify_token":"5ed065f3-7b59-477c-942a-5479bd22c2d7", "secret_2fa":"cf1756e5ef"}
	insert into t_output ( msg ) values ( 'Register Output:   '||l_r1 );
	if l_status != '"success"' then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:4218 -- failed to register, expected ->"success"<- got ->'||l_status||'<-' );
		insert into t_output ( msg ) values ( '   '||l_r1 );
		l_fail = true;
		n_err = n_err + 1;
	end if;
	if l_cnt1 >= l_cnt2 then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:4224 -- failed to register new user.  Row count did not increase.' );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	select l_r1::jsonb -> 'email_verify_token' into l_email_verify_token;
	l_email_verify_token = replace ( l_email_verify_token, '"', '' );
	insert into t_output ( msg ) values ( 'l_email_verify_token = '||coalesce(l_email_verify_token,'--null--') );


	-- new -----------------------------------------------------------------------------------------------------------------------------------------
	commit; 

	select count(1) into l_cnt1 from q_qr_user_role;
	if l_cnt1 = 0 then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:4239 -- missing data in q_qr_user_role' );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	select l_r1::jsonb -> 'user_id' into l_user_id;

	--------------------------------- create an auth token -------------------------------
	-- select token
	-- 	into l_auth_token
	-- 	from q_qr_auth_tokens
	-- 	where user_id = l_user_id
	-- 	limit 1
	-- 	;
	l_auth_token = uuid_generate_v4();
	insert into q_qr_auth_tokens ( token, user_id ) values ( l_auth_token, l_user_id ); -- expires in 31 days
	insert into t_output ( msg ) values ( 'l_auth_token = '||l_auth_token::text );
	delete from x_tmp_values where name = 'l_auth_token';
	insert into x_tmp_values ( name, value ) values ( 'l_auth_token', l_auth_token::text );
	select count(1) into l_cnt_auth_tokens;
	if not found or l_cnt_auth_tokens = 0 then 
		insert into t_output ( msg ) values ( 'Missing - no auth_tokens: File:001.tables.m4.sql Line No:4260 -- missing data in q_qr_user_role' );
	end if;
	commit; 

	-- end -----------------------------------------------------------------------------------------------------------------------------------------

	commit; 

	select l_r1::jsonb -> 'secret_2fa' into l_secret_2fa;
	l_secret_2fa = replace ( l_secret_2fa, '"', '' );
	insert into t_output ( msg ) values ( 'l_secret_2fa = '||coalesce(l_secret_2fa,'---null---') );

	select l_r1::jsonb -> 'user_id' into l_user_id;
	insert into t_output ( msg ) values ( 'l_user_id = '||coalesce(to_json(l_user_id)::text,'---null---') );

	commit; 
	select count(1) into l_cnt_auth_tokens;
	if not found or l_cnt_auth_tokens = 0 then 
		insert into t_output ( msg ) values ( 'Missing - no auth_tokens: File:001.tables.m4.sql Line No:4278 -- missing data in q_qr_user_role' );
	end if;

	-- set this user to be an "admin"
	insert into q_qr_user_role ( user_id, role_id ) values
		  ( l_user_id, 1001 ) -- xyzzy - improve to use role name.
	;
	-- xyzzy - improve to use add_role_to_usr


	-- check that user exists
	-- check function that allows us to selet un-encrypted data.
	select count(1) 
		into l_cnt1 
		from (
			select get_user_list( 'my long secret password', 'user info password' )
		) as t1;
	if l_cnt1 = 0 then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:4296 -- failed to create user' );
		l_fail = true;
		n_err = n_err + 1;
	end if;
	select count(1) into l_cnt_auth_tokens;
	if not found or l_cnt_auth_tokens = 0 then 
		insert into t_output ( msg ) values ( 'Missing - no auth_tokens: File:001.tables.m4.sql Line No:4302 -- missing data in q_qr_user_role' );
	end if;



	-- xyzzy - check that user has not had email registration
	-- xyzzy - check that user has token sent for email registration
		-- xyzzy - check that user has token returned matches

	-- xyzzy - Attempt Login - fail




	insert into t_output ( msg ) values ( 'Just before call' );
	insert into t_output ( msg ) values ( 'l_email_verify_token = '||coalesce(l_email_verify_token, '---null---'));
	commit;

	-- Email Validate User
	select q_auth_v1_email_verify ( l_email_verify_token, 'my long secret password', 'user info password' ) 
		into l_r2;

	insert into t_output ( msg ) values ( 'Just after call' );
	insert into t_output ( msg ) values ( 'l_r2 = '||coalesce(l_r2, '---null---') );
	commit;

	-- xyzzy - Attempt loing succede (1)
		-- xyzzy - verify no auth_token returned.
		-- xyzzy - verify that we get a 2fa required.


	select count(1) into l_cnt_auth_tokens;
	if not found or l_cnt_auth_tokens = 0 then 
		insert into t_output ( msg ) values ( 'Missing - no auth_tokens: File:001.tables.m4.sql Line No:4335 -- missing data in q_qr_user_role' );
	end if;

	-- test 1a ----------------------------------------------------------------------------------------------------------
	-- Validate the Privileges (Roles) on user
	-- Check Privs - Verify that "user" role is setup for this user. that privileges is set.

	-- select 'should be ''f''';
	select q_amdin_HasPriv ( l_user_id, 'May X' )
		into l_bool;
	if l_bool != false then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:4346 -- return true on non-existent privilege.  user_id='||l_user_id::text );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	-- select 'should be ''t''';
	select q_amdin_HasPriv ( l_user_id, 'May Change Password' )
		into l_bool;
	if l_bool != true then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:4355 -- return false on privilege that should exist.  user_id='||l_user_id::text );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	select count(1) into l_cnt_auth_tokens;
	if not found or l_cnt_auth_tokens = 0 then 
		insert into t_output ( msg ) values ( 'Missing - no auth_tokens: File:001.tables.m4.sql Line No:4362 -- missing data in q_qr_user_role' );
	end if;










-- Some sort of stuff to validate QR code / api call to setup Authenticator tool

-- 2nd part of 2fa login




	-- ( ( create user / register                                 	: q_auth_v1_register 
	-- ( ( validate - email                                  		: q_auth_v1_email_verify 
	-- ( ( setup 2fa - 2fa authenticator (outside tool TOTP)        : 
	-- ( ( login - cookie set jwt - Autenticaiotn Berer Token       : q_auth_v1_login 
	-- ( ( validate the TOTP stuff                                  | q_auth_v1_validate_2fa_token 
	-- ( ( get main menu for QR stuff - webpage                     :
	-- ( ( generate QR - webpage                                  	:
	-- ( ( use QR - webpage                                  		:
	-- ( ( report on accounts / usage of QR - webpage  / reort      :
	-- ( ( all front end appliaiotn stuff                           :
	-- ( ( logout							                        | q_auth_v1_logout 








	-- Attempt login w/ bad password - fail

	-- Attempt login w/ bad username - fail

	-- Attempt login w/ no username - fail

	-- Attempt login w/ no password - fail

	-- Attempt login w/ bad OTP - fail

	-- Attempt login w/ good OTP - success (1)
	-- Attempt login w/ same good OTP - fail as (1)



	-- set start date of account in future
		-- Attempt loing succede (1) -- now fail

	-- set start date of account in past
		-- Attempt loing succede (1) -- now succede


	-- set end date of account in future
		-- Attempt loing succede (1) -- now succede

	-- set end date of account in past
		-- Attempt loing succede (1) -- now fail



	-- 2fa validate
		-- verify auth_token returned
		-- verify preivs retuend


	-- change password process
		-- verify tokens destroyed


	--  logout - verify tokens destroyed


	-- Delete Account -- how is this done.




	-- Too many repeated login failures - wait 10 sec try again - fail

	-- Too many repeated login failures - wait 70 sec try again - success




-- Appliccation Chunks to DO
-- 1. generate jwt tokens and check them (set cookie) on successful login.
-- 2. generate jwt tokens and re-send cookie on re-validate - get new auth-token.
-- 3. check totp 1 time / regiser topt 2fa stuff

	if not l_fail then 
		insert into t_output ( msg ) values ( 'PASS' );
		insert into x_tmp_pass_fail ( name ) values ( 'PASS' );
	else 
		insert into t_output ( msg ) values ( 'FAILED!  No of Errors = '||(n_err::text) );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED!  No of Errors = '||(n_err::text) );
	end if;

END
$$ LANGUAGE plpgsql;


select msg from t_output ;


-- 20 |  l_data= {"status":"success", "user_id":3, "email_verify_token":"18207657-b420-445a-aea5-6c061ffa1e89", "require_2fa":"y", "tmp_token":"e35940af-720c-4438-be52-36e8f8367398", "secret_2fa":"RRFRUD6NOPVVO2ZV", "otp":["d7e317eb","d2ab7aa0","5c2e003d","a336f3c4","6fb1a96c","5a5d6db3","3b578288","0de795f7","2fa3a644","b5736cc4","854d8029","549a0584","92191c96","6587e7ab","080ef5ad","8d2eac1f","226a5c12","5207693d","99520939","3c78f96e"]} | 2022-04-23 09:39:46.31673



-- Just like leonbloy suggested, using two schemas in a database is the way to go. Suppose a source schema (old DB) and a target schema (new DB), you can try
-- something like this (you should consider column names, types, etc.):
-- 		INSERT INTO target.Awards SELECT * FROM source.Nominations;
DO $$
DECLARE
	p_email text;
	p_hmac_password text;
	p_userdata_password text;
	p_first_name text;
	p_last_name text;
	p_pw text;
	l_user_id int;
	l_status text;
	l_r1 text;
	l_r2 text;
	l_cnt1 int;
	l_cnt2 int;
	l_fail bool;
	l_bool bool;
	n_err int;
	l_email_verify_token text;
	l_secret_2fa text;
	v_cnt int;
	l_auth_token uuid;
	l_junk1 int;
	l_privilage text;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2017, 2021, 2022.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	l_fail = false;
	n_err = 0;

	select value::uuid
		into l_auth_token
		from x_tmp_values
		where name = 'l_auth_token'
		;
	if not found then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:4516 -- missing data in x_tmp_values, key=''l_auth_token'' -no rows found-' );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	select t1.user_id as "user_id", json_agg(t3.priv_name)::text as "privileges"
		into l_junk1, l_privilage
		from q_qr_users as t1
			join q_qr_auth_tokens as t2 on ( t1.user_id = t2.user_id )
			left join q_qr_user_to_priv as t3 on ( t1.user_id = t3.user_id )
		where t2.token = l_auth_token
		  and ( t1.start_date < current_timestamp or t1.start_date is null )
		  and ( t1.end_date > current_timestamp or t1.end_date is null )
		  and t1.email_validated = 'y'
		  and ( t1.setup_complete_2fa = 'n' or t1.setup_complete_2fa is null )
		  and t2.expires > current_timestamp
		group by t1.user_id
		;
	if not found then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:4535 -- missing data in role/priv/token -no rows found-' );
		l_fail = true;
		n_err = n_err + 1;
	end if;
	if l_junk1 <> l_user_id then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:4540 -- missing data in role/priv/token - bad user id' );
		l_fail = true;
		n_err = n_err + 1;
	end if;
	if l_privilage::text = '[null]' then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:4545 -- missing data in role/priv/token - bad user id' );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	if not l_fail then 
		insert into t_output ( msg ) values ( 'PASS' );
		insert into x_tmp_pass_fail ( name ) values ( 'PASS' );
	else 
		insert into t_output ( msg ) values ( 'FAILED!  No of Errors = '||(n_err::text) );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED!  No of Errors = '||(n_err::text) );
	end if;

	insert into t_output ( msg ) values ( ' ' );
	insert into t_output ( msg ) values ( ' ' );
	commit;

END
$$ LANGUAGE plpgsql;

drop table if exists x_tmp_values ;

select msg from t_output ;

select name from x_tmp_pass_fail;

drop table if exists x_tmp_pass_fail ;
-- all done --
