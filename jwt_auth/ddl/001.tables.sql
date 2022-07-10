
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
	  seq 		serial not null primary key
	, msg 		text
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
	, user_id		uuid					-- a user specified ID to join to q_qr_users.user_id
	, updated 		timestamp
	, created 		timestamp default current_timestamp not null
);

create index q_qr_user_seen_before_p1 on q_qr_manifest_version using hash ( hash_seen );
create index q_qr_user_seen_before_p2 on q_qr_manifest_version ( created );



CREATE OR REPLACE function q_qr_manifest_version_upd()
RETURNS trigger AS $$
BEGIN
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
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
	l_user_id				uuid;
	l_id					uuid;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		-- fix all of these
		--		insert into t_output ( msg ) values ( '  l_user_id ->'||coalesce(to_json(l_user_id)::text,'---null---')||'<-');
		-- bad
		--		insert into t_output ( msg ) values ( '		p_id ->'||p_id||'<-');
		insert into t_output ( msg ) values ( 'function ->q_auth_v1_etag_seen <- 001.tables.m4.sql 144' );
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

-- drop function q_auth_v1_etag_device_mark ( p_seen_id varchar, p_user_id varchar, p_hmac_password varchar, p_userdata_password varchar );
-- drop function q_auth_v1_etag_device_mark ( p_seen_id varchar, p_user_id uuid, p_hmac_password varchar, p_userdata_password varchar );

-- to be called when you have a successful 2fa validation on a user_id
create or replace function q_auth_v1_etag_device_mark ( p_seen_id varchar, p_user_id uuid, p_hmac_password varchar, p_userdata_password varchar )
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
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_auth_v1_etag_device_mark<- 001.tables.m4.sql 231' );
		insert into t_output ( msg ) values ( '		p_seen_id ->'||coalesce(to_json(p_seen_id)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '		p_user_id ->'||coalesce(to_json(p_user_id)::text,'---null---')||'<-');
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















CREATE SEQUENCE if not exists t_order_seq
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
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
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


-- create index q_qr_code_h1 on q_qr_code using hash ( qrid10 );
create unique index q_qr_code_h1 on q_qr_code ( qrid10 );











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

create index q_qr_saved_state_p1 on q_qr_saved_state ( expires );



CREATE OR REPLACE function q_qr_saved_state_upd()
RETURNS trigger AS $$
BEGIN
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
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
	user_id 				uuid default uuid_generate_v4() not null primary key,
	email_hmac 				bytea not null,
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
	parent_user_id 			uuid,
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
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
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
	user_id 				uuid not null primary key,
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
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
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
    user_id uuid,
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








-- drop function q_auth_v1_hmac_encode_email ( p_email varchar, p_hmac_password varchar );
-- drop function q_auth_v1_hmac_encode ( p_email varchar, p_hmac_password varchar );

create or replace function q_auth_v1_hmac_encode ( p_email varchar, p_hmac_password varchar )
	returns bytea
	as $$
DECLARE
	l_data					text;
BEGIN
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
CREATE TABLE if not exists q_qr_auth_tokens (
	auth_token_id 	uuid default uuid_generate_v4() primary key not null,
	user_id 				uuid not null,
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
	tmp_token_id 		uuid default uuid_generate_v4() primary key not null,
	user_id 			uuid not null,
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
	security_log_id 	uuid default uuid_generate_v4() primary key not null,
	user_id 			uuid not null,
	activity			text,
	location			text,
	created 			timestamp default current_timestamp not null 						-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);





-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE if not exists q_qr_auth_log (
	security_log_id 	uuid default uuid_generate_v4() primary key not null,
	user_id 			uuid,
	activity			text,
	code				text,
	location			text,
	created 			timestamp default current_timestamp not null 						-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);





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

create unique index q_qr_one_time_password_u1 on q_qr_one_time_password ( user_id, otp_hmac );

ALTER TABLE q_qr_one_time_password 
	ADD CONSTRAINT q_qr_one_time_password_fk1
	FOREIGN KEY (user_id)
	REFERENCES q_qr_users (user_id)
;









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

create unique index q_qr_config_u1 on q_qr_config ( name ) ;



CREATE OR REPLACE function q_qr_config_upd()
RETURNS trigger AS $$
BEGIN
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
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
	user_role_id 	uuid default uuid_generate_v4() not null primary key,
	role_id 		uuid not null,
	user_id 		uuid not null
);

create unique index q_qr_user_role_u1 on q_qr_user_role ( role_id, user_id );
create unique index q_qr_user_role_u2 on q_qr_user_role ( user_id, role_id );

-- A list of all the possible roles that a user can have.
create table if not exists q_qr_role (
	  role_id 		uuid default uuid_generate_v4() not null primary key
	, role_name 	text not null
	, with_grant	varchar(1) default 'n'
);

create unique index q_qr_role_u1 on q_qr_role ( role_name );

-- M:N join from roles to privileges - the set of privileges that each role has.
create table if not exists q_qr_role_priv (
	role_priv_id 	uuid default uuid_generate_v4() not null primary key,
	role_id 		uuid not null,
	priv_id 		uuid not null
);

create unique index q_qr_role_priv_u1 on q_qr_role_priv ( priv_id, role_id );
create unique index q_qr_role_priv_u2 on q_qr_role_priv ( role_id, priv_id );

-- A talbe containing all the possible things that a person can have a permission to do.
create table if not exists q_qr_priv (
	  priv_id 		uuid default uuid_generate_v4() not null primary key
	, priv_name 	text not null
	, with_grant	varchar(1) default 'n'
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
-- "18207657-b420-445a-aea5-6c0610000000", 	-- priv_id
-- "e35940af-720c-4438-be52-36e8f0000000", 	-- role_id
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
delete from q_qr_priv cascade;
delete from q_qr_role cascade;
delete from q_qr_role_priv cascade;
delete from q_qr_user_role cascade;
insert into q_qr_priv ( priv_id, priv_name ) values 
	  ( '18207657-b420-445a-aea5-6c0610002001'::uuid, 'May Change Other Password' )
	, ( '18207657-b420-445a-aea5-6c0610002002'::uuid, 'May Shutdown Server' )
	, ( '18207657-b420-445a-aea5-6c0610002003'::uuid, 'May Change Password' )
	, ( '18207657-b420-445a-aea5-6c0610002004'::uuid, 'May Call Test' )

	, ( '18207657-b420-445a-aea5-6c0610002005'::uuid, 'Create New Priv' )
	, ( '18207657-b420-445a-aea5-6c0610002006'::uuid, 'Modify Priv' )
	, ( '18207657-b420-445a-aea5-6c0610002007'::uuid, 'List Priv' )
	, ( '18207657-b420-445a-aea5-6c0610002008'::uuid, 'Delete Priv' )

	, ( '18207657-b420-445a-aea5-6c0610002009'::uuid, 'Create New Role' )
	, ( '18207657-b420-445a-aea5-6c0610002010'::uuid, 'Modify Role' )
	, ( '18207657-b420-445a-aea5-6c0610002011'::uuid, 'List Role' )
	, ( '18207657-b420-445a-aea5-6c0610002012'::uuid, 'Delete Role' )

	, ( '18207657-b420-445a-aea5-6c0610002013'::uuid, 'May Login' )
	, ( '18207657-b420-445a-aea5-6c0610002014'::uuid, 'May Add/Rmeove Role From User' )
	, ( '18207657-b420-445a-aea5-6c0610002015'::uuid, 'May Insert BOL' )
	, ( '18207657-b420-445a-aea5-6c0610002016'::uuid, 'May Update BOL' )
	, ( '18207657-b420-445a-aea5-6c0610002017'::uuid, 'May Delete BOL' )
	, ( '18207657-b420-445a-aea5-6c0610002020'::uuid, 'May Select BOL' )
	, ( '18207657-b420-445a-aea5-6c0610002018'::uuid, 'May Register' )
	, ( '18207657-b420-445a-aea5-6c0610002019'::uuid, 'May BOL' )

	, ( '18207657-b420-445a-aea5-6c0610002022'::uuid, 'Admin: May Create Admin User' )
;
insert into q_qr_role ( role_id, role_name ) values
	  ( 'e35940af-720c-4438-be52-36e8f0001001'::uuid, 'role:admin' )
	, ( 'e35940af-720c-4438-be52-36e8f0001002'::uuid, 'role:server-maint' )
	, ( 'e35940af-720c-4438-be52-36e8f0001003'::uuid, 'role:user' )
;
insert into q_qr_role_priv ( role_id,  priv_id ) values
	  ( 'e35940af-720c-4438-be52-36e8f0001001'::uuid, '18207657-b420-445a-aea5-6c0610002001'::uuid )
	, ( 'e35940af-720c-4438-be52-36e8f0001001'::uuid, '18207657-b420-445a-aea5-6c0610002002'::uuid )
	, ( 'e35940af-720c-4438-be52-36e8f0001001'::uuid, '18207657-b420-445a-aea5-6c0610002003'::uuid )
	, ( 'e35940af-720c-4438-be52-36e8f0001001'::uuid, '18207657-b420-445a-aea5-6c0610002004'::uuid )
	, ( 'e35940af-720c-4438-be52-36e8f0001001'::uuid, '18207657-b420-445a-aea5-6c0610002006'::uuid )
	, ( 'e35940af-720c-4438-be52-36e8f0001001'::uuid, '18207657-b420-445a-aea5-6c0610002007'::uuid )
	, ( 'e35940af-720c-4438-be52-36e8f0001001'::uuid, '18207657-b420-445a-aea5-6c0610002008'::uuid )
	, ( 'e35940af-720c-4438-be52-36e8f0001001'::uuid, '18207657-b420-445a-aea5-6c0610002009'::uuid )
	, ( 'e35940af-720c-4438-be52-36e8f0001001'::uuid, '18207657-b420-445a-aea5-6c0610002010'::uuid )
	, ( 'e35940af-720c-4438-be52-36e8f0001001'::uuid, '18207657-b420-445a-aea5-6c0610002011'::uuid )
	, ( 'e35940af-720c-4438-be52-36e8f0001001'::uuid, '18207657-b420-445a-aea5-6c0610002012'::uuid )
	, ( 'e35940af-720c-4438-be52-36e8f0001001'::uuid, '18207657-b420-445a-aea5-6c0610002013'::uuid )
	, ( 'e35940af-720c-4438-be52-36e8f0001001'::uuid, '18207657-b420-445a-aea5-6c0610002014'::uuid )
	, ( 'e35940af-720c-4438-be52-36e8f0001001'::uuid, '18207657-b420-445a-aea5-6c0610002018'::uuid )
	, ( 'e35940af-720c-4438-be52-36e8f0001001'::uuid, '18207657-b420-445a-aea5-6c0610002019'::uuid )
	, ( 'e35940af-720c-4438-be52-36e8f0001001'::uuid, '18207657-b420-445a-aea5-6c0610002022'::uuid )

	, ( 'e35940af-720c-4438-be52-36e8f0001002'::uuid, '18207657-b420-445a-aea5-6c0610002002'::uuid )
	, ( 'e35940af-720c-4438-be52-36e8f0001002'::uuid, '18207657-b420-445a-aea5-6c0610002004'::uuid )
	, ( 'e35940af-720c-4438-be52-36e8f0001002'::uuid, '18207657-b420-445a-aea5-6c0610002013'::uuid )

	, ( 'e35940af-720c-4438-be52-36e8f0001003'::uuid, '18207657-b420-445a-aea5-6c0610002003'::uuid )
	, ( 'e35940af-720c-4438-be52-36e8f0001003'::uuid, '18207657-b420-445a-aea5-6c0610002004'::uuid )
	, ( 'e35940af-720c-4438-be52-36e8f0001003'::uuid, '18207657-b420-445a-aea5-6c0610002013'::uuid )
	, ( 'e35940af-720c-4438-be52-36e8f0001003'::uuid, '18207657-b420-445a-aea5-6c0610002018'::uuid )
	, ( 'e35940af-720c-4438-be52-36e8f0001003'::uuid, '18207657-b420-445a-aea5-6c0610002019'::uuid )
;


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
create or replace function q_amdin_HasPriv ( p_user_id uuid, p_priv_needed varchar )
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









create or replace function q_amdin_add_priv_to_role ( p_role_id uuid, p_priv_id varchar )
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
		l_data = '{"status":"error","msg":"Not authoriazed to ''Modify Role''","code":"0001","location":"001.tables.m4.sql 1066"}'; 
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Not authorized to ''Modify Role''', '0001', 'File:001.tables.m4.sql Line No:1067');
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











create or replace function q_amdin_remove_priv_from_role ( p_role_id uuid, p_priv_id varchar )
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
		l_data = '{"status":"error","msg":"Not authoriazed to ''Modify Role''","code":"0002","location":"001.tables.m4.sql 1113"}'; 
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Not authorized to ''Modify Role''', '0002', 'File:001.tables.m4.sql Line No:1114');
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
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
	select value into l_data from q_qr_config where name = p_name;
	if not found then
		l_data = '';
	end if;
	RETURN l_data;
END;
$$ LANGUAGE plpgsql;

-- drop function q_get_config_bool ( p_name varchar );
create or replace function q_get_config_bool ( p_name varchar )
	returns bool
	as $$
DECLARE
	l_data bool;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
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
	l_user_id				uuid;
	l_email_hmac			bytea;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_recovery_token		= uuid_generate_v4();


	if not l_fail then
		-- (fixed) xyzzy-Slow!! - better to do select count - and verify where before update.
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
			from q_qr_users as t1
			where t1.email_hmac = l_email_hmac
		)
		select
			  user_id
		    , first_name
		    , last_name
		into
			  l_user_id
			, l_first_name
			, l_last_name
		from user_row
		where parent_user_id is null
		  and account_type = 'login'
		  and ( start_date < current_timestamp or start_date is null )
		  and ( end_date > current_timestamp or end_date is null )
		  and email_validated = 'y'
		  and setup_complete_2fa = 'y'
		for update
		;
		if not found then

			-- Select to get l_user_id for email.  If it is not found above then this may not be a fully setup user.
			-- The l_user_id is used below in a delete to prevet marking of devices as having been seen.
			select user_id
				into l_user_id
				from q_qr_users as t1
				where t1.email_hmac = l_email_hmac
				;

			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or not email validated","code":"0003","location":"001.tables.m4.sql 1276"}'; 
		end if;
	end if;

	-- Delete all the id.json rows for this user - every marked device will nedd to 2fa after this request.
	delete from q_qr_manifest_version where user_id = l_user_id;

	if not l_fail then
		update q_qr_users as t1
			set 
				  password_reset_token = l_recovery_token		
				, password_reset_time = current_timestamp + interval '4 hours'
			where t1.user_id = l_user_id
			;
		-- check # of rows.
		GET DIAGNOSTICS v_cnt = ROW_COUNT;
		if v_cnt != 1 then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or not email validated","code":"0004","location":"001.tables.m4.sql 1294"}'; 
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or not email validated', '0004', 'File:001.tables.m4.sql Line No:1295');
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
	l_user_id				uuid;
	l_first_name			text;
	l_last_name				text;
	l_email					text;
	l_recovery_token		uuid;
	l_email_hmac			bytea;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';
	

	if not l_fail then
		-- 
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
			from q_qr_users as t0
			where t0.email_hmac = l_email_hmac
		)
		select
			  user_id
		    , first_name
		    , last_name
		    , email
		into
			  l_user_id
			, l_first_name
			, l_last_name
			, l_email					
		from user_row as t1
		where password_reset_token = p_recovery_token::uuid
		  and parent_user_id is null
		  and account_type = 'login'
		  and ( start_date < current_timestamp or t1.start_date is null )
		  and ( end_date > current_timestamp or t1.end_date is null )
		  and email_validated = 'y'
		  and setup_complete_2fa = 'y'
		;
		if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or not email validated","code":"0005","location":"001.tables.m4.sql 1382"}'; 
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or not email validated', '0005', 'File:001.tables.m4.sql Line No:1383');
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
	l_user_id				uuid;
	l_first_name			text;
	l_last_name				text;
	l_email_hmac			bytea;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

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
			from q_qr_users as t0
			where t0.email_hmac = l_email_hmac
		)
		select
			  user_id
		    , first_name
		    , last_name
		into
			  l_user_id
			, l_first_name
			, l_last_name
		from user_row as t1
		where password_reset_time > current_timestamp
		  and password_reset_token = p_recovery_token::uuid
		  and account_type = 'login'
		  and ( start_date < current_timestamp or t1.start_date is null )
		  and ( end_date > current_timestamp or t1.end_date is null )
		  and email_validated = 'y'
		  and setup_complete_2fa = 'y'
		  and parent_user_id is null
		for update
		;
		if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or not email validated","code":"0006","location":"001.tables.m4.sql 1468"}'; 
		end if;
	end if;

	if not l_fail then
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
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or not email validated","code":"0007","location":"001.tables.m4.sql 1484"}'; 
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or not email validated', '0007', 'File:001.tables.m4.sql Line No:1485');
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










-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
create or replace function q_auth_v1_delete_account ( p_email varchar, p_pw varchar, p_hmac_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_fail					bool;
	v_cnt 					int;
	l_user_id				uuid;
	l_email_hmac			bytea;
	l_first_name			text;
	l_last_name				text;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	-- Other Checks for valid account login.

	-- xyzzy - SIP accounts fail to do validation that this is a legitimate user.  This is done in the Go code with a "logged" in user.

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
					)
			for update
			;
		update q_qr_users as t1
			set 
				    start_date = current_timestamp + interval '50 years'
				  , end_date = current_timestamp - interval '1 minute'
			where t1.user_id = l_user_id
			;
		-- check # of rows.
		GET DIAGNOSTICS v_cnt = ROW_COUNT;
		if v_cnt != 1 then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or not email validated","code":"0008","location":"001.tables.m4.sql 1588"}'; 
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or not email validated', '0009', 'File:001.tables.m4.sql Line No:1589');
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
--	tgo_add_priv_to_user.sh -> q_qr_add_priv_to_user(...)
create or replace function q_auth_v1_add_priv_to_user ( p_email varchar, p_priv varchar, p_hmac_password varchar, p_userdata_password varchar)
	returns text
	as $$
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
	l_email_hmac			bytea;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';
	l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );

	select t1.user_id
		into l_user_id
		from q_qr_users as t1
		where t1.email_hmac = l_email_hmac
		;
	if not found then
		l_fail = true;
		l_data = '{"status":"error","msg":"Missing Account.","code":"0011","location":"001.tables.m4.sql 1647"}';
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
	l_user_id				uuid;
	l_role_id				uuid;
	l_user_role_id			uuid;
	l_priv_id				uuid;
	l_role_priv_id			uuid;
	l_user_priv_id			uuid;
	l_email_hmac			bytea;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';
	l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );

	select t1.user_id
		into l_user_id
		from q_qr_users as t1
		where t1.email_hmac = l_email_hmac
		;
	if not found then
		l_fail = true;
		l_data = '{"status":"error","msg":"Missing Account.","code":"0011","location":"001.tables.m4.sql 1762"}';
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
	l_user_id				uuid;
	l_role_id				uuid;
	l_user_role_id			uuid;
	l_priv_id				uuid;
	l_role_priv_id			uuid;
	l_user_priv_id			uuid;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
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
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_email_verify_token = uuid_generate_v4();

	-- l_tmp = uuid_generate_v4()::text;
	-- l_secret_2fa = substr(l_tmp,0,7) || substr(l_tmp,10,4);
	l_secret_2fa = p_secret;

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_register<- 001.tables.m4.sql 2006' );
		insert into t_output ( msg ) values ( '  p_email ->'||coalesce(to_json(p_email)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_pw ->'||coalesce(to_json(p_pw)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||coalesce(to_json(p_hmac_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_first_name ->'||coalesce(to_json(p_first_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_last_name ->'||coalesce(to_json(p_last_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_userdata_password ->'||coalesce(to_json(p_userdata_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_secret ->'||coalesce(to_json(p_secret)::text,'---null---')||'<-');
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
		l_data = '{"status":"error","msg":"Account already exists.  Please login or recover password.","code":"0011","location":"001.tables.m4.sql 2053"}';
		-- insert into q_qr_auth_security_log ( user_id, activity, location ) values ( l_bad_user_id, 'User Attempt to Re-Register Same Accont', 'File:001.tables.m4.sql Line No:2054');
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_bad_user_id, 'User Attempt to Re-Register Same Account.', '0011', 'File:001.tables.m4.sql Line No:2055');
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
			l_data = '{"status":"error","msg":"Unable to get privilages for the user.","code":"0012","location":"001.tables.m4.sql 2078"}';
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

		insert into q_qr_auth_security_log ( user_id, activity, location ) values ( l_user_id, 'User Registered', 'File:001.tables.m4.sql Line No:2122');

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
-- q_auth_v1_register_admin is a function for creating non user (role:user) accounts.
--
-- A few accounts are automatically built.  'root', 'admin' etc.   These accounts can then be used
-- to create other administration accounts.
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
create or replace function q_auth_v1_register_admin ( p_email varchar, p_pw varchar, p_hmac_password varchar, p_first_name varchar, p_last_name varchar, p_userdata_password varchar, p_secret varchar, p_root_password varchar, p_specifed_role_name varchar, p_user_id uuid )
	returns text
	as $$
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
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_email_verify_token = uuid_generate_v4();

	l_secret_2fa = p_secret;

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_register_admin<- 001.tables.m4.sql 2209' );
		insert into t_output ( msg ) values ( '  p_email ->'||coalesce(to_json(p_email)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_pw ->'||coalesce(to_json(p_pw)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||coalesce(to_json(p_hmac_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_first_name ->'||coalesce(to_json(p_first_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_last_name ->'||coalesce(to_json(p_last_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_userdata_password ->'||coalesce(to_json(p_userdata_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_secret ->'||coalesce(to_json(p_secret)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_specified_role_name ->'||coalesce(to_json(p_specified_role_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_user_id ->'||coalesce(to_json(p_user_id)::text,'---null---')||'<-');
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
		l_data = '{"status":"error","msg":"Account already exists.  Please login or recover password.","code":"0011","location":"001.tables.m4.sql 2251"}';
		-- insert into q_qr_auth_security_log ( user_id, activity, location ) values ( l_bad_user_id, 'User Attempt to Re-Register Same Accont', 'File:001.tables.m4.sql Line No:2252');
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_bad_user_id, 'User Attempt to Re-Register Same Account.', '0011', 'File:001.tables.m4.sql Line No:2253');
	end if;

	if not l_fail then
		if not q_amdin_HasPriv ( p_user_id, 'Admin: May Create Admin User' ) then
			if l_debug_on then
				insert into t_output ( msg ) values ( 'failed to find priv ''Admin: May Create Admin User'' ->'||p_user_id||'<-');
			end if;
			l_fail = true;
			l_data = '{"status":"error","msg":"Account lacks ''Admin: May Create Admin User'' privilege","code":"0319","location":"001.tables.m4.sql 2262"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account lacks ''Admin: May Create Admin User'' privilege', '0319', 'File:001.tables.m4.sql Line No:2263');
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
				insert into t_output ( msg ) values ( 'failed to find role ->'||p_specified_role_priv||'<-');
			end if;
			l_fail = true;
			l_data = '{"status":"error","msg":"No Such Role:'''||p_speified_role_name||''' ","code":"0320","location":"001.tables.m4.sql 2279"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'No Such Role: '''||p_specified_role_name||''' ', '0320', 'File:001.tables.m4.sql Line No:2280');
		end if;
	end if;

	if not l_fail then
		select json_agg(t1.priv_name)::text
			into l_privs
			from q_qr_role_to_priv as t1
			where t1.role_name = p_specifed_role_name
			;
		if not found then
			if l_debug_on then
				insert into t_output ( msg ) values ( 'Failed to get the privilages for the user' );
			end if;
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to get privilages for the user.","code":"0012","location":"001.tables.m4.sql 2295"}';
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
		) returning user_id into l_user_id  ;

		insert into q_qr_user_role ( user_id, role_id ) 
			select l_user_id, t1.role_id 
			from q_qr_role as t1
			where t1.role_name =  'role:user' 
			;

		insert into q_qr_auth_security_log ( user_id, activity, location ) values ( l_user_id, 'User Registered', 'File:001.tables.m4.sql Line No:2341');

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
-- stmt := "q_auth_v1_resend_email_register ( $1, $2, $3, $4, $5, $6, $7 )"
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

create or replace function q_auth_v1_resend_email_register ( p_email varchar, p_pw varchar, p_hmac_password varchar, p_first_name varchar, p_last_name varchar, p_userdata_password varchar, p_secret varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_junk					text;
	l_fail					bool;
	l_user_id				uuid;
	l_email_verify_token	uuid;
	l_secret_2fa 			varchar(20);
	l_debug_on 				bool;
	l_auth_token			uuid;
	l_tmp_token				uuid;
	l_email_hmac			bytea;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_email_verify_token = uuid_generate_v4();

	-- l_tmp = uuid_generate_v4()::text;
	-- l_secret_2fa = substr(l_tmp,0,7) || substr(l_tmp,10,4);
	l_secret_2fa = p_secret;

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_resend_email_register<- 001.tables.m4.sql 2423' );
		insert into t_output ( msg ) values ( '  p_email ->'||coalesce(to_json(p_email)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_pw ->'||coalesce(to_json(p_pw)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||coalesce(to_json(p_hmac_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_first_name ->'||coalesce(to_json(p_first_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_last_name ->'||coalesce(to_json(p_last_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_userdata_password ->'||coalesce(to_json(p_userdata_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_secret ->'||coalesce(to_json(p_secret)::text,'---null---')||'<-');
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




	-- Lookup User / Validate Password

	l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );
	select user_id
		into l_user_id
		from q_qr_users as t1
		where t1.email_hmac = l_email_hmac
		;

	if not found then
		l_fail = true;
		l_data = '{"status":"error","msg":"No account with this email address exists.  Please register again.","code":"0111","location":"001.tables.m4.sql 2463"}';
		-- insert into q_qr_auth_security_log ( user_id, activity, location ) values ( l_bad_user_id, 'User Attempt to Re-Register Same Accont', 'File:001.tables.m4.sql Line No:2464');
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_bad_user_id, 'No account with this email address exists.  Please register again.","code":"0111","location":"001.tables.m4.sql 2465"}' );
	end if;

	if not l_fail then

		select t1.email_verify_token
			, t1.secret_2fa
			into l_email_verify_token
				, l_secret_2fa
			from q_qr_users as t1
			where t1.user_id = l_user_id
			  and t1.email_verify_token is not null
		  	  and t1.password_hash = crypt(p_pw, password_hash)
			;

		if not found then
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to resend email registration.  Please register again.","code":"0113","location":"001.tables.m4.sql 2482"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_bad_user_id, 'Unable to resend email registration.  Please register again.","code":"0113","location":"001.tables.m4.sql 2483"}' );
		end if;

		insert into q_qr_auth_security_log ( user_id, activity, location ) values ( l_user_id, 'User Email Resend Registered', 'File:001.tables.m4.sql Line No:2486');

	end if;

	if not l_fail then

		select t10.token
			into l_tmp_token
			from (
				select t11.token, t11.expires
					from q_qr_tmp_token as t11
					where t11.user_id = l_user_id
					order by t11.expires
			) as t10
			limit 1
			;
		if not found then
			l_tmp_token = uuid_generate_v4();
			insert into q_qr_tmp_token ( user_id, token, expires ) values ( l_user_id, l_tmp_token, current_timestamp + interval '1 day' );
		end if;

		l_data = '{"status":"success"'
			||', "user_id":' 			||coalesce(to_json(l_user_id)::text,'""')
			||', "email_verify_token":' ||coalesce(to_json(l_email_verify_token)::text,'""')
			||', "require_2fa":' 		||coalesce(to_json('y'::text)::text,'""')
			||', "tmp_token":'   		||coalesce(to_json(l_tmp_token)::text,'""')
			||', "secret_2fa":'			||coalesce(to_json(l_secret_2fa)::text,'""')
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
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_email_verify_token = uuid_generate_v4();

	-- l_tmp = uuid_generate_v4()::text;
	-- l_secret_2fa = substr(l_tmp,0,7) || substr(l_tmp,10,4);
	l_secret_2fa = p_secret;

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_register<- 001.tables.m4.sql 2571' );
		insert into t_output ( msg ) values ( '  p_email ->'||coalesce(to_json(p_email)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_validator ->'||coalesce(to_json(p_validator)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||coalesce(to_json(p_hmac_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_first_name ->'||coalesce(to_json(p_first_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_last_name ->'||coalesce(to_json(p_last_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_userdata_password ->'||coalesce(to_json(p_userdata_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_secret ->'||coalesce(to_json(p_secret)::text,'---null---')||'<-');
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
		l_data = '{"status":"error","msg":"Account already exists.  Please login or recover password.","code":"1011","location":"001.tables.m4.sql 2617"}';
		-- insert into q_qr_auth_security_log ( user_id, activity, location ) values ( l_bad_user_id, 'User Attempt to Re-Register Same Accont', 'File:001.tables.m4.sql Line No:2618');
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_bad_user_id, 'User Attempt to Re-Register Same Account.', '1011', 'File:001.tables.m4.sql Line No:2619');
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
			l_data = '{"status":"error","msg":"Unable to get privilages for the user.","code":"1012","location":"001.tables.m4.sql 2642"}';
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

		insert into q_qr_auth_security_log ( user_id, activity, location ) values ( l_user_id, 'User Registered', 'File:001.tables.m4.sql Line No:2684');

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
	l_user_id				uuid;
	l_tmp_token				uuid;
	l_debug_on 				bool;
	l_email_verify_token	uuid;
	v_cnt 					int;
	l_email_hmac			bytea;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
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

	l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );
	select t1.user_id
		into l_user_id
		from q_qr_users as t1
		where t1.email_hmac = l_email_hmac
		  and email_verify_token = p_old_email_verify_token 
		;
	if not found then
		if l_debug_on then
			insert into t_output ( msg ) values ( 'Failed to find the user' );
		end if;
		l_fail = true;
		l_data = '{"status":"error","msg":"Unable to find the user.","code":"0013","location":"001.tables.m4.sql 2787"}';
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
		l_data = '{"status":"error","msg":"Invalid User/Email or Account not valid","code":"0014","location":"001.tables.m4.sql 2801"}'; 
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid User or Account not valid', '0014', 'File:001.tables.m4.sql Line No:2802');
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
create or replace function q_auth_v1_delete_user ( p_user_id uuid )
	returns text
	as $$
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022

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
-- drop function q_auth_v1_change_password ( p_un varchar, p_pw varchar, p_new_pw varchar, p_hmac_password varchar, p_userdata_password varchar );

-- 2. q_auth_v1_change_password
create or replace function q_auth_v1_change_password ( p_email varchar, p_pw varchar, p_new_pw varchar, p_hmac_password varchar, p_userdata_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_tmp					text;
	v_cnt					int;
	l_user_id				uuid;
	l_email_hmac			bytea;
	l_first_name			text;
	l_last_name				text;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if not l_fail then
		if p_pw = p_new_pw then
			l_fail = true;
			l_data = '{"status":"error","msg":"Old and New Password should be different","code":"0025","location":"001.tables.m4.sql 2892"}'; 
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Old and New Password should be different', '0025', 'File:001.tables.m4.sql Line No:2893');
		end if;
	end if;

	if not l_fail then
		-- (fixed) xyzzy-Slow!! - better to do select count - and verify where before update.
		l_email_hmac = q_auth_v1_hmac_encode ( p_email, p_hmac_password );
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
			where ( t8.start_date < current_timestamp or t8.start_date is null )
		      and ( t8.end_date > current_timestamp or t8.end_date is null )
			  and (
					(
							t8.account_type = 'login'
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
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or not email validated","code":"0315","location":"001.tables.m4.sql 2963"}'; 
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or not email validated', '0315', 'File:001.tables.m4.sql Line No:2964');

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
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or not email validated","code":"0015","location":"001.tables.m4.sql 2979"}'; 
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or not email validated', '0015', 'File:001.tables.m4.sql Line No:2980');
		end if;
	end if;

	-- Delete all the id.json rows for this user - every marked device will nedd to 2fa after this request.
	-- Select to get l_user_id for email.  If it is not found above then this may not be a fully setup user.
	-- The l_user_id is used below in a delete to prevet marking of devices as having been seen.
	delete from q_qr_manifest_version 
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
-- From 2. q_auth_v1_change_password
create or replace function q_auth_v1_change_password_admin ( p_admin_user_id uuid, p_email varchar, p_new_pw varchar, p_hmac_password varchar, p_userdata_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_tmp					text;
	v_cnt					int;
	l_first_name			text;
	l_last_name				text;
	l_user_id				uuid;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if not q_amdin_HasPriv ( p_admin_user_id, 'May Change Other Password' ) then
		l_fail = true;
		l_data = '{"status":"error","msg":"Not authoriazed to change others passwrod","code":"0016","location":"001.tables.m4.sql 3038"}'; 
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Not authorized to change others password', '0016', 'File:001.tables.m4.sql Line No:3039');
	end if;

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
			where t1.user_id = l_user_id;
			;
		-- check # of rows.
		GET DIAGNOSTICS v_cnt = ROW_COUNT;
		if v_cnt != 1 then
			l_fail = true;
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or not email validated","code":"0017","location":"001.tables.m4.sql 3076"}'; 
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or not email validated', '0017', 'File:001.tables.m4.sql Line No:3077');
		end if;
	end if;

	if not l_fail then
		-- Delete all the id.json rows for this user - every marked device will nedd to 2fa after this request.
		-- Select to get l_user_id for email.  If it is not found above then this may not be a fully setup user.
		-- The l_user_id is used below in a delete to prevet marking of devices as having been seen.
		delete from q_qr_manifest_version 
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
-- Inicates partial registraiotn, email_validated == "n", - code==="0020"			0020
-- Inicates partial registraiotn, setup_complete_2fa == "n", - code==="0220"		0220
--
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

create or replace function q_auth_v1_login ( p_email varchar, p_pw varchar, p_am_i_known varchar, p_hmac_password varchar, p_userdata_password varchar )
	returns text
	as $$
DECLARE
	l_2fa_id				uuid;
	l_data					text;
	l_fail					bool;
  	l_user_id 				uuid;
	l_email_validated		varchar(1);
	l_setup_complete_2fa 	varchar(1);
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
	l_one_time_password_id 	uuid;
	v_cnt 					int;
	l_validation_method		varchar(10);
	l_manifet_id			uuid;
	l_email_hmac            bytea;
	l_otp_hmac              text;
	l_is_new_device_login	varchar(1);
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );

	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
	l_fail = false;
	l_data = '{"status":"unknown"}';
	l_is_new_device_login= 'n';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_login<- 001.tables.m4.sql 3158' );
		insert into t_output ( msg ) values ( '  p_email ->'||coalesce(to_json(p_email)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_pw ->'||coalesce(to_json(p_pw)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_am_i_known ->'||coalesce(to_json(p_am_i_known)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||coalesce(to_json(p_hmac_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_userdata_password ->'||coalesce(to_json(p_userdata_password)::text,'---null---')||'<-');
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
			from q_qr_users
			where email_hmac = l_email_hmac
			;
			if not found then
				l_fail = true;
				l_data = '{"status":"error","msg":"Invalid Username or Password","code":"0055","location":"001.tables.m4.sql 3283"}'; -- return no such account or password
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Password', '0055', 'File:001.tables.m4.sql Line No:3284');
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
					insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Used Ont Time Password', '0011', 'File:001.tables.m4.sql Line No:3308');
				else 
					l_fail = true;
					l_data = '{"status":"error","msg":"Invalid Username or Password","code":"0018","location":"001.tables.m4.sql 3311"}'; -- return no such account or password
					insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Password', '0018', 'File:001.tables.m4.sql Line No:3312');
				end if;

			end if; -- AAA

		end if; -- BBB

	end if;

	if l_debug_on then
		insert into t_output ( msg ) values ( '->'||coalesce(to_json(p_userdata_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( 'l_first_name = ->'||coalesce(to_json(l_first_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( 'l_last_name = ->'||coalesce(to_json(l_last_name)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( 'l_validation_method = ->'||coalesce(to_json(l_validation_method)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( 'l_start_date = ->'||coalesce(to_json(l_start_date)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( 'l_end_date = ->'||coalesce(to_json(l_end_date)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( 'l_email_validated = ->'||coalesce(to_json(l_email_validated)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( 'l_setup_complete_2fa = ->'||coalesce(to_json(l_setup_complete_2fa)::text,'---null---')||'<-');
	end if;

	if not l_fail then
		if not q_amdin_HasPriv ( l_user_id, 'May Login' ) then
			if l_debug_on then
				insert into t_output ( msg ) values ( 'failed to find priv ''May Login'' ->'||l_user_id||'<-');
			end if;
			l_fail = true;
			l_data = '{"status":"error","msg":"Account lacks ''May Login'' privilege","code":"0019","location":"001.tables.m4.sql 3338"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account lacks ''May Login'' privilege', '0019', 'File:001.tables.m4.sql Line No:3339');
		end if;
	end if;

	if not l_fail then
		if l_validation_method != 'un/pw' then
			l_fail = true;
			l_data = '{"status":"error","msg":"Account is not a un/pw authetication method","code":"0027","location":"001.tables.m4.sql 3346"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account is not a un/pw autetication method', '0027', 'File:001.tables.m4.sql Line No:3347');
		end if;
	end if;

	if not l_fail then
		if l_email_validated = 'n' then
			-- Inicates partial registraiotn, email_validated == "n", - code==="0020"
			l_fail = true;
			l_data = '{"status":"error","msg":"Account has not not been validated","code":"0020","location":"001.tables.m4.sql 3355"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has not been validated', '0020', 'File:001.tables.m4.sql Line No:3356');
		end if;
	end if;

	if not l_fail then
		if l_setup_complete_2fa = 'n' then
			-- Inicates partial registraiotn, setup_complete_2fa == "n", - code==="0220"
			l_fail = true;
			l_data = '{"status":"error","msg":"Account has not not had 2Fa setup","code":"0220","location":"001.tables.m4.sql 3364"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has not had 2Fa setup', '0220', 'File:001.tables.m4.sql Line No:3365');
		end if;
	end if;

	if not l_fail then
		if l_start_date is not null then
			if l_start_date > current_timestamp then
				l_fail = true;
				l_data = '{"status":"error","msg":"Account has a start date that has not been reached","code":"0028","location":"001.tables.m4.sql 3373"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has start date that has not bee reached', '0028', 'File:001.tables.m4.sql Line No:3374');
			end if;
		end if;
	end if;

	if not l_fail then
		if l_end_date is not null then
			if l_end_date <= current_timestamp then
				l_fail = true;
				l_data = '{"status":"error","msg":"Account has a end date that has been reached","code":"0029","location":"001.tables.m4.sql 3383"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has ned date that has bee reached', '0029', 'File:001.tables.m4.sql Line No:3384');
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
					l_is_new_device_login = 'y';
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
				l_data = '{"status":"error","msg":"Unable to create user/auth-token.","code":"0030","location":"001.tables.m4.sql 3426"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to crate user/auth-token.', '0030', 'File:001.tables.m4.sql Line No:3427');
			END;
		end if;
	end if;

	if not l_fail then
		if l_login_failures >= 6 and l_failed_login_timeout >= current_timestamp then
			l_fail = true;
			l_data = '{"status":"error","msg":"Too many failed login attempts - please wait 1 minute.","code":"0031","location":"001.tables.m4.sql 3435"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Too many failed login attempts - please wait 1 minute.', '0031', 'File:001.tables.m4.sql Line No:3436');
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
			l_data = '{"status":"error","msg":"Unable to get privilages for the user.","code":"0032","location":"001.tables.m4.sql 3457"}';
			l_privileges = '';
		end if;
	end if;

	if not l_fail then

		if l_debug_on then
			insert into t_output ( msg ) values ( 'function ->q_quth_v1_login<-..... Continued ...  001.tables.m4.sql 3465' );
			insert into t_output ( msg ) values ( 'calculate l_user_id ->'||coalesce(to_json(l_user_id)::text,'---null---')||'<-');
			insert into t_output ( msg ) values ( 'calculate l_privs ->'||coalesce(to_json(l_privileges)::text,'---null---')||'<-');
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
			insert into q_qr_auth_security_log ( user_id, activity, location ) values ( l_user_id, 'Login - Part 1 Success: '||l_tmp_token::text, 'File:001.tables.m4.sql Line No:3482');
		else
			insert into q_qr_auth_security_log ( user_id, activity, location ) values ( l_user_id, 'Successful Login', 'File:001.tables.m4.sql Line No:3484');
		end if;
		l_data = '{"status":"success"'
			||', "user_id":'     			||coalesce(to_json(l_user_id)::text,'""')
			||', "auth_token":'  			||coalesce(to_json(l_auth_token)::text,'""')
			||', "tmp_token":'   			||coalesce(to_json(l_tmp_token)::text,'""')
			||', "require_2fa":' 			||coalesce(to_json(l_require_2fa)::text,'""')
			||', "secret_2fa":'  			||coalesce(to_json(l_secret_2fa)::text,'""')
			||', "account_type":'			||coalesce(to_json(l_account_type)::text,'""')
			||', "privileges":'  			||coalesce(to_json(l_privileges)::text,'""')
			||', "first_name":'  			||coalesce(to_json(l_first_name)::text,'""')
			||', "last_name":'   			||coalesce(to_json(l_last_name)::text,'""')
			||', "is_new_device_login":' 	||coalesce(to_json(l_is_new_device_login)::text,'"n"')
			||'}';
	else 
		if l_user_id is not null then
			insert into q_qr_auth_security_log ( user_id, activity, location ) values ( l_user_id, 'Login Failure', 'File:001.tables.m4.sql Line No:3500');
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
drop function q_auth_v1_regen_otp ( p_email varchar, p_pw varchar, p_hmac_password varchar );

create or replace function q_auth_v1_regen_otp ( p_email varchar, p_pw varchar, p_hmac_password varchar , p_userdata_password varchar )
	returns text
	as $$
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

	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
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
			l_data = '{"status":"error","msg":"Invalid Username or Password/attempt to create new OTP","code":"0034","location":"001.tables.m4.sql 3583"}'; 
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Password/attempt to create new OTP', '0034', 'File:001.tables.m4.sql Line No:3584');
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
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

create or replace function q_auth_v1_register_un_pw ( p_parent_user_id uuid, p_email varchar, p_hmac_password varchar,  p_userdata_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_fail					bool;
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
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022

	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_register_un_pw<- 001.tables.m4.sql 3668' );
		insert into t_output ( msg ) values ( '  p_parent_user_id ->'||coalesce(to_json(p_parent_user_id)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_email ->'||coalesce(to_json(p_email)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||coalesce(to_json(p_hmac_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_userdata_password ->'||coalesce(to_json(p_userdata_password)::text,'---null---')||'<-');
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
			l_data = '{"status":"error","msg":"Invalid Username or Password","code":"0035","location":"001.tables.m4.sql 3716"}'; -- return no such account or password
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Password', '0035', 'File:001.tables.m4.sql Line No:3717');
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
			l_data = '{"status":"error","msg":"Account has not not been validated","code":"0036","location":"001.tables.m4.sql 3732"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has not been validated', '0036', 'File:001.tables.m4.sql Line No:3733');
		end if;
	end if;
	if not l_fail then
		if l_start_date is not null then
			if l_start_date > current_timestamp then
				l_fail = true;
				l_data = '{"status":"error","msg":"Account has a start date that has not been reached","code":"0036","location":"001.tables.m4.sql 3740"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has start date that has not bee reached', '0036', 'File:001.tables.m4.sql Line No:3741');
			end if;
		end if;
	end if;
	if not l_fail then
		if l_end_date is not null then
			if l_end_date <= current_timestamp then
				l_fail = true;
				l_data = '{"status":"error","msg":"Account has a end date that has been reached","code":"0037","location":"001.tables.m4.sql 3749"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has ned date that has bee reached', '0037', 'File:001.tables.m4.sql Line No:3750');
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
				l_data = '{"status":"error","msg":"Unable to create user/auth-token.","code":"0038","location":"001.tables.m4.sql 3763"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to crate user/auth-token.', '0038', 'File:001.tables.m4.sql Line No:3764');
			END;
		end if;
	end if;
	if not l_fail then
		if l_login_failures > 6 or l_failed_login_timeout >= current_timestamp then
			l_fail = true;
			l_data = '{"status":"error","msg":"Too many failed login attempts - please wait 1 minute.","code":"0039","location":"001.tables.m4.sql 3771"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Too many failed login attempts - please wait 1 minute.', '0039', 'File:001.tables.m4.sql Line No:3772');
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

		insert into q_qr_auth_security_log ( user_id, activity, location ) values ( l_user_id, 'User Registered', 'File:001.tables.m4.sql Line No:3806');
	end if;

	if not l_fail then
		l_tmp_token = uuid_generate_v4();
		insert into q_qr_tmp_token ( user_id, token ) values ( l_user_id, l_tmp_token );
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
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
create or replace function q_auth_v1_register_token ( p_parent_user_id uuid,  p_hmac_password varchar,  p_userdata_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_fail					bool;
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
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022

	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_quth_v1_register_token<- 001.tables.m4.sql 3867' );
		insert into t_output ( msg ) values ( '  p_parent_user_id ->'||coalesce(to_json(p_parent_user_id)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||coalesce(to_json(p_hmac_password)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_userdata_password ->'||coalesce(to_json(p_userdata_password)::text,'---null---')||'<-');
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
			l_data = '{"status":"error","msg":"Invalid Username or Password","code":"0040","location":"001.tables.m4.sql 3915"}'; -- return no such account or password
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Password', '0040', 'File:001.tables.m4.sql Line No:3916');
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
			l_data = '{"status":"error","msg":"Account has not not been validated","code":"0041","location":"001.tables.m4.sql 3931"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has not been validated', '0041', 'File:001.tables.m4.sql Line No:3932');
		end if;
	end if;
	if not l_fail then
		if l_start_date is not null then
			if l_start_date > current_timestamp then
				l_fail = true;
				l_data = '{"status":"error","msg":"Account has a start date that has not been reached","code":"0043","location":"001.tables.m4.sql 3939"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has start date that has not bee reached', '0043', 'File:001.tables.m4.sql Line No:3940');
			end if;
		end if;
	end if;
	if not l_fail then
		if l_end_date is not null then
			if l_end_date <= current_timestamp then
				l_fail = true;
				l_data = '{"status":"error","msg":"Account has a end date that has been reached","code":"0044","location":"001.tables.m4.sql 3948"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Account has ned date that has bee reached', '0044', 'File:001.tables.m4.sql Line No:3949');
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
				l_data = '{"status":"error","msg":"Unable to create user/auth-token.","code":"0045","location":"001.tables.m4.sql 3962"}';
				insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to crate user/auth-token.', '0045', 'File:001.tables.m4.sql Line No:3963');
			END;
		end if;
	end if;
	if not l_fail then
		if l_login_failures > 6 or l_failed_login_timeout >= current_timestamp then
			l_fail = true;
			l_data = '{"status":"error","msg":"Too many failed login attempts - please wait 1 minute.","code":"0046","location":"001.tables.m4.sql 3970"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Too many failed login attempts - please wait 1 minute.', '0046', 'File:001.tables.m4.sql Line No:3971');
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

		insert into q_qr_auth_security_log ( user_id, activity, location ) values ( l_user_id, 'User Registered', 'File:001.tables.m4.sql Line No:4005');
	end if;

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
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
create or replace function q_auth_v1_refresh_token ( p_user_id varchar, p_auth_token varchar, p_hmac_password varchar,  p_userdata_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_debug_on 				bool;
	l_auth_token			uuid;	
	l_user_id				uuid;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function ->q_auth_v1_refresh_token<- 001.tables.m4.sql 4049' );
		insert into t_output ( msg ) values ( '  p_user_id ->'||coalesce(to_json(p_user_id)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_auth_token ->'||coalesce(to_json(p_auth_token)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	-- Check current token is still valid
	-- 		Check that UserID matches with auth_token
	select user_id
		into l_user_id
		from q_qr_users as t1
			join q_qr_auth_tokens as t2 on ( t2.user_id = t1.user_id )
		where t1.user_id = p_user_id::uuid
		  and t2.token = p_auth_token::uuid
		;

	if not found then
		l_fail = true;
		l_data = '{"status":"error","msg":"Unable to create user/auth-token.  Current token is invalid.","code":"0263","location":"001.tables.m4.sql 4067"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to create user/auth-token.  Current token is invalid.', '0263', 'File:001.tables.m4.sql Line No:4068');
	end if;

	if not l_fail then
		-- insert / create auth_token
		l_auth_token = uuid_generate_v4();
		BEGIN
			insert into q_qr_auth_tokens ( token, user_id ) values ( l_auth_token, l_user_id );
		EXCEPTION WHEN unique_violation THEN
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to create user/auth-token.","code":"0163","location":"001.tables.m4.sql 4078"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to create user/auth-token.', '0163', 'File:001.tables.m4.sql Line No:4079');
		END;
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "auth_token":'  ||coalesce(to_json(l_auth_token)::text,'""')
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
-- drop function q_auth_v1_email_verify ( p_email_verify_token varchar );

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
	l_user_id				uuid;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'function -> q_auth_v1_email_verify (v2) <- 001.tables.m4.sql 4126' );
		insert into t_output ( msg ) values ( '  p_email_verify_token ->'||coalesce(to_json(p_email_verify_token)::text,'---null---')||'<-');
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
		l_data = '{"status":"error","msg":"Unable to validate account via email.  Please register again.","code":"0058","location":"001.tables.m4.sql 4141"}'; 
	end if;
	if l_debug_on then
		insert into t_output ( msg ) values ( '  l_user_id ->'||coalesce(to_json(l_user_id)::text,'---null---')||'<-');
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
			l_data = '{"status":"error","msg":"Unable to validate account via email.  Please register again.","code":"0059","location":"001.tables.m4.sql 4157"}'; 
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to validate account via email..', '0059', 'File:001.tables.m4.sql Line No:4158');
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
			insert into t_output ( msg ) values ( '  l_tmp_token ->'||coalesce(to_json(l_tmp_token)::text,'---null---')||'<-');
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
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
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
-- drop function q_auth_v1_setup_2fa_test ( p_user_id uuid );

create or replace function q_auth_v1_setup_2fa_test ( p_user_id uuid, p_hmac_password varchar, p_userdata_password varchar )
	returns text
	as $$
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022

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

-- drop function q_auth_v1_validate_2fa_token ( p_email varchar, p_tmp_token varchar, p_2fa_secret varchar, p_hmac_password varchar );

create or replace function q_auth_v1_validate_2fa_token ( p_email varchar, p_tmp_token varchar, p_2fa_secret varchar, p_hmac_password varchar, p_userdata_password varchar )
	returns text
	as $$
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
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';
	l_email_validated = 'n';
	l_x2fa_validated = 'n';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'In q_auth_v1_validate_2fa_token (v2)' );
		insert into t_output ( msg ) values ( '  p_email ->'||coalesce(to_json(p_email)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_tmp_token ->'||coalesce(to_json(p_tmp_token)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||coalesce(to_json(p_hmac_password)::text,'---null---')||'<-');
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
			l_data = '{"status":"error","msg":"Your 2fa number has epired - please try again.","code":"0060","location":"001.tables.m4.sql 4355"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Expired 2fa number.', '0060', 'File:001.tables.m4.sql Line No:4356');
		else
			l_data = '{"status":"error","msg":"Your temporary login token has expired.  Please start your login process again.","code":"0061","location":"001.tables.m4.sql 4358"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Your temporary login token has expired.  Please start your login process again.', '0061', 'File:001.tables.m4.sql Line No:4359');
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
			l_data = '{"status":"error","msg":"Unable to create user/auth-token.","code":"0063","location":"001.tables.m4.sql 4379"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to create user/auth-token.', '0063', 'File:001.tables.m4.sql Line No:4380');
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
			l_data = '{"status":"error","msg":"Unable to get privilages for the user.","code":"0064","location":"001.tables.m4.sql 4395"}';
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
	l_user_id				uuid;
	l_auth_token 			uuid;
	l_debug_on 				bool;
	l_expires				text;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
	l_debug_on = q_get_config_bool ( 'debug' );
	l_fail = false;
	l_data = '{"status":"unknown"}';

	if l_debug_on then
		insert into t_output ( msg ) values ( 'In q_auth_v1_refresh_token (v2)' );
		insert into t_output ( msg ) values ( '  p_email ->'||coalesce(to_json(p_email)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_token ->'||coalesce(to_json(p_token)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_hmac_password ->'||coalesce(to_json(p_hmac_password)::text,'---null---')||'<-');
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
		l_data = '{"status":"error","msg":"Unable to refresh auth-token.","code":"0065","location":"001.tables.m4.sql 4481"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to refresh auth-token.', '0065', 'File:001.tables.m4.sql Line No:4482');
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
			l_data = '{"status":"error","msg":"Unable to create user/auth-token.","code":"0066","location":"001.tables.m4.sql 4495"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Unable to create user/auth-token.', '0066', 'File:001.tables.m4.sql Line No:4496');
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
	l_user_id				uuid;
	l_secret_2fa 			varchar(20);
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
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
		l_data = '{"status":"error","msg":"Invalid email.","code":"0067","location":"001.tables.m4.sql 4550"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid email number.', '0067', 'File:001.tables.m4.sql Line No:4551');
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
-- select q_auth_v1_change_email_address ( 'bob@truckcoinswap.com','bob@truckcoinswap.com','i-am-bob',4,'my long secret password','user info password' );

create or replace function q_auth_v1_change_email_address ( p_old_email varchar, p_new_email varchar, p_pw varchar, p_user_id uuid, p_hmac_password varchar, p_userdata_password varchar )
	returns text
	as $$
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
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: 45c46f35a7258d3d4d205692275ddd75288f0064 tag: v1.0.2 build_date: Thu Jul  7 18:29:51 MDT 2022
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
							t8.account_type = 'login'
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
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or not email validated","code":"0170","location":"001.tables.m4.sql 4668"}'; 
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or not email validated', '0170', 'File:001.tables.m4.sql Line No:4669');
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
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or not email validated","code":"0070","location":"001.tables.m4.sql 4684"}'; 
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or not email validated', '0070', 'File:001.tables.m4.sql Line No:4685');
		end if;

	end if;

	if not l_fail then
		-- Insert into log that email changed.
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Email Addres Changed.', '0099', 'File:001.tables.m4.sql Line No:4692');
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||', "first_name":'  			||coalesce(to_json(l_first_name)::text,'""')
			||', "last_name":'   			||coalesce(to_json(l_last_name)::text,'""')
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;













-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Tests
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

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
-- Simple register/login test.
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
delete from q_qr_tmp_token cascade;
delete from q_qr_one_time_password cascade;
delete from q_qr_auth_tokens cascade;
delete from q_qr_users cascade;
delete from t_output;

DO $$
DECLARE
	l_user_id uuid;
	l_bool bool;
	l_text text;
	l_status text;
	l_cnt int;
	l_tmp_token varchar;
	l_2fa_secret varchar;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2017, 2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	l_2fa_secret = 'RRFRUD6NOPVVO2ZV';

	-- ----------------------------------------------------------------------------------------------------------------------------
	-- Register a user
	-- ----------------------------------------------------------------------------------------------------------------------------
	select q_auth_v1_register ( 'bob@example.com', 'bob the builder', 'my long secret password', 'Bob', 'the Builder', 'user info password', l_2fa_secret )
		into l_text;
	insert into t_output ( msg ) values ( l_text );

	select count(1) into l_cnt from q_qr_users;
	if l_cnt = 0 then
		insert into t_output ( msg ) values ( 'FAILED - registraiton test 1 - failed to create a user File:001.tables.m4.sql Line No:4766' );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED - registraiton test 1 - failed to create a user File:001.tables.m4.sql Line No:4767' );
	else 
		insert into t_output ( msg ) values ( 'PASS - registraiton test 1' );
		insert into x_tmp_pass_fail ( name ) values ( 'PASS - registraiton test 1' );
	end if;

	select l_text::jsonb ->> 'tmp_token' into l_tmp_token;


	-- ----------------------------------------------------------------------------------------------------------------------------
	-- Try login before setup
	-- login should fail at this point
	-- ----------------------------------------------------------------------------------------------------------------------------
	select q_auth_v1_login ( 'bob@example.com', 'bob the builder', '181d4e23-9595-47ec-9a26-1c8313d321f9', 'my long secret password', 'user info password' )
		into l_text;
	insert into t_output ( msg ) values ( l_text );
	select l_text::jsonb -> 'status' into l_status;
	if l_status != '"success"' then
		-- note should not succede -- not setup yet.
		insert into t_output ( msg ) values ( 'PASS - registraiton test 2' );
		insert into x_tmp_pass_fail ( name ) values ( 'PASS - registraiton test 2' );
	else
		insert into t_output ( msg ) values ( 'FAILED - registraiton test 2 - login when should not File:001.tables.m4.sql Line No:4789' );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED - registraiton test 2 - login when should not File:001.tables.m4.sql Line No:4790' );
	end if;


	-- ----------------------------------------------------------------------------------------------------------------------------
	-- Validate email, Validate 2fa
	-- ----------------------------------------------------------------------------------------------------------------------------
	select q_auth_v1_email_verify ( t2.email_verify_token::text , 'my long secret password', 'user info password' ) 
		into l_text
		from q_qr_users as t2
		where t2.email_hmac = q_auth_v1_hmac_encode ( 'bob@example.com', 'my long secret password' )
	;
	insert into t_output ( msg ) values ( l_text );
	select l_text::jsonb -> 'status' into l_status;
	if l_status != '"success"' then
		insert into t_output ( msg ) values ( 'FAILED - registraiton test 3 - validation of email File:001.tables.m4.sql Line No:4805' );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED - registraiton test 3 - validation of email File:001.tables.m4.sql Line No:4806' );
	else
		insert into t_output ( msg ) values ( 'PASS - registraiton test 3 - validation of email' );
		insert into x_tmp_pass_fail ( name ) values ( 'PASS - registraiton test 3 - validation of email' );
	end if;


	-- create or replace function q_auth_v1_validate_2fa_token ( p_email varchar, p_tmp_token varchar, p_2fa_secret varchar, p_hmac_password varchar, p_userdata_password varchar )
	select q_auth_v1_validate_2fa_token ( 'bob@example.com', l_tmp_token, l_2fa_secret, 'my long secret password', 'user info password' )
		into l_text;
	insert into t_output ( msg ) values ( l_text );
	select l_text::jsonb -> 'status' into l_status;
	if l_status != '"success"' then
		insert into t_output ( msg ) values ( 'FAILED - registraiton test 3 - validation of email File:001.tables.m4.sql Line No:4819' );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED - registraiton test 3 - validation of email File:001.tables.m4.sql Line No:4820' );
	else
		insert into t_output ( msg ) values ( 'PASS - registraiton test 4 - validated 2fa secret' );
		insert into x_tmp_pass_fail ( name ) values ( 'PASS - registraiton test 4 - validated 2fa secret' );
	end if;




	-- ----------------------------------------------------------------------------------------------------------------------------
	-- Now login *NOT* should work.
	-- ----------------------------------------------------------------------------------------------------------------------------
	select q_auth_v1_login ( 'bob@example.com', 'bOb the builder', '181d4e23-9595-47ec-9a26-1c8313d321f9', 'my long secret password', 'user info password' )
		into l_text;
	insert into t_output ( msg ) values ( l_text );
	select l_text::jsonb -> 'status' into l_status;
	if l_status != '"success"' then
		insert into t_output ( msg ) values ( 'PASS - registraiton/login test 5 - bad password'  );
		insert into x_tmp_pass_fail ( name ) values ( 'PASS - registraiton/login test 5 - bad password' );
	else
		insert into t_output ( msg ) values ( 'FAILED - registraiton test 5 - faile to login - bad password File:001.tables.m4.sql Line No:4840' );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED - registraiton test 5 - faile to login - bad password File:001.tables.m4.sql Line No:4841' );
	end if;

	select q_auth_v1_login ( 'bob82@example.com', 'bob the builder', '181d4e23-9595-47ec-9a26-1c8313d321f9', 'my long secret password', 'user info password' )
		into l_text;
	insert into t_output ( msg ) values ( l_text );
	select l_text::jsonb -> 'status' into l_status;
	if l_status != '"success"' then
		insert into t_output ( msg ) values ( 'PASS - registraiton/login test 5 - bad username'  );
		insert into x_tmp_pass_fail ( name ) values ( 'PASS - registraiton/login test 5 - bad username' );
	else
		insert into t_output ( msg ) values ( 'FAILED - registraiton test 5 - faile to login - bad username File:001.tables.m4.sql Line No:4852' );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED - registraiton test 5 - faile to login - bad username File:001.tables.m4.sql Line No:4853' );
	end if;



	-- ----------------------------------------------------------------------------------------------------------------------------
	-- Now login should work.
	-- ----------------------------------------------------------------------------------------------------------------------------
	select q_auth_v1_login ( 'bob@example.com', 'bob the builder', '181d4e23-9595-47ec-9a26-1c8313d321f9', 'my long secret password', 'user info password' )
		into l_text;
	insert into t_output ( msg ) values ( l_text );
	select l_text::jsonb -> 'status' into l_status;
	if l_status != '"success"' then
		insert into t_output ( msg ) values ( 'FAILED - registraiton test 5 - faile to login File:001.tables.m4.sql Line No:4866' );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED - registraiton test 5 - faile to login File:001.tables.m4.sql Line No:4867' );
	else
		insert into t_output ( msg ) values ( 'PASS - registraiton/login test 5' );
		insert into x_tmp_pass_fail ( name ) values ( 'PASS - registraiton/login test 5' );
	end if;


END
$$ LANGUAGE plpgsql;

select seq, msg from t_output order by seq;
delete from t_output;
select name from x_tmp_pass_fail;






-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Test of privs function.
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

select seq, msg from t_output;
delete from t_output;


DO $$
DECLARE
	l_user_id uuid;
	l_bool bool;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2017, 2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd

	select user_id
		into l_user_id
		from q_qr_users
		where email_hmac = q_auth_v1_hmac_encode ( 'bob@example.com', 'my long secret password' )
		;

	-- check priv on user (check privs)
	-- select 'should be ''f''';
	select q_amdin_HasPriv ( l_user_id, 'May X' )
		into l_bool;

	if l_bool then
		insert into t_output ( msg ) values ( 'FAILED - q_admin_HasPriv test 1 File:001.tables.m4.sql Line No:4914' );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED - q_admin_HasPriv test 1 File:001.tables.m4.sql Line No:4915' );
	else
		insert into t_output ( msg ) values ( 'PASS - q_admin_HasPriv test 1' );
		insert into x_tmp_pass_fail ( name ) values ( 'PASS - q_admin_HasPriv test 1' );
	end if;

	-- select 'should be ''t''';
	select q_amdin_HasPriv ( l_user_id, 'May Change Password' )
		into l_bool;
	if l_bool then
		insert into t_output ( msg ) values ( 'PASS - q_admin_HasPriv test 2' );
		insert into x_tmp_pass_fail ( name ) values ( 'PASS - q_admin_HasPriv test 2' );
	else
		insert into t_output ( msg ) values ( 'FAILED - q_admin_HasPriv test 2 File:001.tables.m4.sql Line No:4928' );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED - q_admin_HasPriv test 2 File:001.tables.m4.sql Line No:4929' );
	end if;


END
$$ LANGUAGE plpgsql;


select seq, msg from t_output order by seq;
delete from t_output;
select name from x_tmp_pass_fail;














-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Tests - Procedure/Inline
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
DO $$
DECLARE
	l_2fa_secret varchar;
	l_auth_token uuid;
	l_bool bool;
	l_cnt1 int;
	l_cnt2 int;
	l_cnt_auth_tokens int;
	l_email_verify_token text;
	l_fail bool;
	l_junk1 int;
	l_privilage text;
	l_r1 text;
	l_r2 text;
	l_secret_2fa text;
	l_status text;
	l_text text;
	l_tmp_token varchar;
	l_user_id uuid;
	l_user_id_str text;
	n_err int;
	p_email text;
	p_first_name text;
	p_hmac_password text;
	p_last_name text;
	p_pw text;
	p_userdata_password text;
	v_cnt int;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2017, 2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	l_fail = false;
	n_err = 0;


	-- Check Data (Privileges) ------------------------------------------------------------------------------------------
	select count(1) into l_cnt1 from q_qr_role;
	if l_cnt1 = 0 then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:4995 -- missing data in q_qr_role' );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	select count(1) into l_cnt1 from q_qr_priv;
	if l_cnt1 = 0 then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:5002 -- missing data in q_qr_priv' );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	select count(1) into l_cnt1 from q_qr_role_priv;
	if l_cnt1 = 0 then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:5009 -- missing data in q_qr_role_priv' );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	select count(1) into l_cnt1 from q_qr_user_role;
	if l_cnt1 = 0 then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:5016 -- missing data in q_qr_user_role' );
		l_fail = true;
		n_err = n_err + 1;
	end if;











	p_email = 'bob2@example.com';
	p_pw = 'bob the builder';
	p_first_name = 'Bob';
	p_last_name = 'the Builder';
	p_hmac_password = 'my long secret password';	-- Using const passords in the tests will prevent this from interfering with...
	p_userdata_password = 'user info password';		-- ...any regular login accounts.
	l_2fa_secret = 'RRFRUD6NOPVVO2ZV';




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
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:5076 -- config not working' );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	update q_qr_config set b_value = true, value = 'yes' where name = 'config.test';
	GET DIAGNOSTICS v_cnt = ROW_COUNT;
	if v_cnt != 1 then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:5084 -- config not working' );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	l_bool = q_get_config_bool ( 'config.test' );
	if l_bool = false then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:5091 -- config not working' );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	l_bool = q_get_config_bool ( 'missing.test' );
	if l_bool != false then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:5098 -- config not working' );
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
	select q_auth_v1_register ( p_email, p_pw, p_hmac_password, p_first_name, p_last_name, p_userdata_password, l_2fa_secret )
		into l_r1;
	select l_r1::jsonb ->> 'tmp_token' into l_tmp_token;
	select count(1) into l_cnt2 from q_qr_users ;
	select l_r1::jsonb -> 'status' into l_status;
	-- Sample Output
	--  	Register Output:   {"status":"success", "user_id":4, "email_verify_token":"5ed065f3-7b59-477c-942a-5479bd22c2d7", "secret_2fa":"cf1756e5ef"}
	insert into t_output ( msg ) values ( 'Register Output:   '||coalesce(to_json(l_r1)::text,'---null---'));
	if l_status != '"success"' then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:5127 -- failed to register, expected ->"success"<- got ->'||l_status||'<-' );
		insert into t_output ( msg ) values ( '   '||l_r1 );
		l_fail = true;
		n_err = n_err + 1;
	end if;
	if l_cnt1 >= l_cnt2 then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:5133 -- failed to register new user.  Row count did not increase.' );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	select l_r1::jsonb ->> 'email_verify_token' into l_email_verify_token;
	-- l_email_verify_token = replace ( l_email_verify_token, '"', '' );
	insert into t_output ( msg ) values ( 'l_email_verify_token = '||coalesce(l_email_verify_token,'--null--') );


	-- new -----------------------------------------------------------------------------------------------------------------------------------------

	select count(1) into l_cnt1 from q_qr_user_role;
	if l_cnt1 = 0 then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:5147 -- missing data in q_qr_user_role' );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	select l_r1::jsonb ->> 'user_id' into l_user_id_str;
	l_user_id = l_user_id_str::uuid;

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
		insert into t_output ( msg ) values ( 'Missing - no auth_tokens: File:001.tables.m4.sql Line No:5169 -- missing data in q_qr_user_role' );
	end if;

	-- end -----------------------------------------------------------------------------------------------------------------------------------------


	select l_r1::jsonb ->> 'secret_2fa' into l_secret_2fa;
	-- l_secret_2fa = replace ( l_secret_2fa, '"', '' );
	insert into t_output ( msg ) values ( 'l_secret_2fa = '||coalesce(l_secret_2fa,'---null---') );

	select l_r1::jsonb ->> 'user_id' into l_user_id_str;
	insert into t_output ( msg ) values ( 'l_user_id = '||coalesce(to_json(l_user_id_str)::text,'---null---') );

	select count(1) into l_cnt_auth_tokens;
	if not found or l_cnt_auth_tokens = 0 then 
		insert into t_output ( msg ) values ( 'Missing - no auth_tokens: File:001.tables.m4.sql Line No:5184 -- missing data in q_qr_user_role' );
	end if;

	-- set this user to be an "admin"
	insert into q_qr_user_role ( user_id, role_id ) values
		  ( l_user_id, 'e35940af-720c-4438-be52-36e8f0001001'::uuid )
	;


	-- check that user exists
	-- check function that allows us to selet un-encrypted data.
	select count(1) 
		into l_cnt1 
		from (
			select get_user_list( 'my long secret password', 'user info password' )
		) as t1;
	if l_cnt1 = 0 then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:5201 -- failed to create user' );
		l_fail = true;
		n_err = n_err + 1;
	end if;
	select count(1) into l_cnt_auth_tokens;
	if not found or l_cnt_auth_tokens = 0 then 
		insert into t_output ( msg ) values ( 'Missing - no auth_tokens: File:001.tables.m4.sql Line No:5207 -- missing data in q_qr_user_role' );
	end if;



	-- xyzzy - check that user has not had email registration

	-- xyzzy - check that user has token sent for email registration
		-- xyzzy - check that user has token returned matches





	insert into t_output ( msg ) values ( 'Just before call' );
	insert into t_output ( msg ) values ( 'l_email_verify_token = '||coalesce(l_email_verify_token, '---null---'));

	-- Email Validate User
	select q_auth_v1_email_verify ( l_email_verify_token, 'my long secret password', 'user info password' ) 
		into l_r2;

	insert into t_output ( msg ) values ( 'Just after call' );
	insert into t_output ( msg ) values ( 'l_r2 = '||coalesce(l_r2, '---null---') );
	select l_r2::jsonb -> 'status' into l_status;
	if l_status != '"success"' then
		insert into t_output ( msg ) values ( 'FAILED - registraiton validate email - validation of email File:001.tables.m4.sql Line No:5232' );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED - registraiton validate email - validation of email File:001.tables.m4.sql Line No:5233' );
	else
		insert into t_output ( msg ) values ( 'PASS - registraiton validate email - validated email secret' );
		insert into x_tmp_pass_fail ( name ) values ( 'PASS - registraiton validate email - validated email secret' );
	end if;

	commit;


	-- function q_auth_v1_validate_2fa_token ( p_email varchar, p_tmp_token varchar, p_2fa_secret varchar, p_hmac_password varchar, p_userdata_password varchar )
	select q_auth_v1_validate_2fa_token ( p_email, l_tmp_token, l_2fa_secret, 'my long secret password', 'user info password' )
		into l_text;
	insert into t_output ( msg ) values ( l_text );
	select l_text::jsonb -> 'status' into l_status;
	if l_status != '"success"' then
		insert into t_output ( msg ) values ( 'FAILED - registraiton validate 2fa - validation of email File:001.tables.m4.sql Line No:5248' );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED - registraiton validate 2fa - validation of email File:001.tables.m4.sql Line No:5249' );
	else
		insert into t_output ( msg ) values ( 'PASS - registraiton validate 2fa - validated 2fa secret' );
		insert into x_tmp_pass_fail ( name ) values ( 'PASS - registraiton validate 2fa - validated 2fa secret' );
	end if;

	commit;



	-- ----------------------------------------------------------------------------------------------------------------------------
	-- Now login should work.
	-- ----------------------------------------------------------------------------------------------------------------------------
	select q_auth_v1_login ( p_email, 'bob the builder', '181d4e23-9595-47ec-9a26-1c8313d321f9', 'my long secret password', 'user info password' )
		into l_text;
	insert into t_output ( msg ) values ( l_text );
	select l_text::jsonb -> 'status' into l_status;
	if l_status != '"success"' then
		insert into t_output ( msg ) values ( 'FAILED - registraiton test 5 - faile to login File:001.tables.m4.sql Line No:5267' );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED - registraiton test 5 - faile to login File:001.tables.m4.sql Line No:5268' );
	else
		insert into t_output ( msg ) values ( 'PASS - registraiton/login test 5' );
		insert into x_tmp_pass_fail ( name ) values ( 'PASS - registraiton/login test 5' );
	end if;



-- xyzzy - verify no auth_token returned.
-- xyzzy - verify that we get a 2fa required.


	select count(1) into l_cnt_auth_tokens;
	if not found or l_cnt_auth_tokens = 0 then 
		insert into t_output ( msg ) values ( 'Missing - no auth_tokens: File:001.tables.m4.sql Line No:5282 -- missing data in q_qr_user_role' );
	end if;

	-- test 1a ----------------------------------------------------------------------------------------------------------
	-- Validate the Privileges (Roles) on user
	-- Check Privs - Verify that "user" role is setup for this user. that privileges is set.

	-- select 'should be ''f''';
	select q_amdin_HasPriv ( l_user_id, 'May X' )
		into l_bool;
	if l_bool != false then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:5293 -- return true on non-existent privilege.  user_id='||l_user_id::text );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	-- select 'should be ''t''';
	select q_amdin_HasPriv ( l_user_id, 'May Change Password' )
		into l_bool;
	if l_bool != true then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:5302 -- return false on privilege that should exist.  user_id='||l_user_id::text );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	select count(1) into l_cnt_auth_tokens;
	if not found or l_cnt_auth_tokens = 0 then 
		insert into t_output ( msg ) values ( 'Missing - no auth_tokens: File:001.tables.m4.sql Line No:5309 -- missing data in q_qr_user_role' );
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


select seq, msg from t_output order by seq;
delete from t_output;
select name from x_tmp_pass_fail;



















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
	l_user_id uuid;
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

	select count(1) 
		into l_cnt2
		from  (
			select t2.user_id, t1.role_name 
				from q_qr_user_role as t2
					join q_qr_role as t1 on ( t1.role_id = t2.role_id )
				where t2.user_id in (
					select user_id
						from q_qr_users
						where email_hmac = q_auth_v1_hmac_encode ( 'bob2@example.com', 'my long secret password' )
					)
		) lll
		;
	if l_cnt2 != 2 then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:5490 -- should have 2 roles - got:'||l_cnt2::text );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	select token
		into l_auth_token
		from q_qr_auth_tokens
		where user_id in (
			select user_id
				from q_qr_users
				where email_hmac = q_auth_v1_hmac_encode ( 'bob2@example.com', 'my long secret password' )
		)
		limit 1
		;
	if not found then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:5506 -- missing data in x_tmp_values, key=''l_auth_token'' -no rows found-' );
		l_fail = true;
		n_err = n_err + 1;
	end if;
	insert into t_output ( msg ) values ( 'l_auth_token = '||l_auth_token );

	select t1.user_id as "user_id", json_agg(t3.priv_name)::text as "privileges"
		into l_user_id, l_privilage
		from q_qr_users as t1
			join q_qr_auth_tokens as t2 on ( t1.user_id = t2.user_id )
			left join q_qr_user_to_priv as t3 on ( t1.user_id = t3.user_id )
		where t2.token = l_auth_token
		  and ( t1.start_date < current_timestamp or t1.start_date is null )
		  and ( t1.end_date > current_timestamp or t1.end_date is null )
		  and t1.email_validated = 'y'
		  and t1.setup_complete_2fa = 'y'
		  and t2.expires > current_timestamp
		group by t1.user_id
		;
	if not found then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:5526 -- missing data in role/priv/token -no rows found-' );
		l_fail = true;
		n_err = n_err + 1;
	end if;
	if l_privilage::text = '[null]' then
		insert into t_output ( msg ) values ( 'Test Failed: File:001.tables.m4.sql Line No:5531 -- missing data in role/priv/token - bad user id' );
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
	commit;

END
$$ LANGUAGE plpgsql;

select seq, msg from t_output order by seq;
delete from t_output;
select name from x_tmp_pass_fail;




drop table if exists x_tmp_values ;




-- select q_auth_v1_register_admin ( 'root', 'pdFscrum33a44bb', p_hmac_password varchar, 'Root', 'Root', p_userdata_password varchar, 'LNBKY26BSTL66YPF', 'pDfqr3f3ra721', p_specifed_role_name varchar, 3);
-- select q_auth_v1_register_admin ( 'pschlump@gmail.com', 'pdFscrum33a44bb', p_hmac_password varchar, 'Philip', 'Schlump', p_userdata_password varchar, 'SUHAL6OIUHAV7TNQ', 'pDfqr3f3ra721', p_specifed_role_name varchar, 3);

