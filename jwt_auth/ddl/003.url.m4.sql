
-- Copyright (C) Philip Schlump, 2008-2023.
-- MIT Licensed.  See LICENSE.mit file.
-- BSD Licensed.  See LICENSE.bsd file.

drop table if exists q_qr_redirect ;
drop table if exists q_qr_redirect_log ;

-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE if not exists q_qr_redirect (
	  redirect_id				uuid DEFAULT uuid_generate_v4() not null primary key
	, qr_id						text not null
	, qr_file_path				text not null
	, qr_url_path				text not null
	, campain_id				uuid 
	, user_id					uuid not null
	, destination_url			text not null
	, destination_headers		jsonb 
	, destination_params		jsonb 
	, destination_method		text default 'GET' not null
	, method					text default 'location' not null
	, updated 					timestamp
	, created 					timestamp default current_timestamp not null
);

create index q_qr_redirect_p1 on q_qr_redirect ( user_id, campain_id );
create index q_qr_redirect_p2 on q_qr_redirect ( destination_url );
create unique index q_qr_redirect_u1 on q_qr_redirect ( qr_id );

m4_updTrig(q_qr_redirect)


-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE if not exists q_qr_redirect_log (
	  redirect_log_id		uuid DEFAULT uuid_generate_v4() not null primary key
	, qr_id					uuid
	, redirect_id			uuid	 -- fk 
	, updated 				timestamp
	, created 				timestamp default current_timestamp not null
);

create index q_qr_redirect_log_p1 on q_qr_redirect_log ( group_id );

m4_updTrig(q_qr_redirect_log)





-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION q_qr_url_short_create ( p_short_id varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
	as $$
DECLARE
	l_data					text;
	l_first_name			text;
	l_last_name				text;
	l_fail					bool;
	v_cnt 					int;
	l_user_id				uuid;
	l_email_hmac			bytea;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"error","msg":"invalid id"}';

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
	-- stmt := "q_qr_url_short_redirect ( $1, $2, $3 )"
CREATE OR REPLACE FUNCTION q_qr_url_short_redirect ( p_short_id varchar, p_hmac_password varchar, p_userdata_password varchar ) RETURNS text
	as $$
DECLARE
	l_data					text;
	l_first_name			text;
	l_last_name				text;
	l_fail					bool;
	v_cnt 					int;
	l_user_id				uuid;
	l_email_hmac			bytea;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"error","msg":"invalid id"}';


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
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or not email validated","code":"m4_count()","location":"m4___file__ m4___line__"}';
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
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or not email validated","code":"m4_count()","location":"m4___file__ m4___line__"}';
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or not email validated', 'm4_counter()', 'File:m4___file__ Line No:m4___line__');
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

