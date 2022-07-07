create or replace function q_auth_v1_change_email_address ( p_old_email varchar, p_new_email varchar, p_pw varchar, p_user_id int, p_hmac_password varchar, p_userdata_password varchar )
	returns text
	as $$
DECLARE
	l_data					text;
	l_fail					bool;
	l_user_id				int;
	l_secret_2fa 			varchar(20);
	v_cnt 					int;
	l_email_hmac			bytea;
BEGIN
	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_user_id = p_user_id::int;

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
			into l_user_id
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
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or not email validated","code":"0170","location":"m4___file__ m4___line__"}'; 
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or not email validated', '0170', 'File:m4___file__ Line No:m4___line__');
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
			l_data = '{"status":"error","msg":"Invalid Username or Account not valid or not email validated","code":"0070","location":"m4___file__ m4___line__"}'; 
			insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Invalid Username or Account not valid or not email validated', '0070', 'File:m4___file__ Line No:m4___line__');
		end if;

	end if;

	if not l_fail then
		-- Insert into log that email changed.
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_user_id, 'Email Addres Changed.', '0099', 'File:m4___file__ Line No:m4___line__');
	end if;

	if not l_fail then
		l_data = '{"status":"success"'
			||'}';
	end if;

	RETURN l_data;
END;
$$ LANGUAGE plpgsql;
