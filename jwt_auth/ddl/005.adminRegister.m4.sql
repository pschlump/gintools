
-- Copyright (C) Philip Schlump, 2008-2023.
-- MIT Licensed.  See LICENSE.mit file.
-- BSD Licensed.  See LICENSE.bsd file.

-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION q_auth_v1_register_role ( p_email varchar, p_pw varchar, p_hmac_password varchar, p_first_name varchar, p_last_name varchar, p_userdata_password varchar, p_secret varchar, p_registration_token varchar, p_role_to_use varchar ) RETURNS text
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
	l_reg_password			text;
	l_cmp_to				text;
BEGIN
	l_debug_on = q_get_config_bool ( 'debug' );
	l_reg_password= q_get_config ( 'reg_password' );

	-- Copyright (C) Philip Schlump, 2008-2021.
	-- BSD 3 Clause Licensed.  See LICENSE.bsd
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	l_fail = false;
	l_data = '{"status":"unknown"}';

	l_email_verify_token = uuid_generate_v4();

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
		insert into t_output ( msg ) values ( '  p_registration_token ->'||coalesce(to_json(p_registration_token)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  p_role_to_use ->'||coalesce(to_json(p_role_to_use)::text,'---null---')||'<-');
		insert into t_output ( msg ) values ( '  ' );
	end if;

	l_cmp_to = encode(hmac(p_pregistration_token, p_hmac_password, 'sha256'), 'base64');
	if l_cmp_to <> l_reg_password then
		l_fail = true;
		l_data = '{"status":"error","msg":"Invalid registration_token.  No account created.","code":"0412","location":"m4___file__ m4___line__"}';
		l_privs = '';
	end if;


-- xyzzyRegister - TODO - 
	-- Cleanup any users that have expired tokens.
	-- won't work !!! tranactional error !!!
	-- !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	delete from q_qr_users
		where email_verify_expire < current_timestamp - interval '30 days'
		  and ( email_validated = 'n' or setup_complete_2fa = 'n' )
		;
	-- Cleanup any users that have expired saved state
	delete from q_qr_saved_state
		where expires < current_timestamp
		;

	-- Cleanup old tmp tokens.
	delete from q_qr_tmp_token 
		where expires < current_timestamp
		;

	if not l_fail then

		select json_agg(t1.priv_name)::text
			into l_privs
			from q_qr_role_to_priv as t1
			where t1.role_name =  p_role_to_use
			;
			-- where t1.role_name =  'role:user' 
		if not found then
			if l_debug_on then
				insert into t_output ( msg ) values ( 'Failed to get the privilages for the user' );
			end if;
			l_fail = true;
			l_data = '{"status":"error","msg":"Unable to get privilages for the user.","code":"0012","location":"m4___file__ m4___line__"}';
			l_privs = '';
		end if;
		if l_debug_on then
			insert into t_output ( msg ) values ( 'calculate l_privs ->'||coalesce(to_json(l_privs)::text,'---null---')||'<-');
		end if;
	end if;

	-- If user has hever logged in and is attempting to register the user again - then delete old user - must have same email.
	-- PERFORM * FROM foo WHERE x = 'abc' AND y = 'xyz';
	-- IF FOUND THEN
	-- 	....
	-- END IF;
	-- , login_success = login_success + 1


-- xyzzyRegister - TODO - 
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
		l_data = '{"status":"error","msg":"Account already exists.  Please login or recover password.","code":"0011","location":"m4___file__ m4___line__"}';
		insert into q_qr_auth_log ( user_id, activity, code, location ) values ( l_bad_user_id, 'User Attempt to Re-Register Same Account.', '0011', 'File:m4___file__ Line No:m4___line__');
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

		insert into q_qr_auth_security_log ( user_id, activity, location ) values ( l_user_id, 'User Registered', 'File:m4___file__ Line No:m4___line__');

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

