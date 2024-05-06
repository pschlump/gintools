
-- Copyright (C) Philip Schlump, 2008-2023.
-- MIT Licensed.  See LICENSE.mit file.
-- BSD Licensed.  See LICENSE.bsd file.

-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Tests
-- Tests
-- Tests
-- Tests
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

m4_comment([[[

-- $code$ 2000

-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--
-- UUID Version
--
-- convert user_id to uuid! (remove sequences)
-- "18207657-b420-445a-aea5-6c061ffa1e89",
-- "e35940af-720c-4438-be52-36e8f8367398",
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

-- xyzzy400 - must create user with with this user_id!

-- xyzzyRegister - TODO -  Question is how to re-register a user that failed in the middle of registraiton.
	-- same UN / PW => update instead of insert. (do an upsert?)  - if not validated?

-- xyzzyWhy - Why are there users at this point?

-- xyzzy - TODO xyzzy889900 - add / remove priv from user.  In Dev.
	-- add remove role
	-- create role with list of privs
	-- remove priv from role

-- xyzzy - TODO test
--	CREATE OR REPLACE function q_auth_v1_register_token ( p_email varchar, p_pw varchar, p_hmac_password varchar, p_first_name varchar, p_last_name varchar, p_userdata_password varchar, p_secret varchar, p_registration_token uuid )
--	CREATE OR REPLACE function q_auth_v1_register_admin ( p_email varchar, p_pw varchar, p_hmac_password varchar, p_first_name varchar, p_last_name varchar, p_userdata_password varchar, p_secret varchar, p_admin_password varchar, p_specifed_role_name varchar, p_admin_user_id uuid )

select q_auth_v1_xsrf_setup ( '5e0026a0-e04b-4e45-67d8-9ff7f37f7d66','http://localhost:8080/home','my long secret password','user info password' );

]]])

-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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
		insert into t_output ( msg ) values ( 'FAILED - registraiton test 1 - failed to create a user File:m4___file__ Line No:m4___line__' );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED - registraiton test 1 - failed to create a user File:m4___file__ Line No:m4___line__' );
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
		insert into t_output ( msg ) values ( 'FAILED - registraiton test 2 - login when should not File:m4___file__ Line No:m4___line__' );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED - registraiton test 2 - login when should not File:m4___file__ Line No:m4___line__' );
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
		insert into t_output ( msg ) values ( 'FAILED - registraiton test 3 - validation of email File:m4___file__ Line No:m4___line__' );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED - registraiton test 3 - validation of email File:m4___file__ Line No:m4___line__' );
	else
		insert into t_output ( msg ) values ( 'PASS - registraiton test 3 - validation of email' );
		insert into x_tmp_pass_fail ( name ) values ( 'PASS - registraiton test 3 - validation of email' );
	end if;


	-- CREATE OR REPLACE function q_auth_v1_validate_2fa_token ( p_email varchar, p_tmp_token varchar, p_2fa_secret varchar, p_hmac_password varchar, p_userdata_password varchar )
	select q_auth_v1_validate_2fa_token ( 'bob@example.com', l_tmp_token, l_2fa_secret, 'my long secret password', 'user info password' )
		into l_text;
	insert into t_output ( msg ) values ( l_text );
	select l_text::jsonb -> 'status' into l_status;
	if l_status != '"success"' then
		insert into t_output ( msg ) values ( 'FAILED - registraiton test 3 - validation of email File:m4___file__ Line No:m4___line__' );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED - registraiton test 3 - validation of email File:m4___file__ Line No:m4___line__' );
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
		insert into t_output ( msg ) values ( 'FAILED - registraiton test 5 - faile to login - bad password File:m4___file__ Line No:m4___line__' );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED - registraiton test 5 - faile to login - bad password File:m4___file__ Line No:m4___line__' );
	end if;

	select q_auth_v1_login ( 'bob82@example.com', 'bob the builder', '181d4e23-9595-47ec-9a26-1c8313d321f9', 'my long secret password', 'user info password' )
		into l_text;
	insert into t_output ( msg ) values ( l_text );
	select l_text::jsonb -> 'status' into l_status;
	if l_status != '"success"' then
		insert into t_output ( msg ) values ( 'PASS - registraiton/login test 5 - bad username'  );
		insert into x_tmp_pass_fail ( name ) values ( 'PASS - registraiton/login test 5 - bad username' );
	else
		insert into t_output ( msg ) values ( 'FAILED - registraiton test 5 - faile to login - bad username File:m4___file__ Line No:m4___line__' );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED - registraiton test 5 - faile to login - bad username File:m4___file__ Line No:m4___line__' );
	end if;



	-- ----------------------------------------------------------------------------------------------------------------------------
	-- Now login should work.
	-- ----------------------------------------------------------------------------------------------------------------------------
	select q_auth_v1_login ( 'bob@example.com', 'bob the builder', '181d4e23-9595-47ec-9a26-1c8313d321f9', 'my long secret password', 'user info password' )
		into l_text;
	insert into t_output ( msg ) values ( l_text );
	select l_text::jsonb -> 'status' into l_status;
	if l_status != '"success"' then
		insert into t_output ( msg ) values ( 'FAILED - registraiton test 5 - faile to login File:m4___file__ Line No:m4___line__' );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED - registraiton test 5 - faile to login File:m4___file__ Line No:m4___line__' );
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
		insert into t_output ( msg ) values ( 'FAILED - q_admin_HasPriv test 1 File:m4___file__ Line No:m4___line__' );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED - q_admin_HasPriv test 1 File:m4___file__ Line No:m4___line__' );
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
		insert into t_output ( msg ) values ( 'FAILED - q_admin_HasPriv test 2 File:m4___file__ Line No:m4___line__' );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED - q_admin_HasPriv test 2 File:m4___file__ Line No:m4___line__' );
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
	l_privilege text;
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
		insert into t_output ( msg ) values ( 'Test Failed: File:m4___file__ Line No:m4___line__ -- missing data in q_qr_role' );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	select count(1) into l_cnt1 from q_qr_priv;
	if l_cnt1 = 0 then
		insert into t_output ( msg ) values ( 'Test Failed: File:m4___file__ Line No:m4___line__ -- missing data in q_qr_priv' );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	select count(1) into l_cnt1 from q_qr_role_priv;
	if l_cnt1 = 0 then
		insert into t_output ( msg ) values ( 'Test Failed: File:m4___file__ Line No:m4___line__ -- missing data in q_qr_role_priv' );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	select count(1) into l_cnt1 from q_qr_user_role;
	if l_cnt1 = 0 then
		insert into t_output ( msg ) values ( 'Test Failed: File:m4___file__ Line No:m4___line__ -- missing data in q_qr_user_role' );
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
		insert into t_output ( msg ) values ( 'Test Failed: File:m4___file__ Line No:m4___line__ -- config not working' );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	update q_qr_config set b_value = true, value = 'yes' where name = 'config.test';
	GET DIAGNOSTICS v_cnt = ROW_COUNT;
	if v_cnt != 1 then
		insert into t_output ( msg ) values ( 'Test Failed: File:m4___file__ Line No:m4___line__ -- config not working' );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	l_bool = q_get_config_bool ( 'config.test' );
	if l_bool = false then
		insert into t_output ( msg ) values ( 'Test Failed: File:m4___file__ Line No:m4___line__ -- config not working' );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	l_bool = q_get_config_bool ( 'missing.test' );
	if l_bool != false then
		insert into t_output ( msg ) values ( 'Test Failed: File:m4___file__ Line No:m4___line__ -- config not working' );
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
		insert into t_output ( msg ) values ( 'Test Failed: File:m4___file__ Line No:m4___line__ -- failed to register, expected ->"success"<- got ->'||l_status||'<-' );
		insert into t_output ( msg ) values ( '   '||l_r1 );
		l_fail = true;
		n_err = n_err + 1;
	end if;
	if l_cnt1 >= l_cnt2 then
		insert into t_output ( msg ) values ( 'Test Failed: File:m4___file__ Line No:m4___line__ -- failed to register new user.  Row count did not increase.' );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	select l_r1::jsonb ->> 'email_verify_token' into l_email_verify_token;
	-- l_email_verify_token = replace ( l_email_verify_token, '"', '' );
	insert into t_output ( msg ) values ( 'l_email_verify_token = '||coalesce(l_email_verify_token,'--null--') );


	-- new -----------------------------------------------------------------------------------------------------------------------------------------

	select count(1) into l_cnt1 from q_qr_user_role;
	if l_cnt1 = 0 then
		insert into t_output ( msg ) values ( 'Test Failed: File:m4___file__ Line No:m4___line__ -- missing data in q_qr_user_role' );
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
		insert into t_output ( msg ) values ( 'Missing - no auth_tokens: File:m4___file__ Line No:m4___line__ -- missing data in q_qr_user_role' );
	end if;

	-- end -----------------------------------------------------------------------------------------------------------------------------------------


	select l_r1::jsonb ->> 'secret_2fa' into l_secret_2fa;
	-- l_secret_2fa = replace ( l_secret_2fa, '"', '' );
	insert into t_output ( msg ) values ( 'l_secret_2fa = '||coalesce(l_secret_2fa,'---null---') );

	select l_r1::jsonb ->> 'user_id' into l_user_id_str;
	insert into t_output ( msg ) values ( 'l_user_id = '||coalesce(to_json(l_user_id_str)::text,'---null---') );

	select count(1) into l_cnt_auth_tokens;
	if not found or l_cnt_auth_tokens = 0 then
		insert into t_output ( msg ) values ( 'Missing - no auth_tokens: File:m4___file__ Line No:m4___line__ -- missing data in q_qr_user_role' );
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
		insert into t_output ( msg ) values ( 'Test Failed: File:m4___file__ Line No:m4___line__ -- failed to create user' );
		l_fail = true;
		n_err = n_err + 1;
	end if;
	select count(1) into l_cnt_auth_tokens;
	if not found or l_cnt_auth_tokens = 0 then
		insert into t_output ( msg ) values ( 'Missing - no auth_tokens: File:m4___file__ Line No:m4___line__ -- missing data in q_qr_user_role' );
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
		insert into t_output ( msg ) values ( 'FAILED - registraiton validate email - validation of email File:m4___file__ Line No:m4___line__' );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED - registraiton validate email - validation of email File:m4___file__ Line No:m4___line__' );
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
		insert into t_output ( msg ) values ( 'FAILED - registraiton validate 2fa - validation of email File:m4___file__ Line No:m4___line__' );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED - registraiton validate 2fa - validation of email File:m4___file__ Line No:m4___line__' );
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
		insert into t_output ( msg ) values ( 'FAILED - registraiton test 5 - faile to login File:m4___file__ Line No:m4___line__' );
		insert into x_tmp_pass_fail ( name ) values ( 'FAILED - registraiton test 5 - faile to login File:m4___file__ Line No:m4___line__' );
	else
		insert into t_output ( msg ) values ( 'PASS - registraiton/login test 5' );
		insert into x_tmp_pass_fail ( name ) values ( 'PASS - registraiton/login test 5' );
	end if;



-- xyzzy - verify no auth_token returned.
-- xyzzy - verify that we get a 2fa required.


	select count(1) into l_cnt_auth_tokens;
	if not found or l_cnt_auth_tokens = 0 then
		insert into t_output ( msg ) values ( 'Missing - no auth_tokens: File:m4___file__ Line No:m4___line__ -- missing data in q_qr_user_role' );
	end if;

	-- test 1a ----------------------------------------------------------------------------------------------------------
	-- Validate the Privileges (Roles) on user
	-- Check Privs - Verify that "user" role is setup for this user. that privileges is set.

	-- select 'should be ''f''';
	select q_amdin_HasPriv ( l_user_id, 'May X' )
		into l_bool;
	if l_bool != false then
		insert into t_output ( msg ) values ( 'Test Failed: File:m4___file__ Line No:m4___line__ -- return true on non-existent privilege.  user_id='||l_user_id::text );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	-- select 'should be ''t''';
	select q_amdin_HasPriv ( l_user_id, 'May Change Password' )
		into l_bool;
	if l_bool != true then
		insert into t_output ( msg ) values ( 'Test Failed: File:m4___file__ Line No:m4___line__ -- return false on privilege that should exist.  user_id='||l_user_id::text );
		l_fail = true;
		n_err = n_err + 1;
	end if;

	select count(1) into l_cnt_auth_tokens;
	if not found or l_cnt_auth_tokens = 0 then
		insert into t_output ( msg ) values ( 'Missing - no auth_tokens: File:m4___file__ Line No:m4___line__ -- missing data in q_qr_user_role' );
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
	l_privilege text;
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
		)
		;
						-- where email_hmac = q_auth_v1_hmac_encode ( 'bob0@bob.com', 'bob' )
						-- where email_hmac = q_auth_v1_hmac_encode ( 'bob2@example.com', 'my long secret password' )

	if l_cnt2 != 2 then
		insert into t_output ( msg ) values ( 'Test Failed: File:m4___file__ Line No:m4___line__ -- should have 2 roles - got:'||l_cnt2::text );
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
		insert into t_output ( msg ) values ( 'Test Failed: File:m4___file__ Line No:m4___line__ -- missing data in x_tmp_values, key=''l_auth_token'' -no rows found-' );
		l_fail = true;
		n_err = n_err + 1;
	end if;
	insert into t_output ( msg ) values ( 'l_auth_token = '||l_auth_token );

	select t1.user_id as "user_id", json_agg(t3.priv_name)::text as "privileges"
		into l_user_id, l_privilege
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
		insert into t_output ( msg ) values ( 'Test Failed: File:m4___file__ Line No:m4___line__ -- missing data in role/priv/token -no rows found-' );
		l_fail = true;
		n_err = n_err + 1;
	end if;
	if l_privilege::text = '[null]' then
		insert into t_output ( msg ) values ( 'Test Failed: File:m4___file__ Line No:m4___line__ -- missing data in role/priv/token - bad user id' );
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



