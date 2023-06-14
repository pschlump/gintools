
-- Copyright (C) Philip Schlump, 2008-2023.
-- MIT Licensed.  See LICENSE.mit file.
-- BSD Licensed.  See LICENSE.bsd file.

m4_include(setup.m4)
m4_include(ver.m4)
m4_do_not_edit()

-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Drop Views First
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

drop view if exists q_qr_valid_token ;
drop view if exists q_qr_expired_token ;
drop view if exists q_qr_role_to_priv ;
drop view if exists q_qr_user_to_priv ;
drop view if exists q_qr_valid_tmp_token ;
drop view if exists q_qr_expired_tmp_token ;

-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Drop Tables
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
drop table if exists q_qr_user_pii cascade ;	-- depricated ?? not used ??

drop table if exists q_qr_tmp_tokens cascade ;
drop table if exists q_qr_user_role cascade ;
drop table if exists q_qr_role cascade ;
drop table if exists q_qr_role_priv cascade ;
drop table if exists q_qr_priv cascade ;
drop table if exists q_qr_token_registration cascade ;
drop table if exists q_qr_client cascade ;

drop table if exists q_qr_user_config_default cascade ;
drop table if exists q_qr_saved_state cascade;
drop table if exists q_qr_tmp_token cascade ;
drop table if exists q_qr_track_file cascade;
drop table if exists q_qr_track_by_group cascade;
drop table if exists q_qr_track_by_id cascade;
drop table if exists q_qr_headers cascade;
drop table if exists q_qr_one_time_password cascade;
drop table if exists q_qr_code cascade;
drop table if exists q_qr_auth_tokens cascade ;
drop table if exists q_qr_user_config cascade ;
drop table if exists q_qr_vapid_keys cascade ;
drop table if exists q_qr_users cascade;
drop table if exists q_qr_auth_security_log cascade;
drop table if exists q_qr_auth_log cascade;
drop table if exists q_qr_trace_params ;		-- depricated ?? not used ??
drop table if exists q_qr_config cascade ;
drop table if exists q_qr_manifest_version cascade ;

drop table if exists t_output ;
drop table if exists t_valid_cors_origin ;
drop table if exists q_qr_uploaded_files ;
drop table if exists q_qr_s3_log ;
drop table if exists q_qr_email_log ;
drop table if exists q_qr_validate_startup ;
drop table if exists q_qr_valid_xsrf_id cascade;

drop table if exists q_qr_valid_referer ;
drop table if exists q_qr_valid_xsrf_id ;

ALTER TABLE "q_qr_token_registration" DROP CONSTRAINT "q_qr_token_registration_fk1";
ALTER TABLE "u_valid_state_change"    DROP CONSTRAINT "fk_priv_name__priv__priv_name";

delete from q_qr_user_config_default ;
delete from q_qr_priv cascade;
delete from q_qr_role cascade;
delete from q_qr_role_priv cascade;
delete from q_qr_user_role cascade;

ALTER TABLE q_qr_token_registration
	ADD CONSTRAINT q_qr_token_registration_fk1
	FOREIGN KEY (role_name)
	REFERENCES q_qr_role (role_name)
;

ALTER TABLE u_valid_state_change
    ADD CONSTRAINT fk_priv_name__priv__priv_name
	FOREIGN KEY (priv_name)
	REFERENCES q_qr_priv (priv_name)
;
