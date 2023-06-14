
-- Copyright (C) Philip Schlump, 2008-2023.
-- MIT Licensed.  See LICENSE.mit file.
-- BSD Licensed.  See LICENSE.bsd file.





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
insert into q_qr_valid_xsrf_id ( xsrf_id ) values ( '9ca5c33f-c6b2-4a38-aa99-470135aa81a4'::uuid );

-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
delete from q_qr_valid_referer ;
insert into q_qr_valid_referer ( referer ) values 
	  ( 'http://localhost:8080/' )
	, ( 'http://localhost:9080/' )
	, ( 'http://127.0.0.1:8080/' )
	, ( 'http://192.168.1.1:8080/' )
	, ( 'http://192.168.1.2:8080/' )
	, ( 'http://127.0.0.1:9080/' )
	, ( 'http://localhost:[0-9][0-9]*' )
	, ( 'https://localhost:[0-9][0-9]*' )
On CONFLICT(referer) DO NOTHING
;


-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
insert into t_valid_cors_origin ( valid ) values
	  ( 'http://localhost:[0-9][0-9]*' )
	, ( 'https://localhost:[0-9][0-9]*' )
	;


-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
insert into q_qr_user_config_default ( role_name, value ) values 
	  ( 'role:user', 				'{"display-mode":"light","show-upload-button":"hide" }'::jsonb )
	, ( 'role:client-user', 		'{"display-mode":"light"}'::jsonb )
	, ( 'role:client-admin', 		'{"display-mode":"light"}'::jsonb )
On CONFLICT(role_name) DO NOTHING
;

-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
insert into q_qr_config ( name, value, b_value ) values
	  ( 'debug', 'yes', true )
	, ( 'trace', 'yes', true )
	, ( 'config.test', 'yes', true )
	, ( 'use.2fa', 'yes', true )
On CONFLICT(name) DO NOTHING
;

