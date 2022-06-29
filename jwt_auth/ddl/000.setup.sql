
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


-- Setup for install

drop view if exists q_qr_valid_token ;
drop table if exists q_qr_track_file cascade;
drop table if exists q_qr_track_by_group cascade;
drop table if exists q_qr_track_by_id cascade;
drop table if exists q_qr_code cascade;
drop table if exists q_qr_auth_tokens cascade ;
drop table if exists q_qr_users cascade;
drop table if exists q_qr_headers cascade;
