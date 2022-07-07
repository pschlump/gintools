




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


drop table if exists tcs_bill_of_lading cascade ;










-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--	- tcs_bill_of_lading
--		bill_of_lading_id 

create table if not exists tcs_bill_of_lading (
	bill_of_lading_id 	serial not null primary key, -- group_n_id in uploaded files.
	group_id			uuid DEFAULT uuid_generate_v4() not null,

	user_data			text,

	updated 			timestamp, 									 		-- Project update timestamp (YYYYMMDDHHMMSS timestamp).
	created 			timestamp default current_timestamp not null 		-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);

create index tcs_bill_of_lading_p1 on tcs_bill_of_lading using hash ( group_id );



CREATE OR REPLACE function tcs_bill_of_lading_upd()
RETURNS trigger AS $$
BEGIN
	-- version: 5e83aa840f7efdaf7572ff4b507bc811c966c882 tag: v1.0.2 build_date: Wed Jul  6 12:32:59 MDT 2022
	NEW.updated := current_timestamp;
	RETURN NEW;
END
$$ LANGUAGE 'plpgsql';


CREATE TRIGGER tcs_bill_of_lading_trig
BEFORE update ON "tcs_bill_of_lading"
FOR EACH ROW
EXECUTE PROCEDURE tcs_bill_of_lading_upd();














--- 
--- -- stmt := "insert into q_qr_uploaded_fiels ( id, original_file_name, content_type, size ) values ( $1, $2, $3, $4 )"
--- drop table if exists q_qr_uploaded_files ;
--- CREATE TABLE if not exists q_qr_uploaded_files (
--- 	id					uuid DEFAULT uuid_generate_v4() not null primary key,
--- 	group_id			uuid,				-- a user specified ID to join to anotehr table.
--- 	group_n_id			int, 
--- 	original_file_name	text not null,
--- 	content_type		text not null default 'text/plain',
--- 	size 				int not null default 0,
--- 	file_hash			text,
--- 	url_path			text,
--- 	local_file_path		text
--- );
--- 

