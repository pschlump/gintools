
-- BSD 3 Clause Licensed.  See LICENSE.bsd

--	2. qr_code table - config for a QR
--	3. qr_track_by_id
--	3. qr_track_by_group


drop table if exists q_qr_code ;
create table if not exists q_qr_code (
	qr_code_id 			serial not null primary key,
	qr_type				varchar(30) not null default 'redirect' check ( qr_type in ( 'unknown', 'redirect', 'proxy', 'direct' ) ),
	qrid10				varchar(10) not null,
	body				text not null,		-- what is encoded in the QR
	file_name			text not null,		-- local relative file name
	url_name			text not null,		-- URL path to file
	owner_user_id		int,
	group_id			int,
	redirect_to			text,
	full_text_search 	tsvector,			-- TODO - add trigger and populate from split of body.
	encoding 			varchar(30) not null default 'text',
	img_size 			int not null default 256,
	redundancy			varchar(1) default 'M' check ( redundancy in ( 'M', 'H', 'L' ) ) not null,
	invert				varchar(1) default 'r' check ( invert in ( 'r', 'i' ) ) not null,
	direct				varchar(15) default 'proxy' check ( direct in ( 'direct', 'proxy' ) ) not null,
	add_ran				text default '' not null,									 		-- if not "", then add this as a random value to destination 
	updated 			timestamp, 									 						-- Project update timestamp (YYYYMMDDHHMMSS timestamp).
	created 			timestamp default current_timestamp not null 						-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);


