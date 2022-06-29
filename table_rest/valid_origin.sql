CREATE TABLE t_valid_cors_origin (
	  "id"		uuid DEFAULT uuid_generate_v4() not null primary key
	, "valid" 	text not null
	, "updated" 			timestamp
	, "created" 			timestamp default current_timestamp not null
);
