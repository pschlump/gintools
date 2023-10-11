delete from t_output;

update q_qr_users
	set 
		  password_reset_token = 'ba4b5530-f002-4395-8159-231fa5a48c22'::uuid
		, password_reset_time = current_timestamp + interval '1 hours'
	where email_hmac = q_auth_v1_hmac_encode ( 'admin@write-it-right.ai', 'y75lR1HeI/gb4nx2ZBe69D/FtZY=' )
	;

select q_auth_v1_recover_password_03_set_password ( 'admin@write-it-right.ai','abcdefghij','ba4b5530-f002-4395-8159-231fa5a48c22','y75lR1HeI/gb4nx2ZBe69D/FtZY=','4Ti5G3HmJsw+gbDbMKKVs4tnRUU=' );

select msg from t_output;

delete from t_output;

update q_qr_users
	set 
		  password_reset_token = 'ba4b5530-f002-4395-8159-231fa5a48c22'::uuid
		, password_reset_time = current_timestamp + interval '1 hours'
	where email_hmac = q_auth_v1_hmac_encode ( 'admin@write-it-right.ai', 'y75lR1HeI/gb4nx2ZBe69D/FtZY=' )
	;
insert into q_qr_n6_email_verify ( n6_token, email_verify_token ) values ( '123456', 'ba4b5530-f002-4395-8159-231fa5a48c22'::uuid );

select q_auth_v1_recover_password_03_set_password ( 'admin@write-it-right.ai','abcdefghij','123456','y75lR1HeI/gb4nx2ZBe69D/FtZY=','4Ti5G3HmJsw+gbDbMKKVs4tnRUU=' );

select msg from t_output;

