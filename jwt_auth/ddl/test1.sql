select * 
	from q_qr_users
	where email_address = encode(hmac('testAcct2@email.com', 'my-long-secret', 'sha256'), 'hex')
	;
insert into q_qr_auth_tokens ( user_id, token )
	select user_id, uuid_generate_v4()
	from q_qr_users
	where email_address = encode(hmac('testAcct2@email.com', 'my-long-secret', 'sha256'), 'hex')
	;
select * from q_qr_auth_tokens;

