
select json_agg(t1.token) as token_list, t1.user_id
	from q_qr_auth_tokens as t1
	group by t1.user_id
	;

