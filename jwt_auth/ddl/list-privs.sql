select t1.user_id, t5.priv_name
	from q_qr_users as t1
		join q_qr_user_role as t2  on ( t1.user_id = t2.user_id )
		join q_qr_role as t3       on ( t2.role_id = t3.role_id )
		join q_qr_role_priv as t4  on ( t3.role_id = t4.role_id )
		join q_qr_priv as t5       on ( t4.priv_id = t5.priv_id )
	order by t1.user_id
;
select user_id, priv_name 
	from q_qr_user_to_priv
;
