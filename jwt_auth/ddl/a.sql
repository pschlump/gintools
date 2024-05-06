SELECT
    json_agg(t1)
FROM (
	select name, value
	from q_qr_user_config
) as t1
;
