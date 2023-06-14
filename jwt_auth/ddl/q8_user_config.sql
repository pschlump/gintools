

--			into l_user_config
--create table if not exists q_qr_user_config (
--	config_id 				uuid default uuid_generate_v4() not null primary key,
--	user_id 				uuid not null,
--	name					text not null,
--	item_type				varchar(1) default 's' not null check ( item_type in ( 's', 'b', 'i', 'f', 't' ) ),
--			where t1.user_id = l_user_id

		select
				json_agg(
					json_build_object(
						'config_id', config_id,
						'name', name,
						'value', value
					)
				)::text as data
			from q_qr_user_config as t1
			where t1.user_id = '71fee0ec-5697-4d45-9759-5a6db492adc1'::uuid
			;
