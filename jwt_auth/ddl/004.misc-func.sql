
-- Copyright (C) Philip Schlump, 2008-2023.
-- MIT Licensed.  See LICENSE.mit file.
-- BSD Licensed.  See LICENSE.bsd file.

--
-- SELECT * FROM q_qr_get_all_users 
--

--
-- QueryString: 
-- SELECT
-- 	  t1.user_id
--     , pgp_sym_decrypt(t1.email_enc,$1)::text as email
--     , pgp_sym_decrypt(t1.first_name_enc,$1)::text as first_name
--     , pgp_sym_decrypt(t1.last_name_enc,$1)::text as last_name
-- FROM q_qr_users as t1
--

-- CREATE OR REPLACE function q_auth_v1_xsrf_setup ( p_id uuid, p_ref varchar, p_hmac_password varchar, p_userdata_password varchar )

delete from t_output;

drop function q_qr_get_all_users ( p_hmac_password varchar );




CREATE OR REPLACE FUNCTION q_qr_get_all_users ( p_userdata_password varchar ) returns table (
		user_id uuid,
		email text,
		first_name text,
		last_name text
	)
as $$
declare 
	r0 record;
	l_data text;
begin
	FOR r0 IN SELECT t0.user_id from q_qr_users as t0
	LOOP
		begin
			RETURN QUERY 
				SELECT
					  t1.user_id
					, pgp_sym_decrypt(t1.email_enc, p_userdata_password)::text as email
					, pgp_sym_decrypt(t1.first_name_enc, p_userdata_password)::text as first_name
					, pgp_sym_decrypt(t1.last_name_enc, p_userdata_password)::text as last_name
				FROM q_qr_users as t1
				where t1.user_id = r0.user_id
				;
			insert into t_output ( msg ) values ( success on: '||r0.user_id::text );
		EXCEPTION WHEN others THEN
			insert into t_output ( msg ) values ( 'error on: '||r0.user_id::text );
			-- raise;
			if False then
				select q_auth_v1_delete_user ( r0.user_id ) into l_data;
			end if;
		END;
	END LOOP;
end;
$$ LANGUAGE plpgsql;





select * from q_qr_get_all_users ( 'user info password' );

select msg from t_output order by seq;

/* 
From Production:
psql:,004.sql:24: ERROR:  function q_qr_get_all_users(character varying) does not exist
CREATE FUNCTION
               user_id                |      email       | first_name |  last_name
--------------------------------------+------------------+------------+-------------
 5aa01480-56b1-42b3-9558-36fd7ee54a2a | bob@example.com  | Bob        | the Builder
 7967d676-1ae0-4971-88d8-28ae3970a1b5 | bob2@example.com | Bob        | the Builder
(2 rows)

                       msg
--------------------------------------------------
 error on: ceaf828d-d328-458b-b41f-521d6e7f8176
 error on: f36aee9e-a4fc-47b3-ba0a-42a6c6440cbf
 success on: 5aa01480-56b1-42b3-9558-36fd7ee54a2a
 error on: b2a1049c-1ba6-4d89-bfd1-a088196ce992
 error on: 90c8c408-ba9b-49b1-b975-bc9babd54fdc
 error on: 4acee1e8-c96d-4529-b8d0-e2e52cba5896
 error on: 3290fa4e-60d9-4b38-b4fa-407033227693
 error on: dee25410-babf-4c99-8e02-49b68d7e2cb2
 success on: 7967d676-1ae0-4971-88d8-28ae3970a1b5
 error on: 5ca843e3-921f-42a1-a213-5b687aad526b
 error on: 56cd2aaa-a6d5-4c2d-a0dd-3642ea878a88
 error on: d9093457-7b02-49c4-b0ab-e1d0ab75b647
(12 rows)
*/
