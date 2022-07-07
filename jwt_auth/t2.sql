
drop function q_auth_v1_hmac_encode_email ( p_email varchar, p_hmac_password varchar );

create or replace function q_auth_v1_hmac_encode2 ( p_email varchar, p_hmac_password varchar )
	returns bytea
	as $$
DECLARE
	l_data					bytea;
BEGIN
	l_data = hmac(p_email, p_hmac_password, 'sha256');
	RETURN l_data;
END;
$$ LANGUAGE plpgsql;


create table if not exists test_a (
	id int primary key
	, name text
	, val bytea
);
insert into test_a ( id, name ) values
	  ( 12, 'Mr 12' )
	, ( 22, 'Miss 22' )
	, ( 32, 'Xxx 32' )
;



DO $$
DECLARE
	l_code bytea;
BEGIN
	l_code = q_auth_v1_hmac_encode2 ( 'bob@bob.com', 'a passwrod test' );
	update test_a
		set val = l_code
		where id = 22;
END;
$$ LANGUAGE plpgsql;

select * from test_a;

drop table if exists test_a;

drop function q_auth_v1_hmac_encode2 ( p_email varchar, p_hmac_password varchar );
