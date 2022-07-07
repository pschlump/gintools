
create table if not exists test_a (
	id int primary key
	, name text
	, val text
);
insert into test_a ( id, name ) values
	  ( 12, 'Mr 12' )
	, ( 22, 'Miss 22' )
	, ( 32, 'Xxx 32' )
;

create or replace function test_0000 ( p_name varchar, p_value varchar )
	returns text
	as $$
DECLARE
	l_data			text;
	l_id			int;
BEGIN
	l_data = 'ok';
	select id
		into l_id
		from test_a
		where name = p_name
		for update
		;
	update test_a
		set val = p_value
		where id = l_id
		;
	return l_data;
END;
$$ LANGUAGE plpgsql;

select 'before', * from test_a;

select test_0000 ( 'Mr 12'::text, 'bob'::text );

select 'after', * from test_a;

drop table if exists test_a;


