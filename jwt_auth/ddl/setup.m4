m4_divert(`-1')

m4_changequote(`[[[', `]]]')

m4_define([[[m4_coverage_point]]],[[[]]])

m4_define([[[m4_namespace]]],[[[q_qr]]])

m4_define([[[m4_foreach]]],[[[m4_ifelse(m4_eval($#>2),1,m4_dnl
[[[m4_pushdef([[[$1]]],[[[$3]]])$2[[[]]]m4_popdef([[[$1]]])m4_dnl
[[[]]]m4_ifelse(m4_eval($#>3),1,[[[$0([[[$1]]],[[[$2]]],m4_shift(m4_shift(m4_shift($@))))]]])]]])]]])
m4_define([[[m4_cat]]],[[[m4_foreach([[[x]]],[[[x]]],$@)]]])

m4_define([[[m4_fileno]]],99)
m4_define([[[m4_file_cnt]]],100)
m4_define([[[m4_code]]],m4_dnl
[[[m4_cat(m4_fileno(),m4_file_cnt()[[[]]]m4_define([[[m4_file_cnt]]],m4_incr(m4_file_cnt)))]]])

m4_define([[[m4_uuid_type]]],[[[uuid]]])

m4_define([[[m4_do_not_edit]]],[[[
-- -----------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------
-- 
--  Do not edit this .sql file - it is a generated output of m4 macro processor
--  Do not edit this .sql file - it is a generated output of m4 macro processor
--  Do not edit this .sql file - it is a generated output of m4 macro processor
--  Do not edit this .sql file - it is a generated output of m4 macro processor
-- 
-- -----------------------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------------------
]]])

m4_define([[[m4_comment]]],[[[]]])

m4_define([[[m4_updTrig]]],[[[

CREATE OR REPLACE FUNCTION $1_upd() RETURNS trigger 
AS $$
BEGIN
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	NEW.updated := current_timestamp;
	RETURN NEW;
END
$$ LANGUAGE 'plpgsql';

DROP TRIGGER if exists $1_trig
	ON "$1"
	;

CREATE TRIGGER $1_trig
	BEFORE update ON "$1"
	FOR EACH ROW
	EXECUTE PROCEDURE $1_upd()
	;

]]])

m4_define([[[m4_noDelTrig]]],[[[

CREATE OR REPLACE FUNCTION $1_no_del() RETURNS trigger 
AS $$
BEGIN            
	-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()
	RAISE EXCEPTION 'cannot delete rows from $1';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER if exists $1_no_del
	ON "$1"
	;

CREATE TRIGGER $1_no_del 
	BEFORE DELETE ON "$1"
	FOR EACH ROW
	EXECUTE PROCEDURE check_del_cat()
	;

]]])






m4_comment([[[ -----------------------------------------------------------------------------------------------

This takes 2 parameters....

1. The table Name - this is the table that has the values.
2. The column name - that we will look for the max in.

The sequence is <<table_name>>_<<column_name>>_seq

]]])
m4_define([[[m4_updateSeq]]],[[[

-- Reset the sequence to 1
ALTER SEQUENCE $1_$2_seq RESTART;
SELECT nextval('$1_$2_seq');

-- Login to psql and run the following

-- What is the result?
SELECT MAX($2) FROM $1;

-- Then run...
-- This should be higher than the last result.
SELECT nextval('$1_$2_seq');

-- If it's not higher... run this set the sequence last to your highest id.
-- (wise to run a quick pg_dump first...)

BEGIN;
-- protect against concurrent inserts while you update the counter
LOCK TABLE $1 IN EXCLUSIVE MODE;
-- Update the sequence
SELECT setval('$1_$2_seq', COALESCE((SELECT MAX($2)+1 FROM $1), 1), false);
COMMIT;

-- Validate the sequence at the end.
SELECT nextval('$1_$2_seq');

]]])

m4_divert[[[]]]
