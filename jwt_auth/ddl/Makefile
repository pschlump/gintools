
# Makefile for ordering-and building all-sql.sql to re-load the entire system.
# This has the inter-procedure inter-table dependencies in it.

SQL= \
	setup.sql \
	000.setup.sql \
	001.tables.sql \
	004.tcs.sql

all:  pre $(SQL) post

fix_code:
	cp 001.tables.m4.sql /tmp
	./fix-code.pl <001.tables.m4.sql >,a
	cp ,a 001.tables.m4.sql 


pre:
	cat setup.sql >all-sql.sql

post:
	echo "-- all done --" >>all-sql.sql

000.setup.sql: 000.setup.m4.sql setup.m4 
	./m4.sh 000.setup.m4.sql 000.setup.sql

001.tables.sql: 001.tables.m4.sql setup.m4
	./m4.sh 001.tables.m4.sql 001.tables.sql

004.tcs.sql: 004.tcs.m4.sql setup.m4
	./m4.sh 004.tcs.m4.sql 004.tcs.sql

