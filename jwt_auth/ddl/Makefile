
# Makefile for ordering-and building all-sql.sql to re-load the entire system.
# This has the inter-procedure inter-table dependencies in it.

SQL= \
	setup.sql \
	000.setup.sql \
	000.drop.sql \
	001.tables.sql \
	002.data.sql  \
	004.misc-func.sql \
	003.test.sql 

all:  pre $(SQL) post

# Old - uses m4 macro now
#fix_code:
#	cp 001.tables.m4.sql /tmp
#	./fix-code.pl <001.tables.m4.sql >,a
#	cp ,a 001.tables.m4.sql 


pre:
	cat setup.sql >all-sql.sql

post:
	echo "-- all done --" >>all-sql.sql

000.setup.sql: 000.setup.m4.sql setup.m4 
	./m4.sh 000.setup.m4.sql 000.setup.sql

000.drop.sql: 000.drop.m4.sql setup.m4 
	./m4.sh 000.drop.m4.sql 000.drop.sql

001.tables.sql: 001.tables.m4.sql setup.m4
	./m4.sh 001.tables.m4.sql 001.tables.sql

002.data.sql: 002.data.m4.sql setup.m4
	./m4.sh 002.data.m4.sql 002.data.sql

003.test.sql: 003.test.m4.sql setup.m4
	./m4.sh 003.test.m4.sql 003.test.sql

004.misc-func.sql: 004.misc-func.m4.sql setup.m4
	./m4.sh 004.misc-func.m4.sql 004.misc-func.sql

TO_SVR= \
	001.tables.m4.sql \
	001.tables.sql \
	002.data.sql \
	003.test.sql \
	004.create-setup.sql

deploy:
	scp $(TO_SVR) 	philip@peach.com:/tmp

deploy_tgo:
	scp 	tgo_004_create_setup.sh philip@peach.com:/tmp

deploy_app: all
	scp 000.setup.sql 001.tables.sql 002.test.sql  \
		deploy_app.sh ./deploy_db_app.sh \
		philip@peach.com:/home/philip/tmp


deploy_test01: all
	scp 000.setup.sql 001.tables.sql 002.test.sql  \
		deploy_test01.sh ./deploy_db_test01.sh \
		philip@peach.com:/home/philip/tmp



deploy_test02: all
	scp 000.setup.sql 001.tables.sql 002.test.sql  \
		deploy_test02.sh ./deploy_db_test02.sh \
		philip@peach.com:/home/philip/tmp


new_db:
	psql --dbname=qr0 <setup.sql >out1.lst 2>&1
	psql --dbname=qr0 <001.test.sql >out1.lst 2>&1
