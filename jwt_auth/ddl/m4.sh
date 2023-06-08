
HD=$( git rev-list -1 HEAD )
TAG=$( git tag | sort -t "." -k1,1n -k2,2n -k3,3n | tail -1 )
DT=$( date )

cat >ver.m4 <<XXxx
m4_define([[[m4_ver_version]]],[[[${HD}]]])m4_dnl
m4_define([[[m4_ver_tag]]],[[[${TAG}]]])m4_dnl
m4_define([[[m4_ver_date]]],[[[${DT}]]])m4_dnl
XXxx
	
#-- version: m4_ver_version() tag: m4_ver_tag() build_date: m4_ver_date()

#m4 -P random_string.m4.sql >random_string.sql

m4 -P $1 > $2

cat $2 >>all-sql.sql

