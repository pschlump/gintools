#!/bin/bash

# Copyright (C) Philip Schlump, 2010.
# This file is MIT Licnesed.

#
# Overall Goal:
# Given a list of stored procedure names use `psql`/PostgreSQL, `git` and files to
# check the installed vesion versus the actual code version of:
#		1. Stored Procedures
#		2. Trigger Functions
# Make a list to upgrade or report "current".
#
# Question: should a vesion difference result in a "source compare"?
# Question: should we look in "git" to see when/iff version is older newer?
#

# create or replace function u_agree_eula ( p_agree_eula varchar, p_user_id uuid, p_hmac_password varchar, p_userdata_password varchar )

proc="$1"

psql >,,bb <<XXxx
SELECT prosrc FROM pg_proc WHERE proname = '${proc}';
XXxx

ver1=$(grep version: ,,bb)

fn=$( grep "${proc}" 008.func.sql | grep "create or replace function ${proc}" | sed -e 's/:.*$//' )

echo "ver=${ver1}"

echo "fn=${fn}"

/usr/bin/perl >,,cc <<XXxx

\$st = 1;

open(FH, '<', '${fn}');

while ( <FH> ) {
	if ( \$st == 1 && /^create or replace function ${proc} /) {
		\$st = 2;
	} elsif ( \$st == 2 && /-- version:/ ) {
		print \$_;
		\$st = 3;
	}
}

XXxx


ver1=$(echo "$ver1" | sed -e 's/.*--/--/' )
ver2=$(cat ,,cc | sed -e 's/.*--/--/' )

echo "loaded version=${ver1}"
echo "file   version=${ver2}"

t1=$( echo "$ver1" | awk '{print $3}' )
t2=$( echo "$ver2" | awk '{print $3}' )

if [ "$t1" == "$t2" ] ; then
	echo "Versions Match: PASS" | color-cat -c green
else
	echo "Did Not Match: Load New Vesion" | color-cat -c red
fi
