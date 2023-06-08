#!/usr/bin/perl

# Copyright (C) Philip Schlump, 2010.
# This file is MIT Licnesed.

$st = 1;

while ( <> ) {
	if ( $st == 1 && /create or replace function u_agree_eula /) {
		$st = 2;
	} elsif ( $st == 2 && /-- version:/ ) {
		print $_;
		$st = 3;
	}
}
