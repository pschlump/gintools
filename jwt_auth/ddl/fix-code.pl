#!/usr/bin/perl

my($base);

while ( <> ) {
	if ( /-- \$code\$ [0-9]000/ ) {
		chomp;
		$x = $_;
		$x =~ s/-- \$code\$ //;
		$base = $x;
		# print ( "base ->$base<-\n" );
		print ( "$_\n" );
	} elsif ( /"code": *"[0-9][^"]*"/ ) {
		chomp;
		# print ( "Original: ->$_<-\n" );
		$x = $_;
		$x =~ s/"code": *"[0-9][^"]*"/"code":"$base"/;
		# print ( "Modified: ->$x<-\n" );
		$base++;
		print ( "$x\n" );
	} else {
		print ( "$_" );
	}
}

