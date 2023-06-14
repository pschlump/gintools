delete from "t_ymux_user" where "username" in ( 'app.example.com:def' );
insert into "t_ymux_user" ( "id", "username", "password", "salt", "default_image", "default_title", "email", "email_confirmed", "realm" ) values
  ( '8510a891-899f-4904-59ed-23bc6b52821d', 'app.example.com:def',
	'fc83d9761bac68264130ed0f8f3c9cfbf42c66bb978d677f8bc0d8e559082996d3d061beca0552ea7d9a9135fd69c27d946ccde26cf4e588f3ee8ae037f4c249',
	'3534393831313436', 'top-img.png', 'Country Product', 'pschlump@gmail.com', 'y', 'app.example.com' )
;
