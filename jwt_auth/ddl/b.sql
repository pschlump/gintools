
select pgp_sym_encrypt('bob@truckcoinswap.com', 'Think Pink Ink 8877');
select pgp_sym_decrypt(pgp_sym_encrypt('bob@truckcoinswap.com' , 'Think Pink Ink 8877') , 'Think Pink Ink 8877');

