DO $$
DECLARE
	aid1 uuid;
	aid2 uuid;
	aid3 uuid;
	inv1 uuid;
	inv2 uuid;
BEGIN

	aid1 = uuid_generate_v4();
	aid2 = uuid_generate_v4();
	aid3 = uuid_generate_v4();
	inv1 = uuid_generate_v4();
	inv2 = uuid_generate_v4();

	insert into invoice ( invoice_id, invoice_date, total, tax ) values	
		( inv1, '2020-01-22', 36.00, 36.00*0.07 )
	,	( inv2, '2020-01-23', 90.00, 90.00*0.07 )
	;

	insert into address ( address_id, invoice_id, addr_type, customer_name, address_line1, city, state, zip_code ) values
		( aid1, inv1, 'Billing', 'Mark Devin, LLC', '123 Any Road', 'Laramie', 'WY', '82071' )
	,	( aid2, inv1, 'Shipping', 'Mark Devin, LLC', '123 Any Road', 'Laramie', 'WY', '82071' )
	,	( aid3, inv2, 'Billing', 'Janet Thomas', '12 Main Street', 'Laramie', 'WY', '82071' )
	;

	insert into invoice_line ( line_no, invoice_id, quantity, unit_price, description, extended_price ) values		
		( 1, inv1, 3, 12, 'Widget 1', 36 )
	,   ( 1, inv2, 4, 10, 'Widget 2', 40 )
	,   ( 2, inv2, 4, 12, 'Widget 1', 48 )
	,   ( 3, inv2, 2,  1, 'Widget 4',  2 )
	;

END
$$ LANGUAGE plpgsql;
