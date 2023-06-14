
-- Copyright (C) Philip Schlump, 2008-2023.
-- MIT Licensed.  See LICENSE.mit file.
-- BSD Licensed.  See LICENSE.bsd file.

ALTER TABLE q_qr_token_registration
	ADD CONSTRAINT q_qr_token_registration_fk1
	FOREIGN KEY (role_name)
	REFERENCES q_qr_role (role_name)
;

ALTER TABLE u_valid_state_change
    ADD CONSTRAINT fk_priv_name__priv__priv_name
	FOREIGN KEY (priv_name)
	REFERENCES q_qr_priv (priv_name)
;
