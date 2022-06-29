ALTER SEQUENCE q_qr_role_role_id_seq RESTART;
SELECT nextval('q_qr_role_role_id_seq');

-- Login to psql and run the following

-- What is the result?
SELECT MAX(role_id) FROM q_qr_role;

-- Then run...
-- This should be higher than the last result.
SELECT nextval('q_qr_role_role_id_seq');

-- If it's not higher... run this set the sequence last to your highest id.
-- (wise to run a quick pg_dump first...)

BEGIN;
-- protect against concurrent inserts while you update the counter
LOCK TABLE q_qr_role IN EXCLUSIVE MODE;
-- Update the sequence
SELECT setval('q_qr_role_role_id_seq', COALESCE((SELECT MAX(role_id)+1 FROM q_qr_role), 1), false);
COMMIT;

SELECT nextval('q_qr_role_role_id_seq');
