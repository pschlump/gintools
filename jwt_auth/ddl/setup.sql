
--
-- Remember to 
--
-- 		$ sudo apt-get install postgresql-contrib-9.5
--
-- Before running this.
--
-- Must run as "postgres" user
--       ALTER ROLE pschlump SUPERUSER;
--

--$error-fatal$ Extensions uuid-ossp and pgrypto are required.  Check permissions for creating them.

CREATE EXTENSION if not exists "uuid-ossp";
CREATE EXTENSION if not exists pgcrypto;
CREATE EXTENSION if not exists fuzzystrmatch;

--$error-reset$

