
-- Copyright (C) Philip Schlump, 2008-2023.
-- MIT Licensed.  See LICENSE.mit file.
-- BSD Licensed.  See LICENSE.bsd file.

m4_include(setup.m4)
m4_include(ver.m4)
m4_do_not_edit()

-- Setup for install
CREATE EXTENSION if not exists pgcrypto;
CREATE EXTENSION if not exists "uuid-ossp";
CREATE EXTENSION if not exists fuzzystrmatch;


