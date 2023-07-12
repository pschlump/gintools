-- select id, user_id, etag_seen, n_login, fingerprint_data, sc_id, header_hash, am_i_known from q_qr_device_track;
--                   id                  |               user_id                |      etag_seen       | n_login |         fingerprint_data         |                sc_id                 |                           header_hash                            |              am_i_known
-- --------------------------------------+--------------------------------------+----------------------+---------+----------------------------------+--------------------------------------+------------------------------------------------------------------+--------------------------------------
--  5c04a7a7-6380-4fc4-57af-242c372ce9b8 |                                      | 3ddd89982a6f06303948 |       0 |                                  |                                      |                                                                  |
--  a89d71d5-ae8f-4943-b3cf-584d84ee646c | 524d58b1-b94c-462a-9481-755515a9a222 |                      |       2 | b11ba821e996ecc6b9dd1b0ca7fe139a | 06ee6e25-3158-4f19-9335-38c9b3822389 | c0913a7535439615871db5a171fa7293e8f937102adb09c7d5341e3b33276e2a | 060951a1-169d-44f5-419b-ad0a6d03bc69
--  060951a1-169d-44f5-419b-ad0a6d03bc69 |                                      | f9fdbdb8ddf03064341b |       0 |                                  |                                      |                                                                  |
--  f467e984-2a12-4a41-85c9-2247c060ed8d | 524d58b1-b94c-462a-9481-755515a9a222 |                      |       2 | b11ba821e996ecc6b9dd1b0ca7fe139a | 06ee6e25-3158-4f19-9335-38c9b3822389 | bcaa4ba6cce30df4fc790d9c8466254d61b1ff6d0e53e5ab2fd91ea95928bcb8 | 060951a1-169d-44f5-419b-ad0a6d03bc69
-- (4 rows)
-- 
select substring(id::text from 1 for 12) as "id"
	, substring(user_id::text from 1 for 12) as "user_id"
	, etag_seen
    , n_seen 			
	, n_login
	, fingerprint_data
	, substring(sc_id::text from 1 for 12) as "sc_id"
	, header_hash
	, substring(am_i_known::text from 1 for 12) as "am_i_known"
from q_qr_device_track
;
