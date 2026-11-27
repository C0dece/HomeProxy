ALTER TABLE devices ADD COLUMN sub_token_hash BLOB;
ALTER TABLE devices ADD COLUMN sub_token_enc BLOB;
ALTER TABLE devices ADD COLUMN sub_active INTEGER NOT NULL DEFAULT 0 CHECK(sub_active IN (0,1));
CREATE UNIQUE INDEX IF NOT EXISTS devices_sub_token_hash ON devices(sub_token_hash) WHERE sub_token_hash IS NOT NULL;
