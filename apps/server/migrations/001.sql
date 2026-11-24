CREATE TABLE users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);
CREATE TABLE proxies (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  host TEXT NOT NULL,
  port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
  tls INTEGER NOT NULL CHECK(tls IN (0,1)),
  credentials BLOB NOT NULL
);
CREATE TABLE routes (
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  proxy_id TEXT REFERENCES proxies(id) ON DELETE CASCADE,
  priority INTEGER NOT NULL CHECK(priority >= 0),
  PRIMARY KEY(user_id, proxy_id),
  UNIQUE(user_id, priority)
);
CREATE TABLE devices (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  transport TEXT NOT NULL CHECK(transport IN ('agent','browser')),
  invite_hash BLOB UNIQUE,
  expires INTEGER NOT NULL,
  token_hash BLOB UNIQUE,
  primary_id TEXT NOT NULL UNIQUE,
  direct_id TEXT NOT NULL UNIQUE,
  revoked INTEGER NOT NULL DEFAULT 0,
  ack_revision INTEGER NOT NULL DEFAULT 0,
  seen INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE rules (
  id TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  pattern TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('domain','suffix','process')),
  action TEXT NOT NULL CHECK(action IN ('PROXY','AUTO','LOCAL_DIRECT','SERVER_DIRECT','BLOCK','INHERIT')),
  locked INTEGER NOT NULL CHECK(locked IN (0,1)),
  revision INTEGER NOT NULL
);
CREATE UNIQUE INDEX rule_match ON rules(COALESCE(user_id,''), kind, pattern);
CREATE TABLE state (revision INTEGER NOT NULL);
INSERT INTO state VALUES(1);
CREATE TABLE audit (
  revision INTEGER PRIMARY KEY,
  event TEXT NOT NULL,
  time INTEGER NOT NULL
);
