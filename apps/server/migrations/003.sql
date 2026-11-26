ALTER TABLE proxies ADD COLUMN headers TEXT NOT NULL DEFAULT '{}';
ALTER TABLE rules ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1));

CREATE TABLE service_groups (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  action TEXT NOT NULL CHECK(action IN ('PROXY','AUTO','LOCAL_DIRECT','SERVER_DIRECT','BLOCK','INHERIT')),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  locked INTEGER NOT NULL DEFAULT 0 CHECK(locked IN (0,1)),
  revision INTEGER NOT NULL
);

CREATE TABLE service_group_entries (
  id TEXT PRIMARY KEY,
  group_id TEXT NOT NULL REFERENCES service_groups(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK(kind IN ('domain','suffix','ip_cidr','process','package')),
  pattern TEXT NOT NULL,
  UNIQUE(group_id, kind, pattern)
);
