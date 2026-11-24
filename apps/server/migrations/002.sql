ALTER TABLE rules RENAME TO rules_v1;
DROP INDEX rule_match;
CREATE TABLE rules (
  id TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  pattern TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('domain','suffix','process','package')),
  action TEXT NOT NULL CHECK(action IN ('PROXY','AUTO','LOCAL_DIRECT','SERVER_DIRECT','BLOCK','INHERIT')),
  locked INTEGER NOT NULL CHECK(locked IN (0,1)),
  revision INTEGER NOT NULL
);
INSERT INTO rules SELECT id,user_id,pattern,kind,action,locked,revision FROM rules_v1;
DROP TABLE rules_v1;
CREATE UNIQUE INDEX rule_match ON rules(COALESCE(user_id,''), kind, pattern);
