CREATE TABLE port_bots (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES auth_organizations(id),
  owner_id TEXT NOT NULL REFERENCES auth_users(id),
  name TEXT NOT NULL,
  title TEXT NOT NULL,
  role_description TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX port_bots_owner_order ON port_bots(organization_id, owner_id, created_at, id);
CREATE TABLE port_bot_idempotency (
  organization_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  idem_key TEXT NOT NULL,
  fingerprint BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  status INTEGER NOT NULL,
  body TEXT NOT NULL,
  location TEXT,
  PRIMARY KEY (organization_id, actor_id, idem_key)
);

