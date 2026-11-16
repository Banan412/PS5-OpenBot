-- Compatibility tables for components, per-bot component holds, and write idempotency.
CREATE TABLE port_components (
  organization_id TEXT NOT NULL REFERENCES auth_organizations(id),
  name TEXT NOT NULL,
  title TEXT NOT NULL,
  kind TEXT NOT NULL,
  published INTEGER NOT NULL DEFAULT 1 CHECK (published IN (0, 1)),
  published_at INTEGER,
  description TEXT,
  draft_description TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (organization_id, name)
);
CREATE INDEX port_components_order ON port_components(organization_id, kind, title, name);

CREATE TABLE port_bot_components (
  organization_id TEXT NOT NULL,
  bot_id TEXT NOT NULL REFERENCES port_bots(id) ON DELETE CASCADE,
  component_name TEXT NOT NULL,
  withheld INTEGER NOT NULL DEFAULT 1 CHECK (withheld IN (0, 1)),
  withheld_at INTEGER NOT NULL,
  PRIMARY KEY (organization_id, bot_id, component_name),
  FOREIGN KEY (organization_id, component_name) REFERENCES port_components(organization_id, name) ON DELETE CASCADE
);
CREATE INDEX port_bot_components_by_comp ON port_bot_components(organization_id, component_name, withheld, bot_id);

CREATE TABLE port_compat_idempotency (
  organization_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  idem_key TEXT NOT NULL,
  fingerprint BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  status INTEGER NOT NULL,
  body TEXT NOT NULL,
  PRIMARY KEY (organization_id, actor_id, idem_key)
);
CREATE INDEX port_compat_idempotency_expiry ON port_compat_idempotency(created_at);
