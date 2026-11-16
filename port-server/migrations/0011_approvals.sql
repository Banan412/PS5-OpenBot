-- Policy rules, approval settings, boundaries, interactive HITL approvals,
-- conversation grants, idempotency records, and append-only policy audit trail.

CREATE TABLE port_approval_rules (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES auth_organizations(id),
  scope_owner_id TEXT NOT NULL DEFAULT '',
  bot_id TEXT NOT NULL,
  tool_ref TEXT NOT NULL,
  effect TEXT NOT NULL,
  scope TEXT NOT NULL,
  behaviour TEXT NOT NULL CHECK (behaviour IN ('allow', 'pre_approved', 'ask', 'hand_off')),
  account TEXT,
  kind TEXT CHECK (kind IS NULL OR kind IN ('deleting', 'sending', 'sharing', 'publishing', 'payments', 'credentials', 'security_settings')),
  created_by TEXT REFERENCES auth_users(id),
  created_at INTEGER NOT NULL
);
CREATE INDEX port_approval_rules_org_order
  ON port_approval_rules(organization_id, scope_owner_id, created_at DESC, id DESC);

CREATE TABLE port_approval_settings (
  organization_id TEXT PRIMARY KEY REFERENCES auth_organizations(id),
  enforce_auto_review INTEGER NOT NULL DEFAULT 0 CHECK (enforce_auto_review IN (0, 1)),
  custom_rules_enabled INTEGER NOT NULL DEFAULT 1 CHECK (custom_rules_enabled IN (0, 1)),
  host_commands_cap TEXT NOT NULL DEFAULT 'ask' CHECK (host_commands_cap IN ('ask', 'allow', 'never')),
  action_kinds_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE port_boundaries (
  organization_id TEXT PRIMARY KEY REFERENCES auth_organizations(id),
  mode TEXT NOT NULL DEFAULT 'enforce' CHECK (mode IN ('enforce', 'dry-run')),
  deny_json TEXT NOT NULL DEFAULT '[]',
  allow_json TEXT NOT NULL DEFAULT '[]',
  labels_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE port_approvals (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES auth_organizations(id),
  actor_id TEXT NOT NULL REFERENCES auth_users(id),
  bot_id TEXT NOT NULL REFERENCES port_bots(id),
  conversation_id TEXT NOT NULL REFERENCES port_conversations(id),
  run_id TEXT NOT NULL,
  tool_call_id TEXT,
  tool_ref TEXT NOT NULL,
  effect TEXT NOT NULL,
  scope TEXT NOT NULL,
  thread_id TEXT NOT NULL,
  args_json TEXT NOT NULL,
  target_json TEXT,
  account TEXT,
  policy_json TEXT,
  action_digest BLOB NOT NULL CHECK (length(action_digest) = 32),
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'consumed', 'completed')),
  decision TEXT CHECK (decision IS NULL OR decision IN ('allow_once', 'allow_conversation', 'allow_always', 'deny', 'handled')),
  result_json TEXT,
  created_at INTEGER NOT NULL,
  decided_at INTEGER,
  consumed_at INTEGER,
  completed_at INTEGER,
  expires_at INTEGER NOT NULL
);
CREATE INDEX port_approvals_actor_order
  ON port_approvals(organization_id, actor_id, created_at DESC, id DESC);
CREATE INDEX port_approvals_org_decided
  ON port_approvals(organization_id, decided_at DESC, id DESC);
CREATE INDEX port_approvals_org_completed
  ON port_approvals(organization_id, completed_at DESC, id DESC);

CREATE TABLE port_conversation_grants (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES auth_organizations(id),
  actor_id TEXT NOT NULL REFERENCES auth_users(id),
  conversation_id TEXT NOT NULL REFERENCES port_conversations(id),
  thread_id TEXT NOT NULL,
  bot_id TEXT NOT NULL,
  tool_ref TEXT NOT NULL,
  effect TEXT NOT NULL,
  scope TEXT NOT NULL,
  account TEXT,
  kind TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX port_conversation_grants_lookup
  ON port_conversation_grants(organization_id, actor_id, conversation_id, created_at DESC);

CREATE TABLE port_approval_decide_idem (
  organization_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  approval_id TEXT NOT NULL,
  idem_key TEXT NOT NULL,
  fingerprint BLOB NOT NULL,
  status INTEGER NOT NULL,
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (organization_id, actor_id, approval_id, idem_key)
);

CREATE TABLE port_approval_api_idem (
  organization_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  idem_key TEXT NOT NULL,
  fingerprint BLOB NOT NULL,
  status INTEGER NOT NULL,
  body TEXT NOT NULL,
  location TEXT,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (organization_id, actor_id, idem_key)
);

CREATE TABLE port_policy_audit_events (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES auth_organizations(id),
  actor_id TEXT REFERENCES auth_users(id),
  event_type TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT,
  payload_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX port_policy_audit_org_order
  ON port_policy_audit_events(organization_id, created_at DESC, id DESC);

CREATE TRIGGER port_policy_audit_no_replace BEFORE INSERT ON port_policy_audit_events
WHEN EXISTS (SELECT 1 FROM port_policy_audit_events WHERE id = NEW.id) BEGIN
  SELECT RAISE(ABORT, 'policy audit already exists');
END;
CREATE TRIGGER port_policy_audit_no_update BEFORE UPDATE ON port_policy_audit_events BEGIN
  SELECT RAISE(ABORT, 'policy audit is append only');
END;
CREATE TRIGGER port_policy_audit_no_delete BEFORE DELETE ON port_policy_audit_events BEGIN
  SELECT RAISE(ABORT, 'policy audit is append only');
END;
