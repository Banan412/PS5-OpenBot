-- Internal fail-closed audit foundation. It is not an OpenBot audit API or an
-- authorization grant. No executor consumes records from this table.
CREATE TABLE port_governance_audit (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES auth_organizations(id),
  actor_id TEXT NOT NULL REFERENCES auth_users(id),
  bot_id TEXT NOT NULL REFERENCES port_bots(id),
  conversation_id TEXT NOT NULL REFERENCES port_conversations(id),
  attempt_id TEXT NOT NULL,
  phase TEXT NOT NULL CHECK (phase IN ('intent', 'refused')),
  action_digest BLOB NOT NULL CHECK (length(action_digest) = 32),
  created_at INTEGER NOT NULL,
  UNIQUE (organization_id, actor_id, attempt_id, phase)
);
CREATE INDEX port_governance_audit_org_order ON port_governance_audit(organization_id, created_at, id);
-- Reject REPLACE before SQLite can delete a conflicting row, even when
-- recursive_triggers is disabled on the connection.
CREATE TRIGGER port_governance_audit_no_replace BEFORE INSERT ON port_governance_audit
WHEN EXISTS (SELECT 1 FROM port_governance_audit WHERE id=NEW.id OR
  (organization_id=NEW.organization_id AND actor_id=NEW.actor_id AND attempt_id=NEW.attempt_id AND phase=NEW.phase)) BEGIN
  SELECT RAISE(ABORT, 'governance audit already exists');
END;
CREATE TRIGGER port_governance_audit_no_update BEFORE UPDATE ON port_governance_audit BEGIN
  SELECT RAISE(ABORT, 'governance audit is append only');
END;
CREATE TRIGGER port_governance_audit_no_delete BEFORE DELETE ON port_governance_audit BEGIN
  SELECT RAISE(ABORT, 'governance audit is append only');
END;
