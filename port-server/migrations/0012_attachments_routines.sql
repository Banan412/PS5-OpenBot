-- Conversation attachments and scheduled routines.
CREATE TABLE port_attachments (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES auth_organizations(id),
  conversation_id TEXT NOT NULL REFERENCES port_conversations(id),
  owner_id TEXT NOT NULL REFERENCES auth_users(id),
  filename TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  upload_group TEXT,
  data BLOB NOT NULL,
  extracted_text TEXT,
  message_id TEXT,
  attached_at INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX port_attachments_conv_msg
  ON port_attachments(conversation_id, message_id, created_at);

CREATE TABLE port_routines (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES auth_organizations(id),
  owner_id TEXT NOT NULL REFERENCES auth_users(id),
  bot_id TEXT NOT NULL REFERENCES port_bots(id),
  conversation_id TEXT NOT NULL REFERENCES port_conversations(id),
  title TEXT,
  instruction TEXT NOT NULL,
  cron TEXT NOT NULL,
  timezone TEXT NOT NULL DEFAULT 'UTC',
  goal_id TEXT,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
  last_run_at INTEGER,
  last_run_status TEXT,
  next_run_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX port_routines_owner_order
  ON port_routines(organization_id, owner_id, created_at DESC, id DESC);
CREATE INDEX port_routines_due
  ON port_routines(enabled, next_run_at);

CREATE TABLE port_routine_runs (
  id TEXT PRIMARY KEY,
  routine_id TEXT NOT NULL REFERENCES port_routines(id) ON DELETE CASCADE,
  conversation_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('queued', 'running', 'completed', 'failed')),
  started_at INTEGER NOT NULL,
  finished_at INTEGER
);
CREATE INDEX port_routine_runs_order
  ON port_routine_runs(routine_id, started_at DESC, id DESC);
