-- Private conversations; group membership and model execution are future work.
CREATE TABLE port_conversations (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES auth_organizations(id),
  owner_id TEXT NOT NULL REFERENCES auth_users(id),
  thread_id TEXT NOT NULL,
  bot_ids_json TEXT NOT NULL,
  name TEXT NOT NULL,
  title TEXT,
  pinned INTEGER NOT NULL DEFAULT 0 CHECK(pinned IN (0,1)),
  created_at INTEGER NOT NULL,
  last_read_at INTEGER,
  last_message_at INTEGER,
  deleted INTEGER NOT NULL DEFAULT 0 CHECK(deleted IN (0,1))
);
CREATE INDEX port_conversations_owner ON port_conversations(organization_id,owner_id,deleted,pinned,created_at,id);
CREATE TABLE port_conversation_messages (
  id TEXT NOT NULL,
  conversation_id TEXT NOT NULL REFERENCES port_conversations(id),
  role TEXT NOT NULL CHECK(role IN ('person','bot','tool','system')),
  person_id TEXT,
  bot_id TEXT,
  text TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('queued','running','waiting','completed','failed')),
  created_at INTEGER NOT NULL,
  PRIMARY KEY(conversation_id,id)
);
CREATE INDEX port_conversation_messages_order ON port_conversation_messages(conversation_id,created_at,id);
CREATE TABLE port_conversation_idempotency (
  organization_id TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  request_key TEXT NOT NULL,
  fingerprint BLOB NOT NULL,
  status INTEGER NOT NULL,
  body TEXT NOT NULL,
  location TEXT,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(organization_id,owner_id,request_key)
);
