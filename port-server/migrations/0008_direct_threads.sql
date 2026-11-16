-- Direct threads are allocated for an owner and organization before first use.
-- The first run binds one to exactly one owned Bot and creates its conversation.
CREATE TABLE port_direct_threads (
  thread_id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES auth_organizations(id),
  owner_id TEXT NOT NULL REFERENCES auth_users(id),
  bot_id TEXT REFERENCES port_bots(id),
  conversation_id TEXT REFERENCES port_conversations(id),
  created_at INTEGER NOT NULL,
  CHECK ((bot_id IS NULL AND conversation_id IS NULL) OR (bot_id IS NOT NULL AND conversation_id IS NOT NULL))
);
CREATE INDEX port_direct_threads_owner ON port_direct_threads(organization_id,owner_id);
CREATE TABLE port_direct_thread_requests (
  organization_id TEXT NOT NULL REFERENCES auth_organizations(id),
  owner_id TEXT NOT NULL REFERENCES auth_users(id),
  request_key TEXT NOT NULL,
  thread_id TEXT NOT NULL REFERENCES port_direct_threads(thread_id),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (organization_id,owner_id,request_key)
);
