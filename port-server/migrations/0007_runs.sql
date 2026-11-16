CREATE TABLE port_runs (
  id TEXT PRIMARY KEY,
  conversation_id TEXT NOT NULL REFERENCES port_conversations(id),
  owner_id TEXT NOT NULL REFERENCES auth_users(id),
  bot_id TEXT NOT NULL REFERENCES port_bots(id),
  user_message_id TEXT NOT NULL,
  assistant_message_id TEXT NOT NULL,
  request_key TEXT NOT NULL,
  fingerprint BLOB NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('running','completed','failed')),
  created_at INTEGER NOT NULL,
  UNIQUE(conversation_id,user_message_id),
  UNIQUE(owner_id,request_key)
);
