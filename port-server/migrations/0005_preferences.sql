CREATE TABLE port_preferences (
  user_id TEXT PRIMARY KEY REFERENCES auth_users(id),
  message_emphasis TEXT NOT NULL DEFAULT 'thread',
  banner_dismissed INTEGER NOT NULL DEFAULT 0,
  narration TEXT,
  skin TEXT NOT NULL DEFAULT 'openbot',
  proactive TEXT NOT NULL DEFAULT 'on'
);
CREATE TABLE port_preference_requests (
  user_id TEXT NOT NULL REFERENCES auth_users(id),
  request_key TEXT NOT NULL,
  fingerprint BLOB NOT NULL,
  response TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, request_key)
);
