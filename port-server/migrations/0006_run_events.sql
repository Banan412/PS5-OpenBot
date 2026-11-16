-- Durable, bounded AG-UI event journal. A full journal rejects new writes rather
-- than silently dropping the beginning of an active run.
CREATE TABLE port_run_events (
    conversation_id TEXT NOT NULL REFERENCES port_conversations(id),
    sequence INTEGER NOT NULL CHECK(sequence > 0),
    event_json TEXT NOT NULL,
    bytes INTEGER NOT NULL CHECK(bytes > 0),
    PRIMARY KEY(conversation_id, sequence)
);
