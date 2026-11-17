//! Durable, bounded event storage. Callers must authorize conversation access
//! before using this module and schedule database work on the bounded executor.
//! This is not yet a WebSocket gateway or model run engine.
use crate::storage::{Storage, StorageError};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde_json::Value;
use std::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};

static JOURNAL_EPOCH: AtomicU64 = AtomicU64::new(1);

pub(crate) fn journal_epoch() -> u64 {
    JOURNAL_EPOCH.load(Ordering::Acquire)
}

pub(crate) fn notify_journal_change() {
    JOURNAL_EPOCH.fetch_add(1, Ordering::Release);
}

pub(crate) const MAX_EVENT_BYTES: usize = 64 * 1024;
pub(crate) const MAX_EVENTS: i64 = 24576;
pub(crate) const MAX_TOTAL_BYTES: i64 = 8 * 1024 * 1024;
const MAX_PAGE: usize = 128;
const PRUNE_BATCH: i64 = 256;
const REPLAY_GAP_PREFIX: &str = "conversation_replay_gap:";
const ARCHIVED_SEQ_PREFIX: &str = "conversation_journal_archived_seq:";

#[derive(Debug)]
pub enum JournalError {
    Storage(StorageError),
    InvalidEvent,
    Full,
    InvalidCursor,
    ReplayGap,
}
impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(e) => write!(f, "{e}"),
            Self::InvalidEvent => f.write_str("invalid event"),
            Self::Full => f.write_str("event journal is full"),
            Self::InvalidCursor => f.write_str("invalid event cursor"),
            Self::ReplayGap => f.write_str("conversation replay is incomplete"),
        }
    }
}
impl From<StorageError> for JournalError {
    fn from(e: StorageError) -> Self {
        Self::Storage(e)
    }
}

fn metadata_key(prefix: &str, conversation: &str) -> String {
    format!("{prefix}{conversation}")
}

/// Prune the oldest rows in bounded batches when either `MAX_EVENTS` or
/// `MAX_TOTAL_BYTES` would be exceeded, returning the highest pruned sequence.
fn prune_oldest_for_append(
    tx: &rusqlite::Transaction<'_>,
    conversation: &str,
    count: &mut i64,
    total: &mut i64,
    body_len: i64,
) -> rusqlite::Result<Option<i64>> {
    if *count < MAX_EVENTS && total.saturating_add(body_len) <= MAX_TOTAL_BYTES {
        return Ok(None);
    }

    let mut select_oldest = tx.prepare_cached(
        "SELECT sequence, bytes FROM port_run_events WHERE conversation_id=?1 ORDER BY sequence ASC LIMIT ?2",
    )?;
    let mut delete_through = tx.prepare_cached(
        "DELETE FROM port_run_events WHERE conversation_id=?1 AND sequence<=?2",
    )?;

    let mut max_pruned_seq: Option<i64> = None;
    while *count >= MAX_EVENTS || total.saturating_add(body_len) > MAX_TOTAL_BYTES {
        let batch = select_oldest
            .query_map(params![conversation, PRUNE_BATCH], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if batch.is_empty() {
            break;
        }

        // Leave a PRUNE_BATCH hysteresis cushion when rolling on event count so
        // streaming does not execute a DELETE on every subsequent token.
        let target_count = if *count >= MAX_EVENTS {
            (MAX_EVENTS - PRUNE_BATCH).max(0)
        } else {
            MAX_EVENTS - 1
        };

        let mut cut_seq = batch[0].0;
        let mut deleted_count = 0i64;
        let mut deleted_bytes = 0i64;
        for (seq, bytes) in &batch {
            cut_seq = *seq;
            deleted_count += 1;
            deleted_bytes = deleted_bytes.saturating_add(*bytes);
            let next_count = *count - deleted_count;
            let next_total = total.saturating_sub(deleted_bytes);
            if next_count <= target_count && next_total.saturating_add(body_len) <= MAX_TOTAL_BYTES
            {
                break;
            }
        }

        let removed = delete_through.execute(params![conversation, cut_seq])? as i64;
        if removed == 0 {
            break;
        }
        *count -= deleted_count;
        *total = total.saturating_sub(deleted_bytes);
        max_pruned_seq = Some(max_pruned_seq.map_or(cut_seq, |prev| prev.max(cut_seq)));
    }

    Ok(max_pruned_seq)
}

/// Append one event and assign a monotonically increasing conversation-local id.
/// The caller must not provide cpki_event_id: the journal owns that identity.
/// When the per-conversation event or byte cap is reached, the oldest archived
/// rows are pruned in bounded batches so active streams can continue cleanly.
pub fn append(db: &Storage, conversation: &str, mut event: Value) -> Result<String, JournalError> {
    let obj = event.as_object_mut().ok_or(JournalError::InvalidEvent)?;
    if !obj
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty() && s.len() <= 128)
    {
        return Err(JournalError::InvalidEvent);
    }
    let metadata = obj
        .entry("metadata")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or(JournalError::InvalidEvent)?;
    if metadata.contains_key("cpki_event_id") {
        return Err(JournalError::InvalidEvent);
    }
    let result = db.try_with_connection(|c| {
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (mut count, mut total, last): (i64, i64, i64) = tx.query_row(
            "SELECT COUNT(*),COALESCE(SUM(bytes),0),COALESCE(MAX(sequence),0) FROM port_run_events WHERE conversation_id=?1",
            params![conversation],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let Some(next) = last.checked_add(1) else {
            return Ok(None);
        };
        event["metadata"]["cpki_event_id"] = Value::String(next.to_string());
        let body = event.to_string();
        if body.len() > MAX_EVENT_BYTES {
            return Ok(None);
        }
        let body_len = body.len() as i64;
        let max_pruned_seq =
            prune_oldest_for_append(&tx, conversation, &mut count, &mut total, body_len)?;
        if count >= MAX_EVENTS || total.saturating_add(body_len) > MAX_TOTAL_BYTES {
            return Ok(None);
        }
        if let Some(pruned_seq) = max_pruned_seq {
            tx.execute(
                "INSERT INTO port_metadata(key,value) VALUES(?1,?2) \
                 ON CONFLICT(key) DO UPDATE SET value=CASE \
                 WHEN CAST(port_metadata.value AS INTEGER) > CAST(excluded.value AS INTEGER) \
                 THEN port_metadata.value ELSE excluded.value END",
                params![
                    metadata_key(ARCHIVED_SEQ_PREFIX, conversation),
                    pruned_seq.to_string()
                ],
            )?;
        }
        tx.execute(
            "DELETE FROM port_metadata WHERE key=?1",
            params![metadata_key(REPLAY_GAP_PREFIX, conversation)],
        )?;
        tx.execute(
            "INSERT INTO port_run_events(conversation_id,sequence,event_json,bytes) VALUES(?1,?2,?3,?4)",
            params![conversation, next, body, body_len],
        )?;
        tx.commit()?;
        Ok(Some(next.to_string()))
    })?;
    if result.is_some() {
        notify_journal_change();
    }
    result.ok_or(JournalError::Full)
}

/// Read a bounded page after a previously observed id. Unknown future ids fail
/// rather than silently claiming a complete replay; cursors predating an
/// intentional rolling-window archive advance cleanly to the active window,
/// while unexpected truncation or terminal gaps return `ReplayGap`. None starts
/// from the beginning of the available window.
pub fn replay(
    db: &Storage,
    conversation: &str,
    after: Option<&str>,
    limit: usize,
) -> Result<Vec<Value>, JournalError> {
    if limit == 0 || limit > MAX_PAGE {
        return Err(JournalError::InvalidCursor);
    }
    let cursor = match after {
        None => 0,
        Some(s) => {
            let n = s.parse::<i64>().map_err(|_| JournalError::InvalidCursor)?;
            if n <= 0 || n.to_string() != s {
                return Err(JournalError::InvalidCursor);
            }
            n
        }
    };
    enum ReplayOutcome {
        Events(Vec<String>),
        InvalidCursor,
        Gap,
    }
    let outcome = db.try_with_connection(|c| {
        let gap: bool = c.query_row(
            "SELECT EXISTS(SELECT 1 FROM port_metadata WHERE key=?1)",
            params![metadata_key(REPLAY_GAP_PREFIX, conversation)],
            |r| r.get(0),
        )?;
        if gap {
            return Ok(ReplayOutcome::Gap);
        }

        let archived_raw: Option<String> = c
            .query_row(
                "SELECT value FROM port_metadata WHERE key=?1",
                params![metadata_key(ARCHIVED_SEQ_PREFIX, conversation)],
                |r| r.get(0),
            )
            .optional()?;
        let archived_floor = match archived_raw {
            None => 0,
            Some(raw) => match raw.parse::<i64>() {
                Ok(n) if n > 0 && n.to_string() == raw => n,
                _ => return Ok(ReplayOutcome::Gap),
            },
        };

        let (min_seq, max_seq): (Option<i64>, Option<i64>) = c.query_row(
            "SELECT MIN(sequence),MAX(sequence) FROM port_run_events WHERE conversation_id=?1",
            params![conversation],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;

        let (Some(min_s), Some(max_s)) = (min_seq, max_seq) else {
            if archived_floor > 0 {
                return Ok(ReplayOutcome::Gap);
            }
            if cursor > 0 {
                return Ok(ReplayOutcome::InvalidCursor);
            }
            return Ok(ReplayOutcome::Events(Vec::new()));
        };

        if cursor > max_s {
            return Ok(ReplayOutcome::InvalidCursor);
        }

        // Distinguish intentional rolling archival (min_s == archived_floor + 1)
        // from unexpected prefix truncation.
        if min_s != archived_floor + 1 && cursor < min_s {
            return Ok(ReplayOutcome::Gap);
        }

        if cursor > archived_floor {
            let found: Option<i64> = c
                .query_row(
                    "SELECT sequence FROM port_run_events WHERE conversation_id=?1 AND sequence=?2",
                    params![conversation, cursor],
                    |r| r.get(0),
                )
                .optional()?;
            if found.is_none() {
                return Ok(ReplayOutcome::Gap);
            }
        }

        let effective_cursor = cursor.max(archived_floor);
        let mut stmt = c.prepare(
            "SELECT sequence,event_json FROM port_run_events WHERE conversation_id=?1 AND sequence>?2 ORDER BY sequence LIMIT ?3",
        )?;
        let rows = stmt
            .query_map(params![conversation, effective_cursor, limit as i64], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut expected = effective_cursor + 1;
        let mut events = Vec::with_capacity(rows.len());
        for (seq, json) in rows {
            if seq != expected {
                return Ok(ReplayOutcome::Gap);
            }
            expected = seq + 1;
            events.push(json);
        }
        Ok(ReplayOutcome::Events(events))
    })?;

    match outcome {
        ReplayOutcome::InvalidCursor => Err(JournalError::InvalidCursor),
        ReplayOutcome::Gap => Err(JournalError::ReplayGap),
        ReplayOutcome::Events(rows) => rows
            .into_iter()
            .map(|s| serde_json::from_str(&s).map_err(|_| JournalError::InvalidEvent))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    #[test]
    fn journal_replays_in_order_across_reopen_and_rejects_unknown_cursor() {
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "openbot-events-{:x}.db",
            u64::from_le_bytes(random)
        ));
        let db = Arc::new(Storage::open(&path).unwrap());
        db.try_with_connection(|c| { c.execute_batch("INSERT INTO auth_users(id,email,display_name,password_hash) VALUES('u','a@b','A','x'); INSERT INTO auth_organizations(id,slug,name) VALUES('o','o','O'); INSERT INTO port_conversations(id,organization_id,owner_id,thread_id,bot_ids_json,name,created_at) VALUES('c','o','u','t','[]','chat',1);")?;Ok(()) }).unwrap();
        assert_eq!(
            append(&db, "c", serde_json::json!({"type":"RUN_STARTED"})).unwrap(),
            "1"
        );
        assert_eq!(
            append(
                &db,
                "c",
                serde_json::json!({"type":"TEXT_MESSAGE_CONTENT","delta":"hi"})
            )
            .unwrap(),
            "2"
        );
        assert!(matches!(
            append(
                &db,
                "c",
                serde_json::json!({"type":"x","metadata":{"cpki_event_id":"spoof"}})
            ),
            Err(JournalError::InvalidEvent)
        ));
        assert!(matches!(
            replay(&db, "c", Some("3"), 128),
            Err(JournalError::InvalidCursor)
        ));
        drop(db);
        let db = Storage::open(&path).unwrap();
        let all = replay(&db, "c", None, 128).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0]["metadata"]["cpki_event_id"], "1");
        assert_eq!(replay(&db, "c", Some("1"), 128).unwrap()[0]["delta"], "hi");
        assert!(matches!(
            append(
                &db,
                "c",
                serde_json::json!({"type":"x","value":"x".repeat(MAX_EVENT_BYTES)})
            ),
            Err(JournalError::Full)
        ));
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    struct TempJournal {
        db: Storage,
        path: std::path::PathBuf,
    }

    impl Drop for TempJournal {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn open_test_journal() -> TempJournal {
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "openbot-events-{:x}.db",
            u64::from_le_bytes(random)
        ));
        let db = Storage::open(&path).unwrap();
        db.try_with_connection(|c| {
            c.execute_batch(
                "INSERT INTO auth_users(id,email,display_name,password_hash) VALUES('u','a@b','A','x'); \
                 INSERT INTO auth_organizations(id,slug,name) VALUES('o','o','O'); \
                 INSERT INTO port_conversations(id,organization_id,owner_id,thread_id,bot_ids_json,name,created_at) VALUES('c','o','u','t','[]','chat',1);",
            )?;
            Ok(())
        })
        .unwrap();
        TempJournal { db, path }
    }

    fn seed_events(db: &Storage, conversation: &str, from: i64, to: i64) {
        db.try_with_connection(|c| {
            let tx = c.transaction()?;
            let mut stmt = tx.prepare(
                "INSERT INTO port_run_events(conversation_id,sequence,event_json,bytes) VALUES(?1,?2,?3,?4)",
            )?;
            for seq in from..=to {
                let body = serde_json::json!({
                    "type": "TEXT_MESSAGE_CONTENT",
                    "delta": format!("d{seq}"),
                    "metadata": { "cpki_event_id": seq.to_string() }
                })
                .to_string();
                stmt.execute(params![conversation, seq, body, body.len() as i64])?;
            }
            drop(stmt);
            tx.commit()?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn journal_accepts_more_than_4096_events_and_replays_in_order() {
        let j = open_test_journal();
        seed_events(&j.db, "c", 1, 4090);
        for i in 0..200 {
            let seq = append(
                &j.db,
                "c",
                serde_json::json!({"type":"TEXT_MESSAGE_CONTENT","delta":format!("live-{i}")}),
            )
            .unwrap();
            assert_eq!(seq, (4091 + i).to_string());
        }
        let page = replay(&j.db, "c", Some("4095"), 128).unwrap();
        assert_eq!(page.len(), 128);
        assert_eq!(page[0]["metadata"]["cpki_event_id"], "4096");
        assert_eq!(page[0]["delta"], "live-5");
        let tail = replay(&j.db, "c", Some("4289"), 128).unwrap();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0]["metadata"]["cpki_event_id"], "4290");
    }

    #[test]
    fn journal_rolls_window_past_max_events_and_advances_stale_cursors() {
        let j = open_test_journal();
        seed_events(&j.db, "c", 1, MAX_EVENTS - 5);

        let mut last_seq = MAX_EVENTS - 5;
        for i in 0..600 {
            let id = append(
                &j.db,
                "c",
                serde_json::json!({"type":"TEXT_MESSAGE_CONTENT","delta":format!("roll-{i}")}),
            )
            .unwrap();
            last_seq += 1;
            assert_eq!(id, last_seq.to_string());
        }

        let (count, min_seq, max_seq, archived): (i64, i64, i64, String) = j
            .db
            .try_with_connection(|c| {
                let (cnt, min_s, max_s): (i64, i64, i64) = c.query_row(
                    "SELECT COUNT(*), MIN(sequence), MAX(sequence) FROM port_run_events WHERE conversation_id='c'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )?;
                let arch: String = c.query_row(
                    "SELECT value FROM port_metadata WHERE key=?1",
                    params![metadata_key(ARCHIVED_SEQ_PREFIX, "c")],
                    |r| r.get(0),
                )?;
                Ok((cnt, min_s, max_s, arch))
            })
            .unwrap();

        let archived_seq: i64 = archived.parse().unwrap();
        assert!(count <= MAX_EVENTS);
        assert!(archived_seq >= PRUNE_BATCH);
        assert_eq!(min_seq, archived_seq + 1);
        assert_eq!(max_seq, last_seq);

        // Reconnect from beginning or from a cursor predating the pruned window advances cleanly.
        let from_start = replay(&j.db, "c", None, 128).unwrap();
        assert_eq!(from_start.len(), 128);
        assert_eq!(
            from_start[0]["metadata"]["cpki_event_id"],
            min_seq.to_string()
        );

        let from_stale = replay(&j.db, "c", Some("1"), 128).unwrap();
        assert_eq!(from_stale, from_start);

        let from_archived_edge = replay(&j.db, "c", Some(&archived_seq.to_string()), 128).unwrap();
        assert_eq!(from_archived_edge, from_start);

        let from_active = replay(&j.db, "c", Some(&min_seq.to_string()), 128).unwrap();
        assert_eq!(
            from_active[0]["metadata"]["cpki_event_id"],
            (min_seq + 1).to_string()
        );

        assert!(replay(&j.db, "c", Some(&last_seq.to_string()), 128)
            .unwrap()
            .is_empty());
        assert!(matches!(
            replay(&j.db, "c", Some(&(last_seq + 1).to_string()), 128),
            Err(JournalError::InvalidCursor)
        ));
    }

    #[test]
    fn journal_rolls_window_when_total_bytes_exceeds_limit() {
        let j = open_test_journal();
        let payload = "a".repeat(32 * 1024);
        let total_events = 300; // ~9.6 MiB > 8 MiB MAX_TOTAL_BYTES, well below MAX_EVENTS
        for i in 1..=total_events {
            let id = append(
                &j.db,
                "c",
                serde_json::json!({"type":"TOOL_CALL_ARGS","delta":payload,"i":i}),
            )
            .unwrap();
            assert_eq!(id, i.to_string());
        }

        let (count, total_bytes, min_seq): (i64, i64, i64) = j
            .db
            .try_with_connection(|c| {
                Ok(c.query_row(
                    "SELECT COUNT(*), SUM(bytes), MIN(sequence) FROM port_run_events WHERE conversation_id='c'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )?)
            })
            .unwrap();
        assert!(count < total_events as i64);
        assert!(total_bytes <= MAX_TOTAL_BYTES);
        assert!(min_seq > 1);

        let page = replay(&j.db, "c", Some("1"), 128).unwrap();
        assert_eq!(page[0]["metadata"]["cpki_event_id"], min_seq.to_string());
    }

    #[test]
    fn journal_distinguishes_rolling_archival_from_unexpected_gaps() {
        let j = open_test_journal();
        seed_events(&j.db, "c", 1, 20);

        // Unexpected mid-run truncation gap.
        j.db.try_with_connection(|c| {
            c.execute(
                "DELETE FROM port_run_events WHERE conversation_id='c' AND sequence=10",
                [],
            )?;
            Ok(())
        })
        .unwrap();
        assert!(matches!(
            replay(&j.db, "c", None, 128),
            Err(JournalError::ReplayGap)
        ));
        assert!(matches!(
            replay(&j.db, "c", Some("10"), 128),
            Err(JournalError::ReplayGap)
        ));
        assert!(matches!(
            replay(&j.db, "c", Some("21"), 128),
            Err(JournalError::InvalidCursor)
        ));

        // Unexpected prefix truncation without rolling-archival metadata.
        let j2 = open_test_journal();
        seed_events(&j2.db, "c", 5, 10);
        assert!(matches!(
            replay(&j2.db, "c", None, 128),
            Err(JournalError::ReplayGap)
        ));
        assert!(matches!(
            replay(&j2.db, "c", Some("2"), 128),
            Err(JournalError::ReplayGap)
        ));
    }

    #[test]
    fn journal_clears_stale_replay_gap_on_append_and_roll() {
        let j = open_test_journal();
        seed_events(&j.db, "c", 1, MAX_EVENTS);
        j.db.try_with_connection(|c| {
            c.execute(
                "INSERT INTO port_metadata(key,value) VALUES(?1,'terminal event missing because journal is full')",
                params![metadata_key(REPLAY_GAP_PREFIX, "c")],
            )?;
            Ok(())
        })
        .unwrap();

        assert!(matches!(
            replay(&j.db, "c", None, 128),
            Err(JournalError::ReplayGap)
        ));

        // An oversized invalid append must fail without clearing the gap or pruning.
        assert!(matches!(
            append(
                &j.db,
                "c",
                serde_json::json!({"type":"x","value":"x".repeat(MAX_EVENT_BYTES)})
            ),
            Err(JournalError::Full)
        ));
        assert!(matches!(
            replay(&j.db, "c", None, 128),
            Err(JournalError::ReplayGap)
        ));

        // A valid append rolls the window and clears the stale gap marker.
        let seq = append(
            &j.db,
            "c",
            serde_json::json!({"type":"RUN_STARTED","runId":"r2"}),
        )
        .unwrap();
        assert_eq!(seq, (MAX_EVENTS + 1).to_string());

        let gap_exists: bool = j
            .db
            .try_with_connection(|c| {
                Ok(c.query_row(
                    "SELECT EXISTS(SELECT 1 FROM port_metadata WHERE key=?1)",
                    params![metadata_key(REPLAY_GAP_PREFIX, "c")],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert!(!gap_exists);
        let events = replay(&j.db, "c", Some("1"), 128).unwrap();
        assert_eq!(
            events[0]["metadata"]["cpki_event_id"],
            (PRUNE_BATCH + 1).to_string()
        );
    }

    #[test]
    fn journal_preserves_security_bounds() {
        let j = open_test_journal();
        append(&j.db, "c", serde_json::json!({"type":"RUN_STARTED"})).unwrap();
        assert!(matches!(
            replay(&j.db, "c", None, 0),
            Err(JournalError::InvalidCursor)
        ));
        assert!(matches!(
            replay(&j.db, "c", None, MAX_PAGE + 1),
            Err(JournalError::InvalidCursor)
        ));
        for bad in ["0", "-1", "01", "abc"] {
            assert!(matches!(
                replay(&j.db, "c", Some(bad), 128),
                Err(JournalError::InvalidCursor)
            ));
        }
    }
}
