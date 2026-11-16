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
pub(crate) const MAX_EVENTS: i64 = 4096;
pub(crate) const MAX_TOTAL_BYTES: i64 = 8 * 1024 * 1024;
const MAX_PAGE: usize = 128;

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

/// Append one event and assign a monotonically increasing conversation-local id.
/// The caller must not provide cpki_event_id: the journal owns that identity.
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
    let result=db.try_with_connection(|c| {
        let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (count,total,last):(i64,i64,i64)=tx.query_row("SELECT COUNT(*),COALESCE(SUM(bytes),0),COALESCE(MAX(sequence),0) FROM port_run_events WHERE conversation_id=?1",params![conversation],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        if count>=MAX_EVENTS { return Ok(None); }
        let Some(next)=last.checked_add(1) else {return Ok(None)};
        event["metadata"]["cpki_event_id"]=Value::String(next.to_string());
        let body=event.to_string();
        if body.len()>MAX_EVENT_BYTES || total.saturating_add(body.len() as i64)>MAX_TOTAL_BYTES { return Ok(None); }
        tx.execute("INSERT INTO port_run_events(conversation_id,sequence,event_json,bytes) VALUES(?1,?2,?3,?4)",params![conversation,next,body,body.len() as i64])?;
        tx.commit()?; Ok(Some(next.to_string()))
    })?;
    if result.is_some() {
        notify_journal_change();
    }
    result.ok_or(JournalError::Full)
}

/// Read a bounded page after a previously observed id. Unknown ids fail rather
/// than silently claiming a complete replay. None starts from the beginning.
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
    let rows=db.try_with_connection(|c| {
        let gap: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM port_metadata WHERE key=?1)",params![format!("conversation_replay_gap:{conversation}")],|r|r.get(0))?;
        if gap { return Ok(Some(Err(()))); }
        if cursor>0 {
            let found:Option<i64>=c.query_row("SELECT sequence FROM port_run_events WHERE conversation_id=?1 AND sequence=?2",params![conversation,cursor],|r|r.get(0)).optional()?;
            if found.is_none() {return Ok(None)}
        }
        let mut stmt=c.prepare("SELECT event_json FROM port_run_events WHERE conversation_id=?1 AND sequence>?2 ORDER BY sequence LIMIT ?3")?;
        let rows=stmt.query_map(params![conversation,cursor,limit as i64],|r|r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Some(Ok(rows)))
    })?.ok_or(JournalError::InvalidCursor)?;
    let rows = rows.map_err(|_| JournalError::ReplayGap)?;
    rows.into_iter()
        .map(|s| serde_json::from_str(&s).map_err(|_| JournalError::InvalidEvent))
        .collect()
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
}
