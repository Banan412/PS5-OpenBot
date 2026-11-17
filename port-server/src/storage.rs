//! Synchronous, single-connection SQLite foundation for the host prototype.
//!
//! All access must go through `try_with_connection`. In async code, run calls on
//! a bounded blocking executor, never on a Tokio reactor thread. This module is
//! not validated on PS5: its SQLite VFS, ABI and locking still require hardware
//! work. Connections and raw SQL must not be exposed to untrusted callers.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use std::{
    fmt,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex, TryLockError,
    },
    time::{Duration, Instant},
};

// "OBPS"; identifies our database and avoids migrating an unrelated file.
const APPLICATION_ID: i32 = 0x4f42_5053;
const CURRENT_VERSION: i32 = 13;
const BUSY_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub enum StorageError {
    Sqlite(rusqlite::Error),
    InvalidDatabase(&'static str),
    UnsupportedVersion(i32),
    UnexpectedJournalMode(String),
    Busy,
    Poisoned,
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "SQLite error: {e}"),
            Self::InvalidDatabase(reason) => write!(f, "not an OpenBot port database: {reason}"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported database schema version {version}")
            }
            Self::UnexpectedJournalMode(mode) => {
                write!(f, "SQLite did not select TRUNCATE journal mode: {mode}")
            }
            Self::Busy => write!(f, "database connection is busy"),
            Self::Poisoned => write!(f, "database connection lock is poisoned"),
        }
    }
}

impl std::error::Error for StorageError {}
impl From<rusqlite::Error> for StorageError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

pub struct Storage {
    connection: Mutex<Connection>,
    ops: AtomicU64,
}

impl Storage {
    /// Opens a file database without creating its parent directory. Callers must
    /// provision an appropriate private directory and handle mount readiness.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let mut conn = Connection::open(path)?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        check_identity(&conn)?;

        let mode: String = conn.query_row("PRAGMA journal_mode = TRUNCATE", [], |r| r.get(0))?;
        if !mode.eq_ignore_ascii_case("truncate") {
            return Err(StorageError::UnexpectedJournalMode(mode));
        }
        conn.pragma_update(None, "foreign_keys", true)?;
        let foreign_keys: i32 = conn.pragma_query_value(None, "foreign_keys", |r| r.get(0))?;
        if foreign_keys != 1 {
            return Err(StorageError::InvalidDatabase(
                "foreign keys could not be enabled",
            ));
        }
        // Bound SQLite page & statement caches for PS5 shared Flexible Memory.
        let _ = conn.execute_batch("PRAGMA cache_size = -1536; PRAGMA temp_store = MEMORY;");
        conn.set_prepared_statement_cache_capacity(24);

        migrate(&mut conn)?;
        // Any run left in 'running'/'queued' when a previous process exited cannot stream anymore.
        let _ = conn.execute(
            "UPDATE port_runs SET status='failed' WHERE status='running'",
            [],
        );
        let _ = conn.execute(
            "UPDATE port_conversation_messages SET status='failed' WHERE status IN ('running', 'queued')",
            [],
        );
        let _ = conn.execute_batch("PRAGMA shrink_memory;");
        Ok(Self {
            connection: Mutex::new(conn),
            ops: AtomicU64::new(0),
        })
    }

    /// Uses the sole connection with a bounded wait. Call only from a bounded
    /// blocking executor; do not block a Tokio reactor thread. Keep transactions
    /// short and do not alter the connection's PRAGMAs.
    pub fn try_with_connection<T>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            match self.connection.try_lock() {
                Ok(mut conn) => {
                    let res = f(&mut conn);
                    if self.ops.fetch_add(1, Ordering::Relaxed) % 50 == 49 {
                        let _ = conn.execute_batch("PRAGMA shrink_memory;");
                    }
                    return res;
                }
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Err(TryLockError::WouldBlock) => return Err(StorageError::Busy),
                Err(TryLockError::Poisoned(_)) => return Err(StorageError::Poisoned),
            }
        }
    }
}

fn check_identity(conn: &Connection) -> Result<i32, StorageError> {
    let id: i32 = conn.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if id == 0 {
        let object: Option<String> = conn
            .query_row(
                "SELECT name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if version != 0 || object.is_some() {
            return Err(StorageError::InvalidDatabase(
                "unowned database is not empty",
            ));
        }
    } else if id != APPLICATION_ID {
        return Err(StorageError::InvalidDatabase("application ID differs"));
    }
    if version > CURRENT_VERSION || version < 0 {
        return Err(StorageError::UnsupportedVersion(version));
    }
    Ok(version)
}

fn migrate(conn: &mut Connection) -> Result<(), StorageError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    // Recheck after the exclusive writer reservation, before any schema change.
    let version = check_identity(&tx)?;
    if version == 0 {
        tx.execute_batch(include_str!("../migrations/0001_metadata.sql"))?;
        tx.pragma_update(None, "application_id", APPLICATION_ID)?;
        tx.pragma_update(None, "user_version", 1)?;
    }
    if version < 2 {
        tx.execute_batch(include_str!("../migrations/0002_local_auth.sql"))?;
        tx.pragma_update(None, "user_version", 2)?;
    }
    if version < 3 {
        tx.execute_batch(include_str!("../migrations/0003_bots.sql"))?;
        tx.pragma_update(None, "user_version", 3)?;
    }
    if version < 4 {
        tx.execute_batch(include_str!("../migrations/0004_conversations.sql"))?;
        tx.pragma_update(None, "user_version", 4)?;
    }
    if version < 5 {
        tx.execute_batch(include_str!("../migrations/0005_preferences.sql"))?;
        tx.pragma_update(None, "user_version", 5)?;
    }
    if version < 6 {
        tx.execute_batch(include_str!("../migrations/0006_run_events.sql"))?;
        tx.pragma_update(None, "user_version", 6)?;
    }
    if version < 7 {
        tx.execute_batch(include_str!("../migrations/0007_runs.sql"))?;
        tx.pragma_update(None, "user_version", 7)?;
    }
    if version < 8 {
        tx.execute_batch(include_str!("../migrations/0008_direct_threads.sql"))?;
        tx.pragma_update(None, "user_version", 8)?;
    }
    if version < 9 {
        tx.execute_batch(include_str!("../migrations/0009_governance.sql"))?;
        tx.pragma_update(None, "user_version", 9)?;
    }
    if version < 10 {
        tx.execute_batch(include_str!("../migrations/0010_compat.sql"))?;
        tx.pragma_update(None, "user_version", 10)?;
    }
    if version < 11 {
        tx.execute_batch(include_str!("../migrations/0011_approvals.sql"))?;
        tx.pragma_update(None, "user_version", 11)?;
    }
    if version < 12 {
        tx.execute_batch(include_str!("../migrations/0012_attachments_routines.sql"))?;
        tx.pragma_update(None, "user_version", 12)?;
    }
    if version < 13 {
        ensure_column(
            &tx,
            "port_approval_settings",
            "execution_mode",
            "TEXT NOT NULL DEFAULT 'ask' CHECK (execution_mode IN ('ask', 'auto', 'turbo'))",
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO port_approval_settings(
                organization_id, enforce_auto_review, custom_rules_enabled,
                host_commands_cap, action_kinds_json, execution_mode
            )
            SELECT id, 0, 1, 'ask', '{}', 'ask' FROM auth_organizations",
            [],
        )?;
        tx.pragma_update(None, "user_version", 13)?;
    }
    tx.commit()?;
    Ok(())
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool, StorageError> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn ensure_column(
    conn: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), StorageError> {
    if !column_exists(conn, table, column)? {
        conn.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
            [],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "openbot-storage-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn migrations_persist_and_sqlite_settings_are_verified() {
        let dir = test_dir();
        let path = dir.join("storage.db");
        let db = Storage::open(&path).unwrap();
        db.try_with_connection(|c| {
            let journal: String = c.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
            let fk: i32 = c.pragma_query_value(None, "foreign_keys", |r| r.get(0))?;
            assert_eq!(journal.to_lowercase(), "truncate");
            assert_eq!(fk, 1);
            c.execute(
                "INSERT INTO port_metadata(key, value) VALUES ('test', 'persisted')",
                [],
            )?;
            Ok(())
        })
        .unwrap();
        drop(db);
        let db = Storage::open(&path).unwrap();
        db.try_with_connection(|c| {
            let value: String = c.query_row(
                "SELECT value FROM port_metadata WHERE key='test'",
                [],
                |r| r.get(0),
            )?;
            assert_eq!(value, "persisted");
            Ok(())
        })
        .unwrap();
        drop(db);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_foreign_or_future_databases_without_migration() {
        let dir = test_dir();
        let path = dir.join("other.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute("CREATE TABLE unrelated (id INTEGER)", [])
            .unwrap();
        drop(conn);
        assert!(matches!(
            Storage::open(&path),
            Err(StorageError::InvalidDatabase(_))
        ));
        let future = dir.join("future.db");
        let conn = Connection::open(&future).unwrap();
        conn.pragma_update(None, "application_id", APPLICATION_ID)
            .unwrap();
        conn.pragma_update(None, "user_version", CURRENT_VERSION + 1)
            .unwrap();
        drop(conn);
        assert!(matches!(
            Storage::open(&future),
            Err(StorageError::UnsupportedVersion(_))
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn overload_is_rejected_after_bounded_wait() {
        let dir = test_dir();
        let db = Storage::open(dir.join("storage.db")).unwrap();
        let guard = db.connection.lock().unwrap();
        assert!(matches!(
            db.try_with_connection(|_| Ok(())),
            Err(StorageError::Busy)
        ));
        drop(guard);
        drop(db);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn short_connection_contention_is_retried() {
        let dir = test_dir();
        let db = Storage::open(dir.join("storage.db")).unwrap();
        let guard = db.connection.lock().unwrap();
        std::thread::scope(|scope| {
            let (started, received) = std::sync::mpsc::channel();
            let db_ref = &db;
            let task = scope.spawn(move || {
                started.send(()).unwrap();
                db_ref.try_with_connection(|_| Ok(()))
            });
            received.recv().unwrap();
            std::thread::sleep(Duration::from_millis(20));
            drop(guard);
            assert!(task.join().unwrap().is_ok());
        });
        drop(db);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn migrates_v12_approval_settings_idempotently_to_execution_mode() {
        let dir = test_dir();
        let path = dir.join("v12.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.pragma_update(None, "journal_mode", "TRUNCATE").unwrap();
            conn.pragma_update(None, "foreign_keys", true).unwrap();
            conn.execute_batch(include_str!("../migrations/0001_metadata.sql")).unwrap();
            conn.pragma_update(None, "application_id", APPLICATION_ID).unwrap();
            conn.execute_batch(include_str!("../migrations/0002_local_auth.sql")).unwrap();
            conn.execute_batch(include_str!("../migrations/0003_bots.sql")).unwrap();
            conn.execute_batch(include_str!("../migrations/0004_conversations.sql")).unwrap();
            conn.execute_batch(include_str!("../migrations/0005_preferences.sql")).unwrap();
            conn.execute_batch(include_str!("../migrations/0006_run_events.sql")).unwrap();
            conn.execute_batch(include_str!("../migrations/0007_runs.sql")).unwrap();
            conn.execute_batch(include_str!("../migrations/0008_direct_threads.sql")).unwrap();
            conn.execute_batch(include_str!("../migrations/0009_governance.sql")).unwrap();
            conn.execute_batch(include_str!("../migrations/0010_compat.sql")).unwrap();
            conn.execute_batch(include_str!("../migrations/0011_approvals.sql")).unwrap();
            conn.execute_batch(include_str!("../migrations/0012_attachments_routines.sql")).unwrap();
            conn.execute(
                "INSERT INTO auth_organizations(id, slug, name) VALUES ('default', 'default', 'OpenBot')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO auth_organizations(id, slug, name) VALUES ('org_seeded', 'org_seeded', 'Seeded')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO port_approval_settings(organization_id, enforce_auto_review, custom_rules_enabled, host_commands_cap, action_kinds_json)
                 VALUES ('default', 0, 1, 'ask', '{}')",
                [],
            )
            .unwrap();
            conn.pragma_update(None, "user_version", 12).unwrap();
        }

        let db = Storage::open(&path).unwrap();
        db.try_with_connection(|c| {
            let ver: i32 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
            assert_eq!(ver, 13);
            let mode_default: String = c.query_row(
                "SELECT execution_mode FROM port_approval_settings WHERE organization_id = 'default'",
                [],
                |r| r.get(0),
            )?;
            assert_eq!(mode_default, "ask");
            let (seeded_custom, seeded_mode): (bool, String) = c.query_row(
                "SELECT custom_rules_enabled, execution_mode FROM port_approval_settings WHERE organization_id = 'org_seeded'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            assert!(seeded_custom);
            assert_eq!(seeded_mode, "ask");
            Ok(())
        })
        .unwrap();
        drop(db);
        // Reopening again stays idempotent.
        let db2 = Storage::open(&path).unwrap();
        drop(db2);
        fs::remove_dir_all(dir).unwrap();
    }
}
