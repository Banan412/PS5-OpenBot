//! Isolated fail-closed audit foundation. This does not implement upstream
//! rules, human approval, grants, a public API or an action executor.
//! Calling it never authorizes or executes an action. Execute it only in a
//! bounded blocking task after authenticating the actor and validating origin.
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug)]
pub enum GateError {
    InvalidInput,
    Unauthorized,
    Conflict,
    Storage(rusqlite::Error),
    Clock,
}
impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput => write!(f, "invalid action"),
            Self::Unauthorized => write!(f, "action not authorized"),
            Self::Conflict => write!(f, "attempt conflict"),
            Self::Storage(_) => write!(f, "audit storage failure"),
            Self::Clock => write!(f, "clock unavailable"),
        }
    }
}
impl std::error::Error for GateError {}
impl From<rusqlite::Error> for GateError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Storage(e)
    }
}

/// Inputs must be supplied by a trusted server-side caller, never taken from a
/// browser as evidence of authorization. `canonical_action` is bounded JSON;
/// its digest is retained for correlation, not secrecy or tamper protection.
pub struct Action<'a> {
    pub organization_id: &'a str,
    pub actor_id: &'a str,
    pub bot_id: &'a str,
    pub conversation_id: &'a str,
    pub attempt_id: &'a str,
    pub canonical_action: &'a serde_json::Value,
}
#[derive(Debug, PartialEq, Eq)]
pub enum GateOutcome {
    Refused,
    AlreadyRefused,
}
fn valid_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 200 && !s.chars().any(char::is_control)
}
fn id() -> Result<String, GateError> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).map_err(|_| GateError::InvalidInput)?;
    Ok(b.iter().map(|v| format!("{v:02x}")).collect())
}

/// Atomically records an attempt and its refusal. Both rows are appended in a
/// single transaction or neither is. The same attempt can be replayed only for
/// exactly the same actor, bot, conversation and action. There is no allow path.
pub fn record_refusal(c: &mut Connection, a: &Action<'_>) -> Result<GateOutcome, GateError> {
    if [
        a.organization_id,
        a.actor_id,
        a.bot_id,
        a.conversation_id,
        a.attempt_id,
    ]
    .iter()
    .any(|s| !valid_id(s))
        || !a.canonical_action.is_object()
    {
        return Err(GateError::InvalidInput);
    }
    let serialized = serde_json::to_vec(a.canonical_action).map_err(|_| GateError::InvalidInput)?;
    if serialized.is_empty() || serialized.len() > 65536 {
        return Err(GateError::InvalidInput);
    }
    let hash = Sha256::digest(&serialized).to_vec();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .ok_or(GateError::Clock)?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let permitted:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM auth_memberships m JOIN auth_users u ON u.id=m.user_id JOIN port_bots b ON b.id=?3 AND b.organization_id=m.organization_id AND b.owner_id=m.user_id JOIN port_conversations c ON c.id=?4 AND c.organization_id=m.organization_id AND c.owner_id=m.user_id WHERE m.organization_id=?1 AND m.user_id=?2 AND u.revoked=0 AND c.deleted=0)",params![a.organization_id,a.actor_id,a.bot_id,a.conversation_id],|r|r.get(0))?;
    if !permitted {
        return Err(GateError::Unauthorized);
    }
    // Ensure the bot is a participant, not just another bot the same owner has.
    let bot_list: String = tx.query_row(
        "SELECT bot_ids_json FROM port_conversations WHERE id=?1",
        params![a.conversation_id],
        |r| r.get(0),
    )?;
    let bots: Vec<String> = serde_json::from_str(&bot_list).map_err(|_| GateError::InvalidInput)?;
    if !bots.iter().any(|bot| bot == a.bot_id) {
        return Err(GateError::Unauthorized);
    }
    let previous:Option<(String,String,Vec<u8>)>=tx.query_row("SELECT bot_id,conversation_id,action_digest FROM port_governance_audit WHERE organization_id=?1 AND actor_id=?2 AND attempt_id=?3 AND phase='refused'",params![a.organization_id,a.actor_id,a.attempt_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    if let Some((bot, conversation, old)) = previous {
        return if bot == a.bot_id && conversation == a.conversation_id && old == hash {
            Ok(GateOutcome::AlreadyRefused)
        } else {
            Err(GateError::Conflict)
        };
    }
    for phase in ["intent", "refused"] {
        tx.execute("INSERT INTO port_governance_audit(id,organization_id,actor_id,bot_id,conversation_id,attempt_id,phase,action_digest,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![id()?,a.organization_id,a.actor_id,a.bot_id,a.conversation_id,a.attempt_id,phase,hash,now])?;
    }
    tx.commit()?;
    Ok(GateOutcome::Refused)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn database() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.pragma_update(None, "foreign_keys", true).unwrap();
        c.execute_batch("CREATE TABLE auth_users(id TEXT PRIMARY KEY,revoked INTEGER NOT NULL);CREATE TABLE auth_organizations(id TEXT PRIMARY KEY);CREATE TABLE auth_memberships(user_id TEXT,organization_id TEXT);CREATE TABLE port_bots(id TEXT PRIMARY KEY,organization_id TEXT,owner_id TEXT);CREATE TABLE port_conversations(id TEXT PRIMARY KEY,organization_id TEXT,owner_id TEXT,bot_ids_json TEXT,deleted INTEGER); INSERT INTO auth_users VALUES('u',0),('x',0);INSERT INTO auth_organizations VALUES('org');INSERT INTO auth_memberships VALUES('u','org');INSERT INTO port_bots VALUES('bot','org','u'),('other','org','u');INSERT INTO port_conversations VALUES('conv','org','u','[\"bot\"]',0);").unwrap();
        c.execute_batch(include_str!("../migrations/0009_governance.sql"))
            .unwrap();
        c
    }
    #[test]
    fn refusal_is_atomic_idempotent_private_and_append_only() {
        let mut c = database();
        let payload = json!({"tool":"reader","secret":"private content"});
        let a = Action {
            organization_id: "org",
            actor_id: "u",
            bot_id: "bot",
            conversation_id: "conv",
            attempt_id: "attempt",
            canonical_action: &payload,
        };
        assert_eq!(record_refusal(&mut c, &a).unwrap(), GateOutcome::Refused);
        assert_eq!(
            record_refusal(&mut c, &a).unwrap(),
            GateOutcome::AlreadyRefused
        );
        let count: i64 = c
            .query_row("SELECT COUNT(*) FROM port_governance_audit", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 2);
        let leaked:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM port_governance_audit WHERE CAST(action_digest AS TEXT) LIKE '%private content%')",[],|r|r.get(0)).unwrap();
        assert!(!leaked);
        assert!(c
            .execute("UPDATE port_governance_audit SET phase='refused'", [])
            .is_err());
        assert!(c.execute("DELETE FROM port_governance_audit", []).is_err());
        assert!(c.execute("INSERT OR REPLACE INTO port_governance_audit SELECT * FROM port_governance_audit LIMIT 1",[]).is_err());
        let other = json!({"tool":"writer"});
        let conflict = Action {
            canonical_action: &other,
            ..a
        };
        assert!(matches!(
            record_refusal(&mut c, &conflict),
            Err(GateError::Conflict)
        ));
    }
    #[test]
    fn denies_wrong_owner_wrong_bot_and_rolls_back_audit_errors() {
        let mut c = database();
        let payload = json!({"action":"read"});
        let a = Action {
            organization_id: "org",
            actor_id: "x",
            bot_id: "bot",
            conversation_id: "conv",
            attempt_id: "a",
            canonical_action: &payload,
        };
        assert!(matches!(
            record_refusal(&mut c, &a),
            Err(GateError::Unauthorized)
        ));
        let wrong = Action {
            actor_id: "u",
            bot_id: "other",
            ..a
        };
        assert!(matches!(
            record_refusal(&mut c, &wrong),
            Err(GateError::Unauthorized)
        ));
        c.execute_batch("CREATE TRIGGER simulate_failure BEFORE INSERT ON port_governance_audit WHEN NEW.phase='refused' BEGIN SELECT RAISE(ABORT,'simulated'); END;").unwrap();
        let good = Action {
            bot_id: "bot",
            ..wrong
        };
        assert!(matches!(
            record_refusal(&mut c, &good),
            Err(GateError::Storage(_))
        ));
        let count: i64 = c
            .query_row("SELECT COUNT(*) FROM port_governance_audit", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
    }
}
