use rusqlite::Connection;

use crate::BridgeError;

const APPLICATION_ID: i64 = 1_128_416_711;
const VERSION: i64 = 4;

const SECURITY: &str = "CREATE TABLE IF NOT EXISTS security_state(
  id INTEGER PRIMARY KEY CHECK(id=1),
  clock INTEGER NOT NULL CHECK(clock>=0)
) STRICT;";
const REVOCATION: &str = "CREATE TABLE IF NOT EXISTS revocation_watermarks(
  scope TEXT NOT NULL,
  binding TEXT NOT NULL,
  epoch INTEGER NOT NULL CHECK(epoch>=0),
  PRIMARY KEY(scope,binding)
) STRICT;";
const CONSUMED: &str = "CREATE TABLE IF NOT EXISTS consumed(
  request_id TEXT PRIMARY KEY,
  reservation_id TEXT UNIQUE NOT NULL,
  at INTEGER NOT NULL CHECK(at>=0)
) STRICT;";
const STATUS_NONCES: &str = "CREATE TABLE IF NOT EXISTS identity_status_nonces(
  nonce_digest TEXT PRIMARY KEY,
  observed_at INTEGER NOT NULL CHECK(observed_at>=0)
) STRICT;";
const STATUS_ANCHORS: &str = "CREATE TABLE IF NOT EXISTS identity_status_anchors(
  binding_digest TEXT PRIMARY KEY,
  session_ref_digest TEXT NOT NULL,
  posture_revision INTEGER NOT NULL CHECK(posture_revision>0),
  subject_epoch INTEGER NOT NULL CHECK(subject_epoch>0),
  service_epoch INTEGER NOT NULL CHECK(service_epoch>0),
  device_epoch INTEGER NOT NULL CHECK(device_epoch>0),
  session_epoch INTEGER NOT NULL CHECK(session_epoch>0),
  issued_at INTEGER NOT NULL CHECK(issued_at>=0),
  expires_at INTEGER NOT NULL CHECK(expires_at>issued_at)
) STRICT;";
const AUDIT: &str = "CREATE TABLE IF NOT EXISTS audit(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id TEXT NOT NULL,
  subject_digest TEXT NOT NULL,
  action TEXT NOT NULL,
  resource_digest TEXT NOT NULL,
  event_digest TEXT NOT NULL,
  at INTEGER NOT NULL CHECK(at>=0)
) STRICT;";

pub(crate) fn initialize(connection: &mut Connection) -> Result<(), BridgeError> {
    let application = pragma(connection, "application_id")?;
    let version = pragma(connection, "user_version")?;
    if application == 0 && version == 0 && user_table_count(connection)? == 0 {
        connection
            .execute_batch(&format!(
                "PRAGMA application_id={APPLICATION_ID};
                 PRAGMA user_version={VERSION};
                 {SECURITY}{REVOCATION}{CONSUMED}{STATUS_NONCES}{STATUS_ANCHORS}{AUDIT}"
            ))
            .map_err(|_| BridgeError::Storage)?;
    } else if application != APPLICATION_ID || version != VERSION {
        return Err(BridgeError::Storage);
    }
    if !exact_schema(connection)? {
        return Err(BridgeError::Storage);
    }
    connection
        .execute(
            "INSERT OR IGNORE INTO security_state(id,clock) VALUES(1,0)",
            [],
        )
        .map_err(|_| BridgeError::Storage)?;
    Ok(())
}

fn exact_schema(connection: &Connection) -> Result<bool, BridgeError> {
    if user_table_count(connection)? != 6 {
        return Ok(false);
    }
    for (name, expected) in [
        ("security_state", SECURITY),
        ("revocation_watermarks", REVOCATION),
        ("consumed", CONSUMED),
        ("identity_status_nonces", STATUS_NONCES),
        ("identity_status_anchors", STATUS_ANCHORS),
        ("audit", AUDIT),
    ] {
        if !table_matches(connection, name, expected)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn table_matches(connection: &Connection, name: &str, expected: &str) -> Result<bool, BridgeError> {
    let actual: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
            [name],
            |row| row.get(0),
        )
        .map_err(|_| BridgeError::Storage)?;
    Ok(compact(&actual) == compact(&expected.replace(" IF NOT EXISTS", "")))
}

fn user_table_count(connection: &Connection) -> Result<i64, BridgeError> {
    connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| BridgeError::Storage)
}

fn pragma(connection: &Connection, name: &str) -> Result<i64, BridgeError> {
    connection
        .pragma_query_value(None, name, |row| row.get(0))
        .map_err(|_| BridgeError::Storage)
}

fn compact(value: &str) -> String {
    value
        .trim_end_matches(';')
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect()
}
