use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_local_control_bridge::{BridgeError, DurableSecurityStore};
use rusqlite::Connection;

const APPLICATION_ID: i64 = 1_128_416_711;

#[test]
fn readme_describes_current_v4_state_and_legacy_rejection() {
    let readme = include_str!("../README.md");
    assert!(readme.contains("SQLite v4"));
    assert!(readme.contains("v2/v3"));
    assert!(!readme.contains("SQLite v2はexact schemaの場合だけmanaged migration"));
    assert!(!readme.contains("SQLite v2からv3への初回起動"));
}

#[test]
// OP-15
fn legacy_v2_state_is_rejected_without_implicit_migration() {
    let root = private_root();
    let path = root.path().join("bridge.sqlite3");
    let connection = create_v2(&path);
    connection
        .execute("INSERT INTO security_state(id,clock) VALUES(1,44)", [])
        .expect("clock");
    connection
        .execute(
            "INSERT INTO revocation_watermarks(scope,binding,epoch) VALUES('device','unsigned',99)",
            [],
        )
        .expect("unsigned epoch");
    connection
        .execute(
            "INSERT INTO consumed(request_id,reservation_id,at) VALUES('request:a','reservation:a',43)",
            [],
        )
        .expect("replay record");
    connection
        .execute(
            "INSERT INTO audit(request_id,subject_digest,action,resource_digest,event_digest,at)
             VALUES('request:a','sha256:subject','enroll-credential','sha256:resource','sha256:event',43)",
            [],
        )
        .expect("audit record");
    drop(connection);

    assert_eq!(
        DurableSecurityStore::open(&path, 20).expect_err("v2 rejected"),
        BridgeError::Storage
    );
    let rejected = Connection::open(&path).expect("legacy state");
    assert_eq!(pragma(&rejected, "user_version"), 2);
    assert_eq!(count(&rejected, "revocation_watermarks"), 1);
    assert_eq!(count(&rejected, "consumed"), 1);
    assert_eq!(count(&rejected, "audit"), 1);
    assert_eq!(
        rejected
            .query_row("SELECT clock FROM security_state WHERE id=1", [], |row| row
                .get::<_, i64>(0))
            .expect("clock"),
        44
    );
}

#[test]
fn legacy_v3_without_durable_status_anchors_is_rejected() {
    let root = private_root();
    let path = root.path().join("bridge.sqlite3");
    let connection = create_v2(&path);
    connection
        .execute_batch(
            "CREATE TABLE identity_status_nonces(
             nonce_digest TEXT PRIMARY KEY,observed_at INTEGER NOT NULL CHECK(observed_at>=0)
             ) STRICT; PRAGMA user_version=3;",
        )
        .expect("v3 schema");
    drop(connection);
    assert_eq!(
        DurableSecurityStore::open(&path, 20).expect_err("v3 rejected"),
        BridgeError::Storage
    );
}

#[test]
fn v2_with_an_unknown_table_is_rejected_without_mutation() {
    let root = private_root();
    let path = root.path().join("bridge.sqlite3");
    let connection = create_v2(&path);
    connection
        .execute(
            "CREATE TABLE attacker_claim(epoch INTEGER NOT NULL) STRICT",
            [],
        )
        .expect("unexpected table");
    drop(connection);

    assert!(matches!(
        DurableSecurityStore::open(&path, 20),
        Err(BridgeError::Storage)
    ));
    let rejected = Connection::open(&path).expect("rejected state remains readable");
    assert_eq!(pragma(&rejected, "user_version"), 2);
    assert_eq!(count(&rejected, "attacker_claim"), 0);
}

fn create_v2(path: &std::path::Path) -> Connection {
    fs::write(path, []).expect("state file");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private state");
    let connection = Connection::open(path).expect("state");
    connection
        .execute_batch(&format!(
            "PRAGMA application_id={APPLICATION_ID};
             PRAGMA user_version=2;
             CREATE TABLE security_state(id INTEGER PRIMARY KEY CHECK(id=1),clock INTEGER NOT NULL CHECK(clock>=0)) STRICT;
             CREATE TABLE revocation_watermarks(scope TEXT NOT NULL,binding TEXT NOT NULL,epoch INTEGER NOT NULL CHECK(epoch>=0),PRIMARY KEY(scope,binding)) STRICT;
             CREATE TABLE consumed(request_id TEXT PRIMARY KEY,reservation_id TEXT UNIQUE NOT NULL,at INTEGER NOT NULL CHECK(at>=0)) STRICT;
             CREATE TABLE audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,request_id TEXT NOT NULL,subject_digest TEXT NOT NULL,action TEXT NOT NULL,resource_digest TEXT NOT NULL,event_digest TEXT NOT NULL,at INTEGER NOT NULL CHECK(at>=0)) STRICT;"
        ))
        .expect("v2 schema");
    connection
}

fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
    root
}

fn pragma(connection: &Connection, name: &str) -> i64 {
    connection
        .pragma_query_value(None, name, |row| row.get(0))
        .expect("pragma")
}

fn count(connection: &Connection, table: &str) -> i64 {
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .expect("count")
}
