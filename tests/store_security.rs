use std::{
    fs::{self, Permissions},
    os::unix::fs::{PermissionsExt, symlink},
};

use crowsi_local_control_bridge::{BridgeError, DurableSecurityStore};
use rusqlite::Connection;

#[test]
fn durable_store_requires_absolute_private_non_symlink_state() {
    assert_eq!(
        DurableSecurityStore::open("relative.sqlite3", 3).expect_err("relative path"),
        BridgeError::Storage
    );
    let root = tempfile::tempdir().expect("temp");
    fs::set_permissions(root.path(), Permissions::from_mode(0o700)).expect("private parent");
    let real = root.path().join("real.sqlite3");
    let store = DurableSecurityStore::open(&real, 3).expect("secure state");
    let mode = fs::metadata(&real).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    drop(store);
    let linked = root.path().join("linked.sqlite3");
    symlink(&real, &linked).expect("symlink");
    assert_eq!(
        DurableSecurityStore::open(&linked, 3).expect_err("symlink"),
        BridgeError::Storage
    );
}

#[test]
fn unknown_or_unversioned_sqlite_schema_is_rejected() {
    let root = tempfile::tempdir().expect("temp");
    fs::set_permissions(root.path(), Permissions::from_mode(0o700)).expect("private parent");
    let path = root.path().join("rogue.sqlite3");
    let connection = Connection::open(&path).expect("rogue database");
    connection
        .execute_batch("CREATE TABLE injected(value TEXT);")
        .expect("rogue schema");
    drop(connection);
    fs::set_permissions(&path, Permissions::from_mode(0o600)).expect("private file");

    assert_eq!(
        DurableSecurityStore::open(path, 3).expect_err("unknown schema"),
        BridgeError::Storage
    );
}
