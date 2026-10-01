use std::{
    fs,
    os::unix::{
        fs::{PermissionsExt, symlink},
        net::UnixListener,
    },
};

use crowsi_local_control_bridge::{BridgeError, PrivateUnixListener};

#[test]
fn recovering_bind_replaces_only_an_owner_private_stale_socket() {
    if !filesystem_unix_sockets_available() {
        return;
    }
    let root = private_root();
    let path = root.path().join("control.sock");
    let stale = UnixListener::bind(&path).expect("stale socket");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private socket");
    drop(stale);

    let recovered = PrivateUnixListener::bind_recovering_stale(&path).expect("recovered listener");
    assert!(std::os::unix::net::UnixStream::connect(&path).is_ok());
    drop(recovered);
    assert!(fs::symlink_metadata(path).is_err());
}

#[test]
fn recovering_bind_preserves_active_and_ambiguous_paths() {
    if !filesystem_unix_sockets_available() {
        return;
    }
    let root = private_root();
    let active_path = root.path().join("active.sock");
    let active = UnixListener::bind(&active_path).expect("active socket");
    fs::set_permissions(&active_path, fs::Permissions::from_mode(0o600)).expect("private socket");
    assert_storage_error(&active_path);
    assert!(std::os::unix::net::UnixStream::connect(&active_path).is_ok());
    drop(active);

    let managed_path = root.path().join("managed.sock");
    let managed =
        PrivateUnixListener::bind_recovering_stale(&managed_path).expect("managed socket");
    assert_storage_error(&managed_path);
    assert!(std::os::unix::net::UnixStream::connect(&managed_path).is_ok());
    drop(managed);

    let regular = root.path().join("regular.sock");
    fs::write(&regular, b"replacement").expect("regular replacement");
    fs::set_permissions(&regular, fs::Permissions::from_mode(0o600)).expect("private file");
    assert_storage_error(&regular);
    assert_eq!(fs::read(&regular).expect("preserved file"), b"replacement");

    let target = root.path().join("target.sock");
    let target_listener = UnixListener::bind(&target).expect("target socket");
    let link = root.path().join("link.sock");
    symlink(&target, &link).expect("socket symlink");
    assert_storage_error(&link);
    assert!(
        fs::symlink_metadata(&link)
            .expect("preserved link")
            .file_type()
            .is_symlink()
    );
    drop(target_listener);
}

#[test]
fn recovering_bind_rejects_non_private_socket_and_parent() {
    if !filesystem_unix_sockets_available() {
        return;
    }
    let root = private_root();
    let path = root.path().join("accessible.sock");
    let stale = UnixListener::bind(&path).expect("stale socket");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).expect("accessible socket");
    drop(stale);
    assert_storage_error(&path);
    assert!(fs::symlink_metadata(&path).is_ok());

    fs::remove_file(&path).expect("remove test socket");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o750)).expect("accessible parent");
    assert_storage_error(&path);
}

fn assert_storage_error(path: &std::path::Path) {
    assert_eq!(
        PrivateUnixListener::bind_recovering_stale(path).err(),
        Some(BridgeError::Storage)
    );
}

fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("temporary root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
    root
}

fn filesystem_unix_sockets_available() -> bool {
    let root = private_root();
    UnixListener::bind(root.path().join("probe.sock")).is_ok()
}
