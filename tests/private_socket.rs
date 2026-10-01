use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink},
};

use crowsi_local_control_bridge::{BridgeError, PrivateUnixListener};

#[test]
fn private_listener_has_owner_only_mode_and_cleans_its_inode() {
    if !filesystem_unix_sockets_available() {
        return;
    }
    let root = private_root();
    let path = root.path().join("control.sock");
    {
        let socket = PrivateUnixListener::bind(&path).expect("bind");
        assert_eq!(socket.path(), path);
        let metadata = fs::symlink_metadata(&path).expect("socket metadata");
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.mode() & 0o777, 0o600);
    }
    assert!(!path.exists());
}

#[test]
fn listener_rejects_ambiguous_or_accessible_paths() {
    assert_eq!(
        PrivateUnixListener::bind("relative.sock").err(),
        Some(BridgeError::Storage)
    );
    let root = tempfile::tempdir().expect("temporary root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).expect("permissive root");
    assert_eq!(
        PrivateUnixListener::bind(root.path().join("control.sock")).err(),
        Some(BridgeError::Storage)
    );

    let private = private_root();
    let occupied = private.path().join("occupied");
    fs::write(&occupied, b"not-a-socket").expect("occupied path");
    assert_eq!(
        PrivateUnixListener::bind(occupied).err(),
        Some(BridgeError::Storage)
    );
}

#[test]
fn drop_does_not_remove_a_replaced_path() {
    if !filesystem_unix_sockets_available() {
        return;
    }
    let root = private_root();
    let path = root.path().join("control.sock");
    let socket = PrivateUnixListener::bind(&path).expect("bind");
    fs::remove_file(&path).expect("remove original socket");
    fs::write(&path, b"replacement").expect("replacement");
    drop(socket);
    assert_eq!(
        fs::read(&path).expect("preserved replacement"),
        b"replacement"
    );
}

#[test]
fn symlinked_parent_is_rejected() {
    let root = private_root();
    let target = root.path().join("target");
    fs::create_dir(&target).expect("target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).expect("private target");
    let alias = root.path().join("alias");
    symlink(&target, &alias).expect("symlink");
    assert_eq!(
        PrivateUnixListener::bind(alias.join("control.sock")).err(),
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
    std::os::unix::net::UnixListener::bind(root.path().join("probe.sock")).is_ok()
}
