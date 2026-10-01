use std::{
    fs::{self, File, OpenOptions, symlink_metadata},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

use nix::{libc, unistd::Uid};

use crate::BridgeError;

pub(super) struct SocketRecoveryLock {
    _file: File,
}

pub(super) fn prepare_path(path: &Path) -> Result<SocketRecoveryLock, BridgeError> {
    let lock = acquire_lock(path)?;
    let stale = match symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(lock),
        Err(_) => return Err(BridgeError::Storage),
    };
    super::validate_socket_metadata(&stale)?;
    require_not_registered(path)?;
    remove_unchanged(path, &stale)?;
    Ok(lock)
}

fn acquire_lock(socket: &Path) -> Result<SocketRecoveryLock, BridgeError> {
    let path = lock_path(socket);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|_| BridgeError::Storage)?;
    let opened = file.metadata().map_err(|_| BridgeError::Storage)?;
    let linked = symlink_metadata(path).map_err(|_| BridgeError::Storage)?;
    if !opened.is_file()
        || opened.uid() != Uid::effective().as_raw()
        || opened.mode() & 0o777 != 0o600
        || opened.nlink() != 1
        || opened.dev() != linked.dev()
        || opened.ino() != linked.ino()
    {
        return Err(BridgeError::Storage);
    }
    file.try_lock().map_err(|_| BridgeError::Storage)?;
    Ok(SocketRecoveryLock { _file: file })
}

fn lock_path(socket: &Path) -> PathBuf {
    let mut value = socket.as_os_str().to_os_string();
    value.push(".lock");
    PathBuf::from(value)
}

fn remove_unchanged(path: &Path, stale: &std::fs::Metadata) -> Result<(), BridgeError> {
    let current = symlink_metadata(path).map_err(|_| BridgeError::Storage)?;
    super::validate_socket_metadata(&current)?;
    if current.dev() != stale.dev() || current.ino() != stale.ino() {
        return Err(BridgeError::Storage);
    }
    fs::remove_file(path).map_err(|_| BridgeError::Storage)
}

#[cfg(target_os = "linux")]
fn require_not_registered(path: &Path) -> Result<(), BridgeError> {
    let expected = path.as_os_str().as_bytes();
    if expected.iter().any(u8::is_ascii_whitespace) {
        return Err(BridgeError::Storage);
    }
    let sockets = fs::read("/proc/net/unix").map_err(|_| BridgeError::Storage)?;
    let active = sockets.split(|byte| *byte == b'\n').any(|line| {
        line.split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty())
            .nth(7)
            .is_some_and(|registered| registered == expected)
    });
    if active {
        Err(BridgeError::Storage)
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
fn require_not_registered(_path: &Path) -> Result<(), BridgeError> {
    Err(BridgeError::Storage)
}
