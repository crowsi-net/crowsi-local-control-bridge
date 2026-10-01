use std::{
    fs::{self, symlink_metadata},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::UnixListener,
    },
    path::{Path, PathBuf},
};

use nix::unistd::Uid;

use crate::BridgeError;

mod recovery;

/// Owns one private Unix listener and removes only the inode it created.
pub struct PrivateUnixListener {
    listener: UnixListener,
    path: PathBuf,
    device: u64,
    inode: u64,
    _recovery_lock: Option<recovery::SocketRecoveryLock>,
}

impl PrivateUnixListener {
    /// Binds a non-symlink socket below an owner-only canonical directory.
    ///
    /// # Errors
    ///
    /// Rejects relative, pre-existing, group-accessible, or replaced paths.
    pub fn bind(path: impl AsRef<Path>) -> Result<Self, BridgeError> {
        let path = path.as_ref();
        validate_parent(path)?;
        require_missing(path)?;
        Self::bind_new(path, None)
    }

    /// Binds after removing an unchanged, owner-only socket with no live listener.
    ///
    /// # Errors
    ///
    /// Rejects active sockets, replacements, non-sockets, symlinks, and unsafe ownership.
    pub fn bind_recovering_stale(path: impl AsRef<Path>) -> Result<Self, BridgeError> {
        let path = path.as_ref();
        validate_parent(path)?;
        let recovery_lock = recovery::prepare_path(path)?;
        Self::bind_new(path, Some(recovery_lock))
    }

    fn bind_new(
        path: &Path,
        recovery_lock: Option<recovery::SocketRecoveryLock>,
    ) -> Result<Self, BridgeError> {
        let listener = UnixListener::bind(path).map_err(|_| BridgeError::Storage)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| BridgeError::Storage)?;
        let metadata = validate_socket(path)?;
        Ok(Self {
            listener,
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
            _recovery_lock: recovery_lock,
        })
    }

    #[must_use]
    pub const fn listener(&self) -> &UnixListener {
        &self.listener
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn require_missing(path: &Path) -> Result<(), BridgeError> {
    match symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(BridgeError::Storage),
    }
}

impl Drop for PrivateUnixListener {
    fn drop(&mut self) {
        let Ok(metadata) = symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn validate_parent(path: &Path) -> Result<(), BridgeError> {
    if !path.is_absolute() {
        return Err(BridgeError::Storage);
    }
    let parent = path.parent().ok_or(BridgeError::Storage)?;
    if parent.canonicalize().map_err(|_| BridgeError::Storage)? != parent {
        return Err(BridgeError::Storage);
    }
    let metadata = symlink_metadata(parent).map_err(|_| BridgeError::Storage)?;
    if !metadata.is_dir()
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(BridgeError::Storage);
    }
    Ok(())
}

fn validate_socket(path: &Path) -> Result<std::fs::Metadata, BridgeError> {
    let metadata = symlink_metadata(path).map_err(|_| BridgeError::Storage)?;
    validate_socket_metadata(&metadata)?;
    Ok(metadata)
}

fn validate_socket_metadata(metadata: &std::fs::Metadata) -> Result<(), BridgeError> {
    if !metadata.file_type().is_socket()
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(BridgeError::Storage);
    }
    Ok(())
}
