use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::{Child, Command},
};

use sha2::{Digest, Sha256};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn path_replacement_cannot_change_the_running_executable_digest() {
    let root = tempfile::tempdir().expect("temporary root");
    let executable = root.path().join("worker");
    let original = fs::read("/bin/sleep").expect("sleep binary");
    fs::write(&executable, &original).expect("worker binary");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).expect("executable mode");
    let child = Command::new(&executable).arg("30").spawn().expect("worker");
    let child = ChildGuard(child);

    fs::remove_file(&executable).expect("unlink executing path");
    fs::copy("/bin/true", &executable).expect("replace path");
    let digest = super::executable_digest(child.0.id()).expect("running inode digest");

    assert_eq!(digest, format!("sha256:{:x}", Sha256::digest(original)));
}
