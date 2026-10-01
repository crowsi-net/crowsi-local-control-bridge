use std::{
    fs::{File, read_to_string},
    io::Read,
    os::unix::net::UnixStream,
};

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use sha2::{Digest, Sha256};

use crate::{BridgeError, model::PeerAttestation};

#[cfg(test)]
mod tests;

/// Attests the kernel-authenticated Unix peer and its pinned executable image.
///
/// # Errors
///
/// Fails closed when peer credentials, process identity, or executable bytes
/// cannot be read consistently.
pub(crate) fn attest_unix_peer(stream: &UnixStream) -> Result<PeerAttestation, BridgeError> {
    let credentials =
        getsockopt(stream, PeerCredentials).map_err(|_| BridgeError::PeerAttestation)?;
    let pid = u32::try_from(credentials.pid()).map_err(|_| BridgeError::PeerAttestation)?;
    let before = process_start_ticks(pid)?;
    let executable_sha256 = executable_digest(pid)?;
    let after = process_start_ticks(pid)?;
    if before != after {
        return Err(BridgeError::PeerAttestation);
    }
    Ok(PeerAttestation {
        pid,
        uid: credentials.uid(),
        gid: credentials.gid(),
        process_start_ticks: before,
        executable_sha256,
    })
}

fn executable_digest(pid: u32) -> Result<String, BridgeError> {
    let mut executable =
        File::open(format!("/proc/{pid}/exe")).map_err(|_| BridgeError::PeerAttestation)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8_192];
    loop {
        let count = executable
            .read(&mut buffer)
            .map_err(|_| BridgeError::PeerAttestation)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn process_start_ticks(pid: u32) -> Result<u64, BridgeError> {
    let stat =
        read_to_string(format!("/proc/{pid}/stat")).map_err(|_| BridgeError::PeerAttestation)?;
    let close = stat.rfind(')').ok_or(BridgeError::PeerAttestation)?;
    stat.get(close + 2..)
        .and_then(|tail| tail.split_whitespace().nth(19))
        .and_then(|value| value.parse().ok())
        .ok_or(BridgeError::PeerAttestation)
}
