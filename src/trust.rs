use crowsi_control_contracts::validate_spiffe_workload;
use ed25519_dalek::VerifyingKey;

use crate::{BridgeError, IdentityStatusTrust};

#[derive(Clone)]
pub struct BridgeTrust {
    pub(crate) pa_key: VerifyingKey,
    pub(crate) caller_uid: u32,
    pub(crate) caller_group_id: u32,
    pub(crate) workload_id: String,
    pub(crate) executable_sha256: String,
    pub(crate) identity_status: IdentityStatusTrust,
}

impl BridgeTrust {
    /// Builds the pinned PA and workload trust boundary.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::Contract`] for weak keys or ambiguous identities.
    pub fn new(
        pa_public_key: [u8; 32],
        caller_uid: u32,
        caller_group_id: u32,
        workload_id: &str,
        executable_sha256: &str,
        identity_status: IdentityStatusTrust,
    ) -> Result<Self, BridgeError> {
        let pa_key = VerifyingKey::from_bytes(&pa_public_key).map_err(|_| BridgeError::Contract)?;
        if pa_key.is_weak()
            || caller_uid == 0
            || caller_group_id == 0
            || validate_spiffe_workload(workload_id).is_err()
            || !valid_digest(executable_sha256)
            || pa_key.to_bytes() == identity_status.public_key()
        {
            return Err(BridgeError::Contract);
        }
        Ok(Self {
            pa_key,
            caller_uid,
            caller_group_id,
            workload_id: workload_id.into(),
            executable_sha256: executable_sha256.into(),
            identity_status,
        })
    }
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
