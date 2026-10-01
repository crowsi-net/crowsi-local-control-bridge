use crate::BridgeAction;
use serde::Serialize;
use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PeerAttestation {
    pub(crate) pid: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) process_start_ticks: u64,
    pub(crate) executable_sha256: String,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct DispatchTicket {
    pub schema: &'static str,
    pub request_id: String,
    pub reservation_id: String,
    pub action: BridgeAction,
    pub resource: String,
    pub purpose: String,
    pub body_sha256: String,
    pub command_digest: String,
    #[serde(skip_serializing)]
    pub service_id: String,
    #[serde(skip_serializing)]
    pub pairwise_subject: String,
    #[serde(skip_serializing)]
    pub device_id: String,
    #[serde(skip_serializing)]
    pub device_proof_key_ref: String,
    #[serde(skip_serializing)]
    pub session_ref: String,
    #[serde(skip_serializing)]
    pub workload_id: String,
    #[serde(skip_serializing)]
    pub actor_profile_id: String,
    #[serde(skip_serializing)]
    pub sender_public_key_hex: String,
    #[serde(skip_serializing)]
    pub device_posture_revision: u64,
    #[serde(skip_serializing)]
    pub subject_revocation_epoch: u64,
    #[serde(skip_serializing)]
    pub service_revocation_epoch: u64,
    #[serde(skip_serializing)]
    pub device_revocation_epoch: u64,
    #[serde(skip_serializing)]
    pub session_revocation_epoch: u64,
    pub authorized_at_epoch_s: i64,
}

impl fmt::Debug for DispatchTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchTicket")
            .field("request_id", &"[REDACTED]")
            .field("reservation_id", &"[REDACTED]")
            .field("action", &self.action)
            .field("body_sha256", &self.body_sha256)
            .field("command_digest", &self.command_digest)
            .field("authorized_at_epoch_s", &self.authorized_at_epoch_s)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuditRecord {
    pub sequence: u64,
    pub request_id: String,
    pub action: BridgeAction,
    pub resource_digest: String,
    pub event_digest: String,
    pub occurred_at_epoch_s: i64,
}
