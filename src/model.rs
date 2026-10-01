use serde::{Deserialize, Serialize};

pub(crate) use crate::model_dispatch::PeerAttestation;
pub use crate::model_dispatch::{AuditRecord, DispatchTicket};
pub use crate::model_readiness::{BridgeReadiness, ReadinessChecks};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BridgeAction {
    ContainAsset,
    RevokeCredential,
    EnrollCredential,
    UseCredential,
    ObserveProvider,
    RunDiagnostic,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub action: BridgeAction,
    pub resource: String,
    pub purpose: String,
    pub body_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlAuthorizationV2 {
    pub schema: String,
    pub issuer: String,
    pub audience: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub device_id: String,
    pub device_proof_key_ref: String,
    pub session_ref: String,
    pub device_posture: String,
    pub device_posture_revision: u64,
    pub subject_revocation_epoch: u64,
    pub service_revocation_epoch: u64,
    pub device_revocation_epoch: u64,
    pub session_revocation_epoch: u64,
    pub workload_id: String,
    pub actor_profile_id: String,
    pub assurance: String,
    pub user_verification: bool,
    pub sender_public_key_hex: String,
    pub request_id: String,
    pub action: BridgeAction,
    pub resource: String,
    pub purpose: String,
    pub body_sha256: String,
    pub reservation_id: String,
    pub issued_at_epoch_s: i64,
    pub expires_at_epoch_s: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthorization {
    pub document: ControlAuthorizationV2,
    pub signature_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SenderProof {
    pub signature_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IpcAuthorizationEnvelopeV2 {
    pub schema: String,
    pub request: ControlRequestV1,
    pub authorization: SignedAuthorization,
    pub sender_proof: SenderProof,
}
