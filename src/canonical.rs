use sha2::{Digest, Sha256};

use crate::{BridgeAction, ControlAuthorizationV2, ControlRequestV1};

#[must_use]
pub fn canonical_request(value: &ControlRequestV1) -> Vec<u8> {
    let mut bytes = domain("crowsi.local-control.request.v1");
    fields(
        &mut bytes,
        [
            value.schema.as_str(),
            value.request_id.as_str(),
            action(value.action),
            value.resource.as_str(),
            value.purpose.as_str(),
            value.body_sha256.as_str(),
        ],
    );
    bytes
}

#[must_use]
pub fn canonical_authorization(value: &ControlAuthorizationV2) -> Vec<u8> {
    let mut bytes = domain("crowsi.local-control.authorization.v2");
    fields(
        &mut bytes,
        [
            value.schema.as_str(),
            value.issuer.as_str(),
            value.audience.as_str(),
            value.service_id.as_str(),
            value.pairwise_subject.as_str(),
            value.device_id.as_str(),
            value.device_proof_key_ref.as_str(),
            value.session_ref.as_str(),
            value.device_posture.as_str(),
            &value.device_posture_revision.to_string(),
            &value.subject_revocation_epoch.to_string(),
            &value.service_revocation_epoch.to_string(),
            &value.device_revocation_epoch.to_string(),
            &value.session_revocation_epoch.to_string(),
            value.workload_id.as_str(),
            value.actor_profile_id.as_str(),
            value.assurance.as_str(),
            if value.user_verification {
                "true"
            } else {
                "false"
            },
            value.sender_public_key_hex.as_str(),
            value.request_id.as_str(),
            action(value.action),
            value.resource.as_str(),
            value.purpose.as_str(),
            value.body_sha256.as_str(),
            value.reservation_id.as_str(),
            &value.issued_at_epoch_s.to_string(),
            &value.expires_at_epoch_s.to_string(),
        ],
    );
    bytes
}

#[must_use]
pub fn sha256_digest(value: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(value)))
}

fn domain(value: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    put(&mut bytes, value);
    bytes
}

fn fields<'a>(bytes: &mut Vec<u8>, values: impl IntoIterator<Item = &'a str>) {
    for value in values {
        put(bytes, value);
    }
}

fn put(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn action(value: BridgeAction) -> &'static str {
    match value {
        BridgeAction::ContainAsset => "contain-asset",
        BridgeAction::RevokeCredential => "revoke-credential",
        BridgeAction::EnrollCredential => "enroll-credential",
        BridgeAction::UseCredential => "use-credential",
        BridgeAction::ObserveProvider => "observe-provider",
        BridgeAction::RunDiagnostic => "run-diagnostic",
    }
}
