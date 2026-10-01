use ed25519_dalek::{Signature, VerifyingKey};

use crate::{
    BridgeError, BridgeTrust, ControlAuthorizationV2, ControlRequestV1, trust::valid_digest,
};

pub(crate) fn request(value: &ControlRequestV1) -> Result<(), BridgeError> {
    if value.schema != "crowsi://local-control/request/v1"
        || !valid_id(&value.request_id)
        || !valid_id(&value.resource)
        || !valid_id(&value.purpose)
        || !valid_digest(&value.body_sha256)
    {
        return Err(BridgeError::Contract);
    }
    Ok(())
}

pub(crate) fn authorization(
    value: &ControlAuthorizationV2,
    request: &ControlRequestV1,
    now: i64,
    trust: &BridgeTrust,
) -> Result<(), BridgeError> {
    if value.schema != "crowsi://local-control/authorization/v2"
        || value.issuer != "crowsi-policy-administrator"
        || value.audience != "crowsi-local-control-bridge"
        || value.service_id != "service:crowsi"
        || value.assurance != "phishing-resistant"
        || !value.user_verification
        || value.device_posture != "compliant"
        || value.device_posture_revision == 0
        || value.workload_id != trust.workload_id
    {
        return Err(BridgeError::Authentication);
    }
    if value.request_id != request.request_id
        || value.action != request.action
        || value.resource != request.resource
        || value.purpose != request.purpose
        || value.body_sha256 != request.body_sha256
    {
        return Err(BridgeError::Binding);
    }
    if value.issued_at_epoch_s > now
        || value.expires_at_epoch_s <= now
        || value
            .expires_at_epoch_s
            .checked_sub(value.issued_at_epoch_s)
            .is_none_or(|lifetime| !(1..=60).contains(&lifetime))
    {
        return Err(BridgeError::Time);
    }
    if ![
        &value.service_id,
        &value.pairwise_subject,
        &value.device_id,
        &value.device_proof_key_ref,
        &value.session_ref,
        &value.actor_profile_id,
        &value.reservation_id,
    ]
    .into_iter()
    .all(|item| valid_id(item))
    {
        return Err(BridgeError::Contract);
    }
    Ok(())
}

pub(crate) fn signature(
    key: &VerifyingKey,
    message: &[u8],
    encoded: &str,
) -> Result<(), BridgeError> {
    let bytes = hex::decode(encoded).map_err(|_| BridgeError::Signature)?;
    let signature = Signature::try_from(bytes.as_slice()).map_err(|_| BridgeError::Signature)?;
    key.verify_strict(message, &signature)
        .map_err(|_| BridgeError::Signature)
}

pub(crate) fn sender_key(
    value: &str,
    authority: &VerifyingKey,
) -> Result<VerifyingKey, BridgeError> {
    let bytes = hex::decode(value).map_err(|_| BridgeError::Authentication)?;
    let key: [u8; 32] = bytes.try_into().map_err(|_| BridgeError::Authentication)?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| BridgeError::Authentication)?;
    if key.is_weak() || key.to_bytes() == authority.to_bytes() {
        return Err(BridgeError::Authentication);
    }
    Ok(key)
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 240
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":._/-".contains(&byte))
}
