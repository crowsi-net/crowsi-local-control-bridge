use crate::{
    BridgeTrust, CurrentStatusBinding, IdentityStatusTrust, SignedAuthorization,
    canonical_authorization, model::PeerAttestation,
};
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::{
    CURRENT_DEVICE_STATUS_SCHEMA, CurrentDeviceStatusV1, DevicePostureV1, RevocationEpochsV1,
    canonical_current_status_payload,
};

use super::{NOW, SESSION_REF_A, STATUS_AUDIENCE, STATUS_ISSUER, STATUS_KEY_ID};

pub fn bridge_trust(peer: &PeerAttestation) -> BridgeTrust {
    let pa = SigningKey::from_bytes(&[7; 32]);
    BridgeTrust::new(
        pa.verifying_key().to_bytes(),
        peer.uid,
        peer.gid,
        "spiffe://crowsi/local/coela-control",
        &peer.executable_sha256,
        identity_status_trust(),
    )
    .expect("valid trust")
}

pub fn identity_status_trust() -> IdentityStatusTrust {
    let signer = SigningKey::from_bytes(&[9; 32]);
    IdentityStatusTrust::new(
        signer.verifying_key().to_bytes(),
        STATUS_KEY_ID,
        STATUS_ISSUER,
        STATUS_AUDIENCE,
        "service:crowsi",
    )
    .expect("valid identity status trust")
}

pub fn managed_status_binding() -> CurrentStatusBinding {
    CurrentStatusBinding::new(
        "pairwise:operator",
        "service:crowsi",
        "device:managed",
        "device-proof:managed",
        SESSION_REF_A,
    )
    .expect("valid status binding")
}

pub fn current_status(
    device_id: &str,
    proof_key: &str,
    device_epoch: u64,
    nonce: &str,
) -> CurrentDeviceStatusV1 {
    current_status_for_session(device_id, proof_key, SESSION_REF_A, device_epoch, 3, nonce)
}

pub fn current_status_for_session(
    device_id: &str,
    proof_key: &str,
    session_ref: &str,
    device_epoch: u64,
    session_epoch: u64,
    nonce: &str,
) -> CurrentDeviceStatusV1 {
    let mut status = CurrentDeviceStatusV1 {
        schema: CURRENT_DEVICE_STATUS_SCHEMA.into(),
        issuer: STATUS_ISSUER.into(),
        audience: STATUS_AUDIENCE.into(),
        service_id: "service:crowsi".into(),
        pairwise_subject: "pairwise:operator".into(),
        device_id: device_id.into(),
        device_proof_key_ref: proof_key.into(),
        session_ref: session_ref.into(),
        device_posture: DevicePostureV1 {
            state: "compliant".into(),
            revision: 2,
        },
        revocation_epochs: RevocationEpochsV1 {
            subject: 1,
            service: 2,
            device: device_epoch,
            session: session_epoch,
        },
        issued_at_epoch_s: u64::try_from(NOW - 1).expect("positive time"),
        expires_at_epoch_s: u64::try_from(NOW + 20).expect("positive time"),
        nonce: nonce.into(),
        key_id: STATUS_KEY_ID.into(),
        signature: String::new(),
    };
    resign_status(&mut status);
    status
}

pub fn resign_status(status: &mut CurrentDeviceStatusV1) {
    let signer = SigningKey::from_bytes(&[9; 32]);
    status.signature = hex::encode(
        signer
            .sign(&canonical_current_status_payload(status))
            .to_bytes(),
    );
}

pub fn resign_authorization(value: &mut SignedAuthorization) {
    let pa = SigningKey::from_bytes(&[7; 32]);
    value.signature_hex = hex::encode(
        pa.sign(&canonical_authorization(&value.document))
            .to_bytes(),
    );
}
