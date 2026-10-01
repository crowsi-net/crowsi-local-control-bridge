#![allow(dead_code)]

use crate::{
    BridgeAction, ControlAuthorizationV2, ControlRequestV1, DurableSecurityStore,
    LocalControlBridge, SenderProof, SignedAuthorization, canonical_authorization,
    canonical_request, clock::TestClock, model::PeerAttestation, sha256_digest,
};
use ed25519_dalek::{Signer, SigningKey};
use std::{fs, os::unix::fs::PermissionsExt};
use tempfile::TempDir;

mod status;
pub use status::*;

pub struct Fixture {
    pub bridge: LocalControlBridge<TestClock>,
    pub request: ControlRequestV1,
    pub authorization: SignedAuthorization,
    pub proof: SenderProof,
    pub peer: PeerAttestation,
    pub root: TempDir,
}

pub const NOW: i64 = 1_800_000_000;
pub const STATUS_ISSUER: &str = "ihat://identity-authority";
pub const STATUS_AUDIENCE: &str = "crowsi://local-control/current-status";
pub const STATUS_KEY_ID: &str = "ihat-status-key:1";
pub const SESSION_REF_A: &str =
    "sref_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub const SESSION_REF_B: &str =
    "sref_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

pub fn fixture() -> Fixture {
    fixture_for_peer(PeerAttestation {
        pid: 100,
        uid: 3001,
        gid: 3001,
        process_start_ticks: 77,
        executable_sha256: sha256_digest(b"coela-control"),
    })
}

pub fn fixture_for_peer(peer: PeerAttestation) -> Fixture {
    let root = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
        .expect("private state directory");
    let pa = SigningKey::from_bytes(&[7; 32]);
    let sender = SigningKey::from_bytes(&[8; 32]);
    let now = NOW;
    let request = ControlRequestV1 {
        schema: "crowsi://local-control/request/v1".into(),
        request_id: "request:001".into(),
        action: BridgeAction::ContainAsset,
        resource: "crowsi://assets/server-01".into(),
        purpose: "incident-containment".into(),
        body_sha256: sha256_digest(b"bounded body"),
    };
    let document = ControlAuthorizationV2 {
        schema: "crowsi://local-control/authorization/v2".into(),
        issuer: "crowsi-policy-administrator".into(),
        audience: "crowsi-local-control-bridge".into(),
        service_id: "service:crowsi".into(),
        pairwise_subject: "pairwise:operator".into(),
        device_id: "device:managed".into(),
        device_proof_key_ref: "device-proof:managed".into(),
        session_ref: SESSION_REF_A.into(),
        device_posture: "compliant".into(),
        device_posture_revision: 2,
        subject_revocation_epoch: 1,
        service_revocation_epoch: 2,
        device_revocation_epoch: 4,
        session_revocation_epoch: 3,
        workload_id: "spiffe://crowsi/local/coela-control".into(),
        actor_profile_id: "profile:security-operator".into(),
        assurance: "phishing-resistant".into(),
        user_verification: true,
        sender_public_key_hex: hex::encode(sender.verifying_key().to_bytes()),
        request_id: request.request_id.clone(),
        action: request.action,
        resource: request.resource.clone(),
        purpose: request.purpose.clone(),
        body_sha256: request.body_sha256.clone(),
        reservation_id: "reservation:001".into(),
        issued_at_epoch_s: now - 1,
        expires_at_epoch_s: now + 15,
    };
    let authorization = SignedAuthorization {
        document: document.clone(),
        signature_hex: hex::encode(pa.sign(&canonical_authorization(&document)).to_bytes()),
    };
    let proof = SenderProof {
        signature_hex: hex::encode(sender.sign(&canonical_request(&request)).to_bytes()),
    };
    let trust = bridge_trust(&peer);
    let store =
        DurableSecurityStore::open(root.path().join("bridge.sqlite3"), 3).expect("durable store");
    let mut bridge = LocalControlBridge::new(trust, store, TestClock::new(now));
    let status = current_status(
        "device:managed",
        "device-proof:managed",
        4,
        "status:fixture-anchor",
    );
    bridge
        .apply_current_device_status(
            &serde_json::to_vec(&status).expect("status JSON"),
            &managed_status_binding(),
        )
        .expect("durable initial status anchor");
    Fixture {
        bridge,
        request,
        authorization,
        proof,
        peer,
        root,
    }
}
