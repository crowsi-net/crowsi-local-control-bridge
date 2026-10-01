use super::support::fixture;
use crate::{BridgeAction, BridgeError, SenderProof, canonical_authorization, canonical_request};
use ed25519_dalek::{Signer, SigningKey};

#[test]
fn exact_bound_request_is_released_once() {
    let mut fixture = fixture();
    let ticket = fixture
        .bridge
        .authorize_attested(
            &fixture.request,
            &fixture.authorization,
            &fixture.proof,
            &fixture.peer,
        )
        .expect("authorized");
    assert_eq!(ticket.action, BridgeAction::ContainAsset);
    assert_eq!(ticket.resource, fixture.request.resource);
    assert_eq!(ticket.purpose, fixture.request.purpose);
    assert_eq!(ticket.body_sha256, fixture.request.body_sha256);
    assert_eq!(ticket.service_id, "service:crowsi");
    assert_eq!(ticket.pairwise_subject, "pairwise:operator");
    assert_eq!(ticket.device_id, "device:managed");
    assert_eq!(ticket.workload_id, "spiffe://crowsi/local/coela-control");
    assert_eq!(ticket.actor_profile_id, "profile:security-operator");
    assert_eq!(ticket.device_revocation_epoch, 4);
    assert!(ticket.command_digest.starts_with("sha256:"));
    let serialized = serde_json::to_string(&ticket).expect("ticket");
    for private_binding in [
        "service_id",
        "pairwise_subject",
        "device_id",
        "device_proof_key_ref",
        "workload_id",
        "actor_profile_id",
        "sender_public_key_hex",
        "device_revocation_epoch",
    ] {
        assert!(!serialized.contains(private_binding));
    }
    let debug = format!("{ticket:?}");
    for private_value in [
        "pairwise:operator",
        "device:managed",
        "server-01",
        "reservation:001",
    ] {
        assert!(!debug.contains(private_value));
    }
    assert_eq!(
        fixture
            .bridge
            .authorize_attested(
                &fixture.request,
                &fixture.authorization,
                &fixture.proof,
                &fixture.peer,
            )
            .expect_err("replay rejected"),
        BridgeError::Replay
    );
}

#[test]
fn body_action_resource_and_sender_are_fully_bound() {
    let mut fixture = fixture();
    fixture.request.resource = "crowsi://assets/server-02".into();
    assert_eq!(
        fixture
            .bridge
            .authorize_attested(
                &fixture.request,
                &fixture.authorization,
                &fixture.proof,
                &fixture.peer,
            )
            .expect_err("binding mismatch"),
        BridgeError::Binding
    );
}

#[test]
fn user_device_and_short_lifetime_are_mandatory() {
    let mut fixture = fixture();
    fixture.authorization.document.user_verification = false;
    assert_eq!(
        fixture
            .bridge
            .authorize_attested(
                &fixture.request,
                &fixture.authorization,
                &fixture.proof,
                &fixture.peer,
            )
            .expect_err("UV required"),
        BridgeError::Authentication
    );
}

#[test]
fn pa_key_cannot_also_satisfy_sender_possession() {
    let mut fixture = fixture();
    let shared = SigningKey::from_bytes(&[7; 32]);
    fixture.authorization.document.sender_public_key_hex =
        hex::encode(shared.verifying_key().to_bytes());
    fixture.authorization.signature_hex = hex::encode(
        shared
            .sign(&canonical_authorization(&fixture.authorization.document))
            .to_bytes(),
    );
    fixture.proof = SenderProof {
        signature_hex: hex::encode(shared.sign(&canonical_request(&fixture.request)).to_bytes()),
    };

    assert_eq!(
        fixture
            .bridge
            .authorize_attested(
                &fixture.request,
                &fixture.authorization,
                &fixture.proof,
                &fixture.peer,
            )
            .expect_err("role-confused key"),
        BridgeError::Authentication
    );
}
