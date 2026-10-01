use super::support::fixture;
use crate::{BridgeAction, BridgeError, BridgeTrust};
use ed25519_dalek::SigningKey;

#[test]
fn extreme_untrusted_times_fail_closed_without_overflow() {
    let mut fixture = fixture();
    fixture.authorization.document.issued_at_epoch_s = i64::MIN;
    fixture.authorization.document.expires_at_epoch_s = i64::MAX;
    assert_eq!(
        fixture
            .bridge
            .authorize_attested(
                &fixture.request,
                &fixture.authorization,
                &fixture.proof,
                &fixture.peer,
            )
            .expect_err("unbounded lifetime"),
        BridgeError::Time
    );
}

#[test]
fn json_contract_rejects_unknown_fields() {
    let value = serde_json::json!({
        "schema": "crowsi://local-control/request/v1",
        "request_id": "request:001",
        "action": "contain-asset",
        "resource": "crowsi://assets/server-01",
        "purpose": "incident-containment",
        "body_sha256": format!("sha256:{}", "a".repeat(64)),
        "trusted": true
    });
    assert!(serde_json::from_value::<crate::ControlRequestV1>(value).is_err());
}

#[test]
fn ipc_frame_is_bounded_and_closed() {
    let mut fixture = fixture();
    let frame = serde_json::json!({
        "schema": "crowsi://local-control/ipc-envelope/v2",
        "request": fixture.request,
        "authorization": fixture.authorization,
        "sender_proof": fixture.proof
    });
    let ticket = fixture
        .bridge
        .authorize_attested_frame(&serde_json::to_vec(&frame).expect("frame"), &fixture.peer)
        .expect("closed IPC");
    assert_eq!(ticket.action, BridgeAction::ContainAsset);
    assert_eq!(
        fixture
            .bridge
            .authorize_attested_frame(&vec![b'a'; 65_537], &fixture.peer)
            .expect_err("oversized"),
        BridgeError::Contract
    );
}

#[test]
fn trust_accepts_only_the_shared_closed_spiffe_profile() {
    let key = SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes();
    let digest = format!("sha256:{}", "a".repeat(64));
    for workload in [
        "spiffe://crowsi/local/coela-control",
        "spiffe://crowsi.example/Team_A/worker.01",
        "spiffe://crowsi/-/_",
    ] {
        assert!(
            BridgeTrust::new(
                key,
                1000,
                1000,
                workload,
                &digest,
                super::support::identity_status_trust(),
            )
            .is_ok()
        );
    }
    for workload in [
        "workload-coela",
        "SPIFFE://crowsi/local/coela-control",
        "spiffe://crowsi//coela-control",
        "spiffe://crowsi/local/../admin",
        "spiffe://crowsi/local/control?role=admin",
        "spiffe://CROWSI/local/coela-control",
        "spiffe://-crowsi/local/control",
        "spiffe://crowsi/local/~control",
    ] {
        assert!(matches!(
            BridgeTrust::new(
                key,
                1000,
                1000,
                workload,
                &digest,
                super::support::identity_status_trust(),
            ),
            Err(BridgeError::Contract)
        ));
    }
}
