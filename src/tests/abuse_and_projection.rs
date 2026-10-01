use super::support::fixture;
use crate::{BridgeError, canonical_authorization, canonical_request};
use ed25519_dalek::{Signer, SigningKey};

#[test]
fn rate_limit_is_durable_and_audited_without_payloads() {
    let mut fixture = fixture();
    for index in 0..3 {
        fixture.request.request_id = format!("request:{index}");
        fixture.authorization.document.request_id = fixture.request.request_id.clone();
        fixture.authorization.document.reservation_id = format!("reservation:{index}");
        let pa = SigningKey::from_bytes(&[7; 32]);
        let sender = SigningKey::from_bytes(&[8; 32]);
        fixture.authorization.signature_hex = hex::encode(
            pa.sign(&canonical_authorization(&fixture.authorization.document))
                .to_bytes(),
        );
        fixture.proof.signature_hex =
            hex::encode(sender.sign(&canonical_request(&fixture.request)).to_bytes());
        fixture
            .bridge
            .authorize_attested(
                &fixture.request,
                &fixture.authorization,
                &fixture.proof,
                &fixture.peer,
            )
            .expect("within limit");
    }
    fixture.request.request_id = "request:limited".into();
    fixture.authorization.document.request_id = fixture.request.request_id.clone();
    let pa = SigningKey::from_bytes(&[7; 32]);
    let sender = SigningKey::from_bytes(&[8; 32]);
    fixture.authorization.signature_hex = hex::encode(
        pa.sign(&canonical_authorization(&fixture.authorization.document))
            .to_bytes(),
    );
    fixture.proof.signature_hex =
        hex::encode(sender.sign(&canonical_request(&fixture.request)).to_bytes());
    assert_eq!(
        fixture
            .bridge
            .authorize_attested(
                &fixture.request,
                &fixture.authorization,
                &fixture.proof,
                &fixture.peer,
            )
            .expect_err("limited"),
        BridgeError::RateLimited
    );
    let audit = fixture.bridge.audit_records().expect("audit");
    assert_eq!(audit.len(), 3);
    assert!(
        !serde_json::to_string(&audit)
            .expect("json")
            .contains("bounded body")
    );
}

#[test]
fn readiness_contains_no_keys_capabilities_or_subjects() {
    let fixture = fixture();
    let readiness = fixture.bridge.readiness();
    let serialized = serde_json::to_string(&readiness).expect("json");
    assert!(serialized.contains("\"state\":\"unavailable\""));
    assert!(!readiness.checks.os_caller_attestation);
    assert!(!readiness.checks.trusted_monotonic_clock);
    assert!(!readiness.checks.durable_replay_store);
    for forbidden in [
        "public_key",
        "subject",
        "reservation",
        "capability",
        "secret",
    ] {
        assert!(!serialized.contains(forbidden));
    }
}
