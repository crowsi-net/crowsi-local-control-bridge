use crate::{
    BridgeError, CurrentStatusBinding, DurableSecurityStore, LocalControlBridge, clock::TestClock,
};

use super::support::{
    NOW, bridge_trust, current_status, fixture, managed_status_binding, resign_status,
};

#[test]
// ID-35
fn every_identity_binding_field_must_match_exactly() {
    let base = current_status(
        "device:managed",
        "device-proof:managed",
        5,
        "status:binding",
    );
    let mut variants = [base.clone(), base.clone(), base.clone(), base.clone(), base];
    variants[0].pairwise_subject = "pairwise:other".into();
    variants[1].service_id = "service:other".into();
    variants[2].device_id = "device:other".into();
    variants[3].device_proof_key_ref = "device-proof:other".into();
    variants[4].session_ref = super::support::SESSION_REF_B.into();
    for mut changed in variants {
        let mut fixture = fixture();
        resign_status(&mut changed);
        assert_eq!(
            fixture
                .bridge
                .apply_current_device_status(&wire(&changed), &managed_status_binding(),),
            Err(BridgeError::Binding)
        );
    }
}

#[test]
fn caller_cannot_route_a_signed_status_for_another_service() {
    let mut fixture = fixture();
    let mut status = current_status(
        "device:managed",
        "device-proof:managed",
        99,
        "status:other-service",
    );
    status.service_id = "service:other".into();
    resign_status(&mut status);
    let caller_binding = CurrentStatusBinding::new(
        "pairwise:operator",
        "service:other",
        "device:managed",
        "device-proof:managed",
        super::support::SESSION_REF_A,
    )
    .expect("valid caller binding");
    assert_eq!(
        fixture
            .bridge
            .apply_current_device_status(&wire(&status), &caller_binding),
        Err(BridgeError::Authentication)
    );
}

#[test]
// ID-37
fn status_nonce_replay_is_rejected_after_reopen() {
    let mut fixture = fixture();
    let status = current_status(
        "device:managed",
        "device-proof:managed",
        5,
        "status:durable",
    );
    let bytes = wire(&status);
    fixture
        .bridge
        .apply_current_device_status(&bytes, &managed_status_binding())
        .expect("first observation");
    let path = fixture.root.path().join("bridge.sqlite3");
    drop(fixture.bridge);
    let store = DurableSecurityStore::open(path, 3).expect("reopen state");
    let trust = bridge_trust(&fixture.peer);
    let mut reopened = LocalControlBridge::new(trust, store, TestClock::new(NOW));
    assert_eq!(
        reopened.apply_current_device_status(&bytes, &managed_status_binding()),
        Err(BridgeError::Replay)
    );
}

#[test]
fn newly_signed_status_cannot_roll_back_a_durable_epoch() {
    let mut fixture = fixture();
    let high = current_status("device:managed", "device-proof:managed", 9, "status:high");
    fixture
        .bridge
        .apply_current_device_status(&wire(&high), &managed_status_binding())
        .expect("high watermark");
    let low = current_status(
        "device:managed",
        "device-proof:managed",
        8,
        "status:new-but-stale",
    );
    assert_eq!(
        fixture
            .bridge
            .apply_current_device_status(&wire(&low), &managed_status_binding()),
        Err(BridgeError::Revoked)
    );
}

#[test]
fn current_status_wire_is_closed_and_bounded() {
    let mut fixture = fixture();
    let status = current_status("device:managed", "device-proof:managed", 5, "status:closed");
    let mut value = serde_json::to_value(status).expect("JSON");
    value
        .as_object_mut()
        .expect("object")
        .insert("caller_claim".into(), serde_json::Value::Bool(true));
    assert_eq!(
        fixture.bridge.apply_current_device_status(
            &serde_json::to_vec(&value).expect("wire"),
            &managed_status_binding(),
        ),
        Err(BridgeError::Contract)
    );
    assert_eq!(
        fixture
            .bridge
            .apply_current_device_status(&vec![b' '; 16_385], &managed_status_binding(),),
        Err(BridgeError::Contract)
    );
}

fn wire(value: &ihat_identity_assertion_contracts::CurrentDeviceStatusV1) -> Vec<u8> {
    serde_json::to_vec(value).expect("status JSON")
}
