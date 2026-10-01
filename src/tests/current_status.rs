use crate::{BridgeError, DurableSecurityStore, LocalControlBridge, clock::TestClock};

use super::support::{
    NOW, SESSION_REF_A, SESSION_REF_B, bridge_trust, current_status, current_status_for_session,
    fixture, managed_status_binding, resign_authorization, resign_status,
};

#[test]
fn authorization_requires_a_durable_exact_status_anchor() {
    let fixture = fixture();
    let store = DurableSecurityStore::open(fixture.root.path().join("unanchored.sqlite3"), 3)
        .expect("empty durable store");
    let mut bridge =
        LocalControlBridge::new(bridge_trust(&fixture.peer), store, TestClock::new(NOW));
    assert_eq!(
        bridge.authorize_attested(
            &fixture.request,
            &fixture.authorization,
            &fixture.proof,
            &fixture.peer,
        ),
        Err(BridgeError::Authentication)
    );
}

#[test]
fn authorization_cannot_outlive_its_last_applied_status() {
    let mut fixture = fixture();
    fixture.authorization.document.expires_at_epoch_s = NOW + 21;
    resign_authorization(&mut fixture.authorization);
    assert_eq!(
        fixture.bridge.authorize_attested(
            &fixture.request,
            &fixture.authorization,
            &fixture.proof,
            &fixture.peer,
        ),
        Err(BridgeError::Revoked)
    );
}

#[test]
// ID-39: one same-device session revocation cannot invalidate its sibling session.
fn fresh_status_revokes_only_its_exact_session_reference() {
    let mut fixture = fixture();
    let revoked_a = current_status_for_session(
        "device:managed",
        "device-proof:managed",
        SESSION_REF_A,
        4,
        4,
        "status:session-a-revoked",
    );
    fixture
        .bridge
        .apply_current_device_status(&wire(&revoked_a), &managed_status_binding())
        .expect("fresh A status");
    assert_eq!(
        fixture.bridge.authorize_attested(
            &fixture.request,
            &fixture.authorization,
            &fixture.proof,
            &fixture.peer,
        ),
        Err(BridgeError::Revoked)
    );

    let status_b = current_status_for_session(
        "device:managed",
        "device-proof:managed",
        SESSION_REF_B,
        4,
        3,
        "status:session-b-current",
    );
    let binding_b = crate::CurrentStatusBinding::new(
        "pairwise:operator",
        "service:crowsi",
        "device:managed",
        "device-proof:managed",
        SESSION_REF_B,
    )
    .expect("session B binding");
    fixture
        .bridge
        .apply_current_device_status(&wire(&status_b), &binding_b)
        .expect("fresh B status");
    fixture.authorization.document.session_ref = SESSION_REF_B.into();
    resign_authorization(&mut fixture.authorization);
    fixture
        .bridge
        .authorize_attested(
            &fixture.request,
            &fixture.authorization,
            &fixture.proof,
            &fixture.peer,
        )
        .expect("session B remains authorized");
}

#[test]
// ID-48: equal device IDs in distinct pairwise namespaces never share watermarks.
fn device_and_posture_watermarks_include_pairwise_and_service_scope() {
    let mut fixture = fixture();
    let high = current_status(
        "device:managed",
        "device-proof:managed",
        99,
        "status:pairwise-a-high",
    );
    fixture
        .bridge
        .apply_current_device_status(&wire(&high), &managed_status_binding())
        .expect("pairwise A status");

    let mut other = current_status(
        "device:managed",
        "device-proof:managed",
        1,
        "status:pairwise-b-low",
    );
    other.pairwise_subject = "pairwise:other-operator".into();
    resign_status(&mut other);
    let other_binding = crate::CurrentStatusBinding::new(
        "pairwise:other-operator",
        "service:crowsi",
        "device:managed",
        "device-proof:managed",
        SESSION_REF_A,
    )
    .expect("pairwise B binding");
    fixture
        .bridge
        .apply_current_device_status(&wire(&other), &other_binding)
        .expect("pairwise B remains independent");
    fixture.authorization.document.pairwise_subject = "pairwise:other-operator".into();
    fixture.authorization.document.device_revocation_epoch = 1;
    resign_authorization(&mut fixture.authorization);
    fixture
        .bridge
        .authorize_attested(
            &fixture.request,
            &fixture.authorization,
            &fixture.proof,
            &fixture.peer,
        )
        .expect("same device ID in pairwise B remains current");
}

include!("current_status_extended.rs");

fn wire(value: &ihat_identity_assertion_contracts::CurrentDeviceStatusV1) -> Vec<u8> {
    serde_json::to_vec(value).expect("status JSON")
}
