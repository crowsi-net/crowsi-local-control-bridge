use crate::BridgeError;

use super::support::{current_status, fixture, managed_status_binding};

#[test]
// ID-47 / OP-14
fn preflight_verification_does_not_consume_the_status_nonce() {
    let mut fixture = fixture();
    let status = current_status(
        "device:managed",
        "device-proof:managed",
        5,
        "status:preflight",
    );
    let bytes = serde_json::to_vec(&status).expect("status JSON");
    fixture
        .bridge
        .verify_current_device_status(&bytes, &managed_status_binding())
        .expect("first preflight");
    fixture
        .bridge
        .verify_current_device_status(&bytes, &managed_status_binding())
        .expect("second preflight");
    fixture
        .bridge
        .apply_current_device_status(&bytes, &managed_status_binding())
        .expect("single durable application");
    assert_eq!(
        fixture
            .bridge
            .apply_current_device_status(&bytes, &managed_status_binding()),
        Err(BridgeError::Replay)
    );
}
