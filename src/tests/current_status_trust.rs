use crate::{BridgeError, IdentityStatusTrust};
use ed25519_dalek::SigningKey;

use super::support::{
    NOW, STATUS_AUDIENCE, STATUS_ISSUER, STATUS_KEY_ID, current_status, fixture,
    managed_status_binding, resign_status,
};

#[test]
// ID-36
fn pa_key_cannot_be_reused_as_mandatory_identity_status_key() {
    let fixture = fixture();
    let pa = SigningKey::from_bytes(&[7; 32]);
    let reused = IdentityStatusTrust::new(
        pa.verifying_key().to_bytes(),
        STATUS_KEY_ID,
        STATUS_ISSUER,
        STATUS_AUDIENCE,
        "service:crowsi",
    )
    .expect("individually valid verifier");
    assert_eq!(
        crate::BridgeTrust::new(
            pa.verifying_key().to_bytes(),
            fixture.peer.uid,
            fixture.peer.gid,
            "spiffe://crowsi/local/coela-control",
            &fixture.peer.executable_sha256,
            reused,
        )
        .err(),
        Some(BridgeError::Contract)
    );
}

#[test]
fn current_status_time_window_is_checked_at_the_trusted_clock() {
    let mut fixture = fixture();
    let mut expired = current_status(
        "device:managed",
        "device-proof:managed",
        5,
        "status:expired",
    );
    expired.issued_at_epoch_s = u64::try_from(NOW - 30).expect("positive time");
    expired.expires_at_epoch_s = u64::try_from(NOW).expect("positive time");
    resign_status(&mut expired);
    assert_eq!(
        fixture
            .bridge
            .apply_current_device_status(&wire(&expired), &managed_status_binding(),),
        Err(BridgeError::Time)
    );
    let mut future = current_status("device:managed", "device-proof:managed", 5, "status:future");
    future.issued_at_epoch_s = u64::try_from(NOW + 1).expect("positive time");
    future.expires_at_epoch_s = u64::try_from(NOW + 20).expect("positive time");
    resign_status(&mut future);
    assert_eq!(
        fixture
            .bridge
            .apply_current_device_status(&wire(&future), &managed_status_binding(),),
        Err(BridgeError::Time)
    );
}

fn wire(value: &ihat_identity_assertion_contracts::CurrentDeviceStatusV1) -> Vec<u8> {
    serde_json::to_vec(value).expect("status JSON")
}
