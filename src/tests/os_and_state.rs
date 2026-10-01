use std::os::unix::net::UnixStream;

use super::support::{
    SESSION_REF_A, current_status, fixture, managed_status_binding, resign_authorization,
};
use crate::{BridgeError, peer::attest_unix_peer};

#[test]
fn kernel_peer_identity_is_observed_from_unix_socket() {
    let (client, _server) = UnixStream::pair().expect("socket pair");
    match attest_unix_peer(&client) {
        Ok(peer) => {
            assert_eq!(peer.uid, nix::unistd::Uid::current().as_raw());
            assert_eq!(peer.gid, nix::unistd::Gid::current().as_raw());
            assert!(peer.pid > 0);
            assert!(peer.executable_sha256.starts_with("sha256:"));
        }
        Err(error) => {
            // Sandboxed CI may deny SO_PEERCRED; denial must never become trust.
            assert_eq!(error, BridgeError::PeerAttestation);
        }
    }
}

#[test]
fn mismatched_os_identity_is_rejected() {
    let mut fixture = fixture();
    fixture.peer.uid += 1;
    assert_eq!(
        fixture
            .bridge
            .authorize_attested(
                &fixture.request,
                &fixture.authorization,
                &fixture.proof,
                &fixture.peer,
            )
            .expect_err("peer mismatch"),
        BridgeError::PeerAttestation
    );
}

#[test]
fn revoked_epoch_and_clock_rollback_fail_closed() {
    let mut fixture = fixture();
    fixture
        .bridge
        .apply_current_device_status(
            &serde_json::to_vec(&current_status(
                "device:managed",
                "device-proof:managed",
                5,
                "status:revoked-epoch",
            ))
            .expect("status JSON"),
            &managed_status_binding(),
        )
        .expect("raise epoch");
    assert_eq!(
        fixture
            .bridge
            .authorize_attested(
                &fixture.request,
                &fixture.authorization,
                &fixture.proof,
                &fixture.peer,
            )
            .expect_err("revoked"),
        BridgeError::Revoked
    );
    fixture.bridge.clock_mut().set(1_799_999_999);
    assert_eq!(fixture.bridge.readiness().state, "unavailable");
}

#[test]
fn revoking_device_a_does_not_raise_device_b_watermark() {
    let mut fixture = fixture();
    fixture
        .bridge
        .apply_current_device_status(
            &serde_json::to_vec(&current_status(
                "device:managed",
                "device-proof:managed",
                99,
                "status:device-a",
            ))
            .expect("status JSON"),
            &managed_status_binding(),
        )
        .expect("revoke A");
    fixture.authorization.document.device_id = "device:second".into();
    fixture.authorization.document.device_proof_key_ref = "device-proof:second".into();
    fixture.authorization.document.device_revocation_epoch = 1;
    resign_authorization(&mut fixture.authorization);
    let status = current_status("device:second", "device-proof:second", 1, "status:device-b");
    let binding = crate::CurrentStatusBinding::new(
        "pairwise:operator",
        "service:crowsi",
        "device:second",
        "device-proof:second",
        SESSION_REF_A,
    )
    .expect("device B binding");
    fixture
        .bridge
        .apply_current_device_status(&serde_json::to_vec(&status).expect("status JSON"), &binding)
        .expect("device B status anchor");
    assert!(
        fixture
            .bridge
            .authorize_attested(
                &fixture.request,
                &fixture.authorization,
                &fixture.proof,
                &fixture.peer,
            )
            .is_ok()
    );
}
