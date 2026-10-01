use std::{fs, os::unix::fs::PermissionsExt};

use crate::{BridgeAction, BridgeError, tests::support::current_status};

use super::{Consume, DurableSecurityStore};

#[test]
fn trusted_clock_watermark_survives_restart() {
    let root = tempfile::tempdir().expect("temporary root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
    let path = root.path().join("bridge.sqlite3");
    let mut first = DurableSecurityStore::open(&path, 3).expect("first open");
    first
        .apply_verified_current_status(&current_status(
            "device:managed",
            "device-proof:managed",
            1,
            "status:clock-anchor",
        ))
        .expect("status anchor");
    first
        .consume(input("request:one", "reservation:one", 101))
        .expect("first observation");
    drop(first);

    let mut reopened = DurableSecurityStore::open(path, 3).expect("reopen");
    assert_eq!(
        reopened
            .consume(input("request:two", "reservation:two", 100))
            .expect_err("rollback"),
        BridgeError::Time
    );
}

#[test]
fn device_watermark_survives_restart_without_reaching_another_device() {
    let root = tempfile::tempdir().expect("temporary root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
    let path = root.path().join("bridge.sqlite3");
    let mut first = DurableSecurityStore::open(&path, 3).expect("first open");
    first
        .apply_verified_current_status(&current_status(
            "device:a",
            "device-proof:a",
            9,
            "status:store-reopen",
        ))
        .expect("snapshot");
    drop(first);
    let mut reopened = DurableSecurityStore::open(path, 3).expect("reopen");
    let mut stale = input("request:a", "reservation:a", 101);
    stale.device_id = "device:a";
    stale.device_proof_key_ref = "device-proof:a";
    stale.device_epoch = 8;
    assert_eq!(reopened.consume(stale), Err(BridgeError::Revoked));
    reopened
        .apply_verified_current_status(&current_status(
            "device:b",
            "device-proof:b",
            1,
            "status:independent-device",
        ))
        .expect("independent anchor");
    let mut independent = input("request:b", "reservation:b", 101);
    independent.device_id = "device:b";
    independent.device_proof_key_ref = "device-proof:b";
    independent.service_epoch = 2;
    assert!(reopened.consume(independent).is_ok());
}

fn input<'a>(request_id: &'a str, reservation_id: &'a str, now: i64) -> Consume<'a> {
    Consume {
        request_id,
        reservation_id,
        pairwise_subject: "pairwise:operator",
        service_id: "service:crowsi",
        device_id: "device:managed",
        device_proof_key_ref: "device-proof:managed",
        session_ref: crate::tests::support::SESSION_REF_A,
        posture_revision: 2,
        subject_epoch: 1,
        service_epoch: 2,
        device_epoch: 1,
        session_epoch: 3,
        authorization_expires_at: crate::tests::support::NOW + 15,
        action: BridgeAction::ContainAsset,
        resource: "crowsi://assets/server-01",
        now,
    }
}
