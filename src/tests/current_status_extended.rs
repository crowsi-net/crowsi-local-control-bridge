#[test]
// ID-34
fn signed_current_status_raises_only_the_exact_device_scope() {
    let mut fixture = fixture();
    let status = current_status("device:managed", "device-proof:managed", 99, "status:a");
    fixture
        .bridge
        .apply_current_device_status(&wire(&status), &managed_status_binding())
        .expect("verified status");
    assert_eq!(
        fixture.bridge.authorize_attested(
            &fixture.request,
            &fixture.authorization,
            &fixture.proof,
            &fixture.peer,
        ),
        Err(BridgeError::Revoked)
    );
    fixture.authorization.document.device_id = "device:second".into();
    fixture.authorization.document.device_proof_key_ref = "device-proof:second".into();
    fixture.authorization.document.device_revocation_epoch = 1;
    resign_authorization(&mut fixture.authorization);
    let second = current_status(
        "device:second",
        "device-proof:second",
        1,
        "status:second-device",
    );
    let second_binding = crate::CurrentStatusBinding::new(
        "pairwise:operator",
        "service:crowsi",
        "device:second",
        "device-proof:second",
        SESSION_REF_A,
    )
    .expect("second binding");
    fixture
        .bridge
        .apply_current_device_status(&wire(&second), &second_binding)
        .expect("second device anchor");
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

#[test]
fn signature_issuer_and_audience_are_verified() {
    let mut fixture = fixture();
    let mut bad_signature = current_status(
        "device:managed",
        "device-proof:managed",
        5,
        "status:signature",
    );
    bad_signature.signature = "00".repeat(64);
    assert_eq!(
        fixture
            .bridge
            .apply_current_device_status(&wire(&bad_signature), &managed_status_binding(),),
        Err(BridgeError::Signature)
    );
    let mut wrong_key_id =
        current_status("device:managed", "device-proof:managed", 5, "status:key-id");
    wrong_key_id.key_id = "ihat-status-key:other".into();
    resign_status(&mut wrong_key_id);
    assert_eq!(
        fixture
            .bridge
            .apply_current_device_status(&wire(&wrong_key_id), &managed_status_binding(),),
        Err(BridgeError::Signature)
    );
    let mut wrong_issuer =
        current_status("device:managed", "device-proof:managed", 5, "status:issuer");
    wrong_issuer.issuer = "ihat://other-authority".into();
    resign_status(&mut wrong_issuer);
    assert_eq!(
        fixture
            .bridge
            .apply_current_device_status(&wire(&wrong_issuer), &managed_status_binding(),),
        Err(BridgeError::Authentication)
    );
    let mut wrong_audience = current_status(
        "device:managed",
        "device-proof:managed",
        5,
        "status:audience",
    );
    wrong_audience.audience = "crowsi://other-consumer".into();
    resign_status(&mut wrong_audience);
    assert_eq!(
        fixture
            .bridge
            .apply_current_device_status(&wire(&wrong_audience), &managed_status_binding(),),
        Err(BridgeError::Authentication)
    );
}

#[test]
fn rejected_status_changes_neither_watermark_nor_nonce_state() {
    let mut fixture = fixture();
    let mut status = current_status(
        "device:managed",
        "device-proof:managed",
        99,
        "status:rejected",
    );
    status.signature = "00".repeat(64);
    assert_eq!(
        fixture
            .bridge
            .apply_current_device_status(&wire(&status), &managed_status_binding(),),
        Err(BridgeError::Signature)
    );
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
    resign_status(&mut status);
    fixture
        .bridge
        .apply_current_device_status(&wire(&status), &managed_status_binding())
        .expect("rejected status did not consume its nonce");
}
