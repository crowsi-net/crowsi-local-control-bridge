use std::process::Command;

#[test]
fn sample_readiness_is_closed_metadata_only_and_fail_closed() {
    let output = Command::new(env!("CARGO_BIN_EXE_crowsi-local-control-bridge"))
        .arg("sample-readiness")
        .output()
        .expect("run sample readiness");
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(value["state"], "unavailable");
    assert_eq!(value["external_actions"], false);
    assert_eq!(
        value
            .as_object()
            .expect("object")
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        [
            "checks",
            "external_actions",
            "reason_codes",
            "schema",
            "state"
        ]
    );
    let serialized = value.to_string();
    for forbidden in ["public_key", "subject", "signature", "capability", "secret"] {
        assert!(!serialized.contains(forbidden));
    }
}
