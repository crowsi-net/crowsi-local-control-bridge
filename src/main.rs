use serde_json::json;

fn main() {
    let command = std::env::args().nth(1);
    if command.as_deref() != Some("sample-readiness") {
        eprintln!("usage: crowsi-local-control-bridge sample-readiness");
        std::process::exit(64);
    }
    let value = json!({
        "schema": "crowsi://local-control/deployment-readiness/v1",
        "state": "unavailable",
        "external_actions": false,
        "reason_codes": [
            "dedicated-os-identity-not-provisioned",
            "root-owned-unix-socket-not-provisioned",
            "hardware-trust-and-trusted-clock-not-provisioned"
        ],
        "checks": {
            "dedicated_os_identity": false,
            "root_owned_unix_socket": false,
            "hardware_trust": false,
            "trusted_clock": false,
            "durable_state": false
        }
    });
    match serde_json::to_string(&value) {
        Ok(encoded) => println!("{encoded}"),
        Err(_) => std::process::exit(70),
    }
}
