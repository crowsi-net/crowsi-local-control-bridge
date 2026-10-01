use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BridgeReadiness {
    pub schema: &'static str,
    pub state: &'static str,
    pub checks: ReadinessChecks,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ReadinessChecks {
    pub os_caller_attestation: bool,
    pub phishing_resistant_user_verification: bool,
    pub device_and_workload_binding: bool,
    pub sender_constraint: bool,
    pub durable_replay_store: bool,
    pub trusted_monotonic_clock: bool,
    pub rate_limit: bool,
    pub revocation: bool,
    pub audit_journal: bool,
}
