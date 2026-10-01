use crate::{BridgeReadiness, LocalControlBridge, TrustedClock, model::ReadinessChecks};

impl<C: TrustedClock> LocalControlBridge<C> {
    #[must_use]
    pub fn readiness(&self) -> BridgeReadiness {
        BridgeReadiness {
            schema: "crowsi://local-control/readiness/v1",
            state: "unavailable",
            checks: ReadinessChecks {
                os_caller_attestation: false,
                phishing_resistant_user_verification: false,
                device_and_workload_binding: false,
                sender_constraint: false,
                durable_replay_store: false,
                trusted_monotonic_clock: false,
                rate_limit: false,
                revocation: false,
                audit_journal: false,
            },
        }
    }
}
