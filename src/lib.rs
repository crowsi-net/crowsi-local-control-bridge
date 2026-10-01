//! Authenticated Unix IPC boundary for local control.
//!
//! Kernel peer evidence cannot be constructed or passed through the public API.
//!
//! ```compile_fail
//! use crowsi_local_control_bridge::PeerAttestation;
//! ```

mod bridge;
mod bridge_status;
mod canonical;
mod clock;
mod error;
mod identity_status;
mod model;
mod model_dispatch;
mod model_readiness;
mod peer;
mod readiness;
mod secure_state;
mod server;
mod socket;
mod store;
mod store_schema;
mod timed_read;
mod trust;
mod validation;

#[cfg(test)]
mod tests;

pub use bridge::LocalControlBridge;
pub use canonical::{canonical_authorization, canonical_request, sha256_digest};
pub use clock::{SystemTrustedClock, TrustedClock};
pub use error::BridgeError;
pub use identity_status::{CurrentStatusBinding, IdentityStatusTrust};
pub use model::{
    AuditRecord, BridgeAction, BridgeReadiness, ControlAuthorizationV2, ControlRequestV1,
    DispatchTicket, IpcAuthorizationEnvelopeV2, SenderProof, SignedAuthorization,
};
pub use server::{AuthorizedOperationHandler, LocalControlServer};
pub use socket::PrivateUnixListener;
pub use store::DurableSecurityStore;
pub use trust::BridgeTrust;
