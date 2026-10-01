use thiserror::Error;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum BridgeError {
    #[error("invalid closed contract")]
    Contract,
    #[error("authentication evidence rejected")]
    Authentication,
    #[error("request binding rejected")]
    Binding,
    #[error("OS peer attestation rejected")]
    PeerAttestation,
    #[error("authorization signature rejected")]
    Signature,
    #[error("authorization expired or clock invalid")]
    Time,
    #[error("authorization was revoked")]
    Revoked,
    #[error("authorization replay rejected")]
    Replay,
    #[error("request rate limited")]
    RateLimited,
    #[error("durable security state unavailable")]
    Storage,
    #[error("local IPC transport unavailable")]
    Transport,
}

impl From<rusqlite::Error> for BridgeError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}
