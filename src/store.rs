use std::path::Path;

use rusqlite::{Connection, params};

use ihat_identity_assertion_contracts::CurrentDeviceStatusV1;

use crate::{AuditRecord, BridgeAction, BridgeError, secure_state, sha256_digest, store_schema};

mod audit;
mod revocation;
mod status_anchor;
#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct DurableSecurityStore {
    connection: Connection,
    rate_limit: u32,
}

#[derive(Clone, Copy)]
pub(crate) struct Consume<'a> {
    pub request_id: &'a str,
    pub reservation_id: &'a str,
    pub pairwise_subject: &'a str,
    pub service_id: &'a str,
    pub device_id: &'a str,
    pub device_proof_key_ref: &'a str,
    pub session_ref: &'a str,
    pub posture_revision: u64,
    pub subject_epoch: u64,
    pub service_epoch: u64,
    pub device_epoch: u64,
    pub session_epoch: u64,
    pub authorization_expires_at: i64,
    pub action: BridgeAction,
    pub resource: &'a str,
    pub now: i64,
}

impl DurableSecurityStore {
    /// Opens private durable replay, revocation, rate, and audit state.
    ///
    /// # Errors
    ///
    /// Rejects non-private paths and unavailable or invalid `SQLite` state.
    pub fn open(path: impl AsRef<Path>, rate_limit: u32) -> Result<Self, BridgeError> {
        if rate_limit == 0 {
            return Err(BridgeError::Contract);
        }
        let mut connection = secure_state::open(path.as_ref())?;
        store_schema::initialize(&mut connection)?;
        Ok(Self {
            connection,
            rate_limit,
        })
    }

    pub(crate) fn consume(&mut self, input: Consume<'_>) -> Result<u64, BridgeError> {
        let transaction = self.connection.transaction()?;
        let watermark: i64 =
            transaction.query_row("SELECT clock FROM security_state WHERE id=1", [], |row| {
                row.get(0)
            })?;
        if input.now < watermark {
            return Err(BridgeError::Time);
        }
        status_anchor::authorize(&transaction, input)?;
        revocation::accept(&transaction, input)?;
        let subject_digest = sha256_digest(input.pairwise_subject.as_bytes());
        let count: u32 = transaction.query_row(
            "SELECT count(*) FROM audit WHERE subject_digest=?1 AND at>=?2",
            params![subject_digest, input.now - 60],
            |row| row.get(0),
        )?;
        if count >= self.rate_limit {
            return Err(BridgeError::RateLimited);
        }
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO consumed VALUES(?1,?2,?3)",
            params![input.request_id, input.reservation_id, input.now],
        )?;
        if inserted != 1 {
            return Err(BridgeError::Replay);
        }
        let sequence = audit::append(
            &transaction,
            input.request_id,
            &subject_digest,
            input.action,
            input.resource,
            input.now,
        )?;
        transaction.execute("UPDATE security_state SET clock=?1 WHERE id=1", [input.now])?;
        transaction.commit()?;
        Ok(sequence)
    }

    pub(crate) fn apply_verified_current_status(
        &mut self,
        status: &CurrentDeviceStatusV1,
    ) -> Result<(), BridgeError> {
        let transaction = self.connection.transaction()?;
        let nonce_digest = sha256_digest(status.nonce.as_bytes());
        let observed_at = i64::try_from(status.issued_at_epoch_s).map_err(|_| BridgeError::Time)?;
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO identity_status_nonces(nonce_digest,observed_at) VALUES(?1,?2)",
            params![nonce_digest, observed_at],
        )?;
        if inserted != 1 {
            return Err(BridgeError::Replay);
        }
        revocation::raise_current_status(&transaction, status)?;
        status_anchor::apply(&transaction, status)?;
        transaction.commit().map_err(Into::into)
    }

    /// Reads the metadata-only hash-chain journal.
    ///
    /// # Errors
    ///
    /// Returns an error when audit state cannot be read.
    pub fn audit_records(&self) -> Result<Vec<AuditRecord>, BridgeError> {
        audit::records(&self.connection)
    }
}
