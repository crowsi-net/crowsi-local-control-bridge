use rusqlite::{Transaction, params};

use ihat_identity_assertion_contracts::CurrentDeviceStatusV1;

use crate::{BridgeError, sha256_digest, store::Consume};

pub(super) fn accept(transaction: &Transaction<'_>, input: Consume<'_>) -> Result<(), BridgeError> {
    let subject = binding(&[input.pairwise_subject]);
    let service = binding(&[input.pairwise_subject, input.service_id]);
    let device = binding(&[input.pairwise_subject, input.service_id, input.device_id]);
    let session = binding(&[
        input.pairwise_subject,
        input.service_id,
        input.device_id,
        input.session_ref,
    ]);
    for (scope, key, epoch) in [
        ("subject", subject.as_str(), input.subject_epoch),
        ("service", service.as_str(), input.service_epoch),
        ("device", device.as_str(), input.device_epoch),
        ("session", session.as_str(), input.session_epoch),
        ("posture", device.as_str(), input.posture_revision),
    ] {
        accept_epoch(transaction, scope, key, epoch)?;
    }
    Ok(())
}

pub(super) fn raise_current_status(
    transaction: &Transaction<'_>,
    value: &CurrentDeviceStatusV1,
) -> Result<(), BridgeError> {
    let subject = binding(&[&value.pairwise_subject]);
    let service = binding(&[&value.pairwise_subject, &value.service_id]);
    let device = binding(&[&value.pairwise_subject, &value.service_id, &value.device_id]);
    let session = binding(&[
        &value.pairwise_subject,
        &value.service_id,
        &value.device_id,
        &value.session_ref,
    ]);
    for (scope, key, epoch) in [
        ("subject", subject.as_str(), value.revocation_epochs.subject),
        ("service", service.as_str(), value.revocation_epochs.service),
        ("device", device.as_str(), value.revocation_epochs.device),
        ("session", session.as_str(), value.revocation_epochs.session),
        ("posture", device.as_str(), value.device_posture.revision),
    ] {
        accept_epoch(transaction, scope, key, epoch)?;
    }
    Ok(())
}

fn accept_epoch(
    transaction: &Transaction<'_>,
    scope: &str,
    key: &str,
    presented: u64,
) -> Result<(), BridgeError> {
    let current = current_epoch(transaction, scope, key)?;
    if presented < current {
        return Err(BridgeError::Revoked);
    }
    raise_epoch(transaction, scope, key, presented)
}

fn raise_epoch(
    transaction: &Transaction<'_>,
    scope: &str,
    key: &str,
    epoch: u64,
) -> Result<(), BridgeError> {
    transaction.execute(
        "INSERT INTO revocation_watermarks(scope,binding,epoch) VALUES(?1,?2,?3)
         ON CONFLICT(scope,binding) DO UPDATE SET epoch=max(epoch,excluded.epoch)",
        params![scope, key, epoch],
    )?;
    Ok(())
}

fn current_epoch(
    transaction: &Transaction<'_>,
    scope: &str,
    key: &str,
) -> Result<u64, BridgeError> {
    transaction
        .query_row(
            "SELECT epoch FROM revocation_watermarks WHERE scope=?1 AND binding=?2",
            params![scope, key],
            |row| row.get(0),
        )
        .or_else(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => Ok(0),
            other => Err(other),
        })
        .map_err(Into::into)
}

fn binding(parts: &[&str]) -> String {
    let mut canonical = b"crowsi.identity.revocation.binding.v1\n".to_vec();
    for part in parts {
        canonical.extend_from_slice(&(part.len() as u64).to_be_bytes());
        canonical.extend_from_slice(part.as_bytes());
    }
    sha256_digest(&canonical)
}
