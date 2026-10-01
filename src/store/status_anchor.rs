use ihat_identity_assertion_contracts::CurrentDeviceStatusV1;
use rusqlite::{OptionalExtension, Transaction, params};

use crate::{BridgeError, sha256_digest, store::Consume};

pub(super) fn apply(
    transaction: &Transaction<'_>,
    status: &CurrentDeviceStatusV1,
) -> Result<(), BridgeError> {
    let binding = status_binding(
        &status.pairwise_subject,
        &status.service_id,
        &status.device_id,
        &status.device_proof_key_ref,
        &status.session_ref,
    );
    let expires_at = i64::try_from(status.expires_at_epoch_s).map_err(|_| BridgeError::Time)?;
    let issued_at = i64::try_from(status.issued_at_epoch_s).map_err(|_| BridgeError::Time)?;
    let changed = transaction.execute(
        "INSERT INTO identity_status_anchors VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)
         ON CONFLICT(binding_digest) DO UPDATE SET
         session_ref_digest=excluded.session_ref_digest,
         posture_revision=excluded.posture_revision,subject_epoch=excluded.subject_epoch,
         service_epoch=excluded.service_epoch,device_epoch=excluded.device_epoch,
         session_epoch=excluded.session_epoch,issued_at=excluded.issued_at,
         expires_at=excluded.expires_at
         WHERE excluded.issued_at>=identity_status_anchors.issued_at",
        params![
            binding,
            sha256_digest(status.session_ref.as_bytes()),
            status.device_posture.revision,
            status.revocation_epochs.subject,
            status.revocation_epochs.service,
            status.revocation_epochs.device,
            status.revocation_epochs.session,
            issued_at,
            expires_at,
        ],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(BridgeError::Revoked)
    }
}

pub(super) fn authorize(
    transaction: &Transaction<'_>,
    input: Consume<'_>,
) -> Result<(), BridgeError> {
    let binding = status_binding(
        input.pairwise_subject,
        input.service_id,
        input.device_id,
        input.device_proof_key_ref,
        input.session_ref,
    );
    let anchor = transaction
        .query_row(
            "SELECT session_ref_digest,posture_revision,subject_epoch,service_epoch,
             device_epoch,session_epoch,expires_at FROM identity_status_anchors
             WHERE binding_digest=?1",
            [binding],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, u64>(3)?,
                    row.get::<_, u64>(4)?,
                    row.get::<_, u64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()?;
    let Some(anchor) = anchor else {
        return Err(BridgeError::Authentication);
    };
    let expected = (
        sha256_digest(input.session_ref.as_bytes()),
        input.posture_revision,
        input.subject_epoch,
        input.service_epoch,
        input.device_epoch,
        input.session_epoch,
    );
    if anchor.0 != expected.0
        || (anchor.1, anchor.2, anchor.3, anchor.4, anchor.5)
            != (expected.1, expected.2, expected.3, expected.4, expected.5)
        || input.authorization_expires_at > anchor.6
    {
        return Err(BridgeError::Revoked);
    }
    Ok(())
}

fn status_binding(
    pairwise: &str,
    service: &str,
    device: &str,
    proof: &str,
    session: &str,
) -> String {
    let mut canonical = b"crowsi.identity.current-status-anchor.v1\n".to_vec();
    for part in [pairwise, service, device, proof, session] {
        canonical.extend_from_slice(&(part.len() as u64).to_be_bytes());
        canonical.extend_from_slice(part.as_bytes());
    }
    sha256_digest(&canonical)
}
