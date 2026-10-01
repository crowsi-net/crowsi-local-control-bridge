use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::{AuditRecord, BridgeAction, BridgeError, sha256_digest};

pub(super) fn append(
    transaction: &Transaction<'_>,
    request_id: &str,
    subject_digest: &str,
    action_value: BridgeAction,
    resource: &str,
    now: i64,
) -> Result<u64, BridgeError> {
    let previous: Option<String> = transaction
        .query_row(
            "SELECT event_digest FROM audit ORDER BY seq DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let resource_digest = sha256_digest(resource.as_bytes());
    let event_digest = sha256_digest(
        format!(
            "{}|{request_id}|{}|{resource_digest}|{now}",
            previous.as_deref().unwrap_or("genesis"),
            action(action_value)
        )
        .as_bytes(),
    );
    transaction.execute(
        "INSERT INTO audit(request_id,subject_digest,action,resource_digest,event_digest,at)
         VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            request_id,
            subject_digest,
            action(action_value),
            resource_digest,
            event_digest,
            now
        ],
    )?;
    u64::try_from(transaction.last_insert_rowid()).map_err(|_| BridgeError::Storage)
}

pub(super) fn records(connection: &Connection) -> Result<Vec<AuditRecord>, BridgeError> {
    let mut query = connection.prepare(
        "SELECT seq,request_id,action,resource_digest,event_digest,at FROM audit ORDER BY seq",
    )?;
    let rows = query.query_map([], |row| {
        Ok(AuditRecord {
            sequence: row.get(0)?,
            request_id: row.get(1)?,
            action: parse_action(&row.get::<_, String>(2)?),
            resource_digest: row.get(3)?,
            event_digest: row.get(4)?,
            occurred_at_epoch_s: row.get(5)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

fn action(value: BridgeAction) -> &'static str {
    match value {
        BridgeAction::ContainAsset => "contain-asset",
        BridgeAction::RevokeCredential => "revoke-credential",
        BridgeAction::EnrollCredential => "enroll-credential",
        BridgeAction::UseCredential => "use-credential",
        BridgeAction::ObserveProvider => "observe-provider",
        BridgeAction::RunDiagnostic => "run-diagnostic",
    }
}

fn parse_action(value: &str) -> BridgeAction {
    match value {
        "contain-asset" => BridgeAction::ContainAsset,
        "revoke-credential" => BridgeAction::RevokeCredential,
        "enroll-credential" => BridgeAction::EnrollCredential,
        "use-credential" => BridgeAction::UseCredential,
        "observe-provider" => BridgeAction::ObserveProvider,
        _ => BridgeAction::RunDiagnostic,
    }
}

#[cfg(test)]
mod tests {
    use super::{action, parse_action};
    use crate::BridgeAction;

    #[test]
    fn credential_use_action_round_trips_through_audit_storage() {
        let value = BridgeAction::UseCredential;
        assert_eq!(parse_action(action(value)), value);
    }
}
