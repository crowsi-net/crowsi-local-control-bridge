use std::{os::unix::net::UnixStream, time::Duration};

use crate::{
    BridgeError, BridgeTrust, ControlRequestV1, DispatchTicket, DurableSecurityStore, SenderProof,
    SignedAuthorization, TrustedClock, canonical_request, model::PeerAttestation,
    peer::attest_unix_peer, sha256_digest, store::Consume, validation,
};

pub struct LocalControlBridge<C = crate::SystemTrustedClock> {
    pub(crate) trust: BridgeTrust,
    pub(crate) store: DurableSecurityStore,
    pub(crate) clock: C,
}

impl<C: TrustedClock> LocalControlBridge<C> {
    #[must_use]
    pub const fn new(trust: BridgeTrust, store: DurableSecurityStore, clock: C) -> Self {
        Self {
            trust,
            store,
            clock,
        }
    }

    /// Verifies and consumes one exactly bound control authorization.
    ///
    /// # Errors
    ///
    /// Rejects any failed identity, binding, signature, time, or durable-state check.
    pub(crate) fn authorize_attested(
        &mut self,
        request: &ControlRequestV1,
        authorization: &SignedAuthorization,
        sender_proof: &SenderProof,
        peer: &PeerAttestation,
    ) -> Result<DispatchTicket, BridgeError> {
        self.validate_peer(peer)?;
        let now = self.clock.now_epoch_s();
        if !self.clock.healthy() {
            return Err(BridgeError::Time);
        }
        validation::request(request)?;
        validation::authorization(&authorization.document, request, now, &self.trust)?;
        validation::signature(
            &self.trust.pa_key,
            &crate::canonical_authorization(&authorization.document),
            &authorization.signature_hex,
        )?;
        let sender_key = validation::sender_key(
            &authorization.document.sender_public_key_hex,
            &self.trust.pa_key,
        )?;
        validation::signature(
            &sender_key,
            &canonical_request(request),
            &sender_proof.signature_hex,
        )?;
        self.store.consume(Consume {
            request_id: &request.request_id,
            reservation_id: &authorization.document.reservation_id,
            pairwise_subject: &authorization.document.pairwise_subject,
            service_id: &authorization.document.service_id,
            device_id: &authorization.document.device_id,
            device_proof_key_ref: &authorization.document.device_proof_key_ref,
            session_ref: &authorization.document.session_ref,
            posture_revision: authorization.document.device_posture_revision,
            subject_epoch: authorization.document.subject_revocation_epoch,
            service_epoch: authorization.document.service_revocation_epoch,
            device_epoch: authorization.document.device_revocation_epoch,
            session_epoch: authorization.document.session_revocation_epoch,
            authorization_expires_at: authorization.document.expires_at_epoch_s,
            action: request.action,
            resource: &request.resource,
            now,
        })?;
        Ok(DispatchTicket {
            schema: "crowsi://local-control/dispatch-ticket/v2",
            request_id: request.request_id.clone(),
            reservation_id: authorization.document.reservation_id.clone(),
            action: request.action,
            resource: request.resource.clone(),
            purpose: request.purpose.clone(),
            body_sha256: request.body_sha256.clone(),
            command_digest: sha256_digest(&canonical_request(request)),
            service_id: authorization.document.service_id.clone(),
            pairwise_subject: authorization.document.pairwise_subject.clone(),
            device_id: authorization.document.device_id.clone(),
            device_proof_key_ref: authorization.document.device_proof_key_ref.clone(),
            session_ref: authorization.document.session_ref.clone(),
            workload_id: authorization.document.workload_id.clone(),
            actor_profile_id: authorization.document.actor_profile_id.clone(),
            sender_public_key_hex: authorization.document.sender_public_key_hex.clone(),
            device_posture_revision: authorization.document.device_posture_revision,
            subject_revocation_epoch: authorization.document.subject_revocation_epoch,
            service_revocation_epoch: authorization.document.service_revocation_epoch,
            device_revocation_epoch: authorization.document.device_revocation_epoch,
            session_revocation_epoch: authorization.document.session_revocation_epoch,
            authorized_at_epoch_s: now,
        })
    }

    /// Parses a closed, bounded IPC frame before authorizing it.
    ///
    /// # Errors
    ///
    /// Rejects malformed, oversized, unknown-field, or unauthorized frames.
    pub(crate) fn authorize_attested_frame(
        &mut self,
        frame: &[u8],
        peer: &PeerAttestation,
    ) -> Result<DispatchTicket, BridgeError> {
        if frame.is_empty() || frame.len() > 65_536 {
            return Err(BridgeError::Contract);
        }
        let envelope: crate::IpcAuthorizationEnvelopeV2 =
            serde_json::from_slice(frame).map_err(|_| BridgeError::Contract)?;
        if envelope.schema != "crowsi://local-control/ipc-envelope/v2" {
            return Err(BridgeError::Contract);
        }
        self.authorize_attested(
            &envelope.request,
            &envelope.authorization,
            &envelope.sender_proof,
            peer,
        )
    }

    /// Reads and authorizes one length-prefixed frame from its attested peer.
    ///
    /// The frame and kernel peer evidence come from the same Unix stream, so
    /// callers cannot attach a reusable or self-asserted peer object.
    ///
    /// # Errors
    ///
    /// Rejects failed kernel attestation, framing, or authorization checks.
    pub fn authorize_unix_stream(
        &mut self,
        stream: &mut UnixStream,
    ) -> Result<DispatchTicket, BridgeError> {
        self.authorize_unix_stream_with_timeout(stream, Duration::from_secs(30))
    }

    /// Reads and authorizes one frame with a poll-based finite deadline.
    ///
    /// # Errors
    ///
    /// Rejects unavailable peer evidence, invalid framing, timeout, or failed
    /// authorization without weakening the production peer boundary.
    pub fn authorize_unix_stream_with_timeout(
        &mut self,
        stream: &mut UnixStream,
        timeout: Duration,
    ) -> Result<DispatchTicket, BridgeError> {
        let peer = attest_unix_peer(stream)?;
        let frame = crate::timed_read::frame(stream, timeout, 65_536)?;
        self.authorize_attested_frame(&frame, &peer)
    }

    /// Reads metadata-only audit records.
    ///
    /// # Errors
    ///
    /// Returns an error when the private audit database cannot be read.
    pub fn audit_records(&self) -> Result<Vec<crate::AuditRecord>, BridgeError> {
        self.store.audit_records()
    }

    #[cfg(test)]
    pub(crate) const fn clock_mut(&mut self) -> &mut C {
        &mut self.clock
    }

    fn validate_peer(&self, peer: &PeerAttestation) -> Result<(), BridgeError> {
        if peer.pid == 0
            || peer.process_start_ticks == 0
            || peer.uid != self.trust.caller_uid
            || peer.gid != self.trust.caller_group_id
            || peer.executable_sha256 != self.trust.executable_sha256
        {
            return Err(BridgeError::PeerAttestation);
        }
        Ok(())
    }
}
