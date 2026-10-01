use ihat_identity_assertion_contracts::{
    CurrentDeviceStatusV1, decode_current_status_strict, verify_current_status_at,
};

use crate::{BridgeError, CurrentStatusBinding, LocalControlBridge, TrustedClock};

impl<C: TrustedClock> LocalControlBridge<C> {
    /// Verifies and atomically applies one current device status document.
    ///
    /// # Errors
    ///
    /// Rejects untrusted, stale, replayed, or incorrectly bound status documents.
    pub fn apply_current_device_status(
        &mut self,
        wire: &[u8],
        expected: &CurrentStatusBinding,
    ) -> Result<(), BridgeError> {
        let status = self.verified_current_device_status(wire, expected)?;
        self.store.apply_verified_current_status(&status)
    }

    /// Verifies status evidence without consuming its nonce or changing epochs.
    ///
    /// # Errors
    ///
    /// Rejects failed signature, time, trust-context, or identity bindings.
    pub fn verify_current_device_status(
        &self,
        wire: &[u8],
        expected: &CurrentStatusBinding,
    ) -> Result<(), BridgeError> {
        self.verified_current_device_status(wire, expected)
            .map(|_| ())
    }

    fn verified_current_device_status(
        &self,
        wire: &[u8],
        expected: &CurrentStatusBinding,
    ) -> Result<CurrentDeviceStatusV1, BridgeError> {
        let trust = &self.trust.identity_status;
        let now = self.clock.now_epoch_s();
        if !self.clock.healthy() {
            return Err(BridgeError::Time);
        }
        let now = u64::try_from(now).map_err(|_| BridgeError::Time)?;
        let status = decode_current_status_strict(wire).map_err(BridgeError::from)?;
        verify_current_status_at(&status, trust, trust.issuer(), trust.audience(), now)
            .map_err(BridgeError::from)?;
        if !expected.matches(&status) {
            return Err(BridgeError::Binding);
        }
        if status.service_id != trust.service_id() {
            return Err(BridgeError::Authentication);
        }
        Ok(status)
    }
}
