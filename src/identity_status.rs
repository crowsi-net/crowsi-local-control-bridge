use ed25519_dalek::{Signature, VerifyingKey};
use ihat_identity_assertion_contracts::{AssertionError, AssertionVerifier, CurrentDeviceStatusV1};

use crate::BridgeError;

#[derive(Clone)]
pub struct IdentityStatusTrust {
    key: VerifyingKey,
    key_id: String,
    issuer: String,
    audience: String,
    service_id: String,
}

impl IdentityStatusTrust {
    /// Pins the identity authority key and the status consumer context.
    ///
    /// # Errors
    ///
    /// Rejects weak keys and ambiguous or oversized identifiers.
    pub fn new(
        public_key: [u8; 32],
        key_id: &str,
        issuer: &str,
        audience: &str,
        service_id: &str,
    ) -> Result<Self, BridgeError> {
        let key = VerifyingKey::from_bytes(&public_key).map_err(|_| BridgeError::Contract)?;
        if key.is_weak()
            || !identifier(key_id, 128)
            || !identifier(issuer, 512)
            || !identifier(audience, 128)
            || !identifier(service_id, 128)
        {
            return Err(BridgeError::Contract);
        }
        Ok(Self {
            key,
            key_id: key_id.into(),
            issuer: issuer.into(),
            audience: audience.into(),
            service_id: service_id.into(),
        })
    }

    pub(crate) fn issuer(&self) -> &str {
        &self.issuer
    }

    pub(crate) fn audience(&self) -> &str {
        &self.audience
    }

    pub(crate) fn service_id(&self) -> &str {
        &self.service_id
    }

    pub(crate) fn public_key(&self) -> [u8; 32] {
        self.key.to_bytes()
    }
}

impl AssertionVerifier for IdentityStatusTrust {
    fn verify(&self, key_id: &str, canonical_payload: &[u8], signature: &str) -> bool {
        if key_id != self.key_id {
            return false;
        }
        let Ok(bytes) = hex::decode(signature) else {
            return false;
        };
        let Ok(signature) = Signature::try_from(bytes.as_slice()) else {
            return false;
        };
        self.key
            .verify_strict(canonical_payload, &signature)
            .is_ok()
    }
}

impl From<AssertionError> for BridgeError {
    fn from(error: AssertionError) -> Self {
        match error {
            AssertionError::InputTooLarge | AssertionError::ContractInvalid => Self::Contract,
            AssertionError::ContextMismatch => Self::Authentication,
            AssertionError::TimeInvalid => Self::Time,
            AssertionError::SignatureInvalid => Self::Signature,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentStatusBinding {
    pairwise_subject: String,
    service_id: String,
    device_id: String,
    device_proof_key_ref: String,
    session_ref: String,
}

impl CurrentStatusBinding {
    /// Defines the exact identity tuple expected by one status update.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or ambiguous identifiers.
    pub fn new(
        pairwise_subject: &str,
        service_id: &str,
        device_id: &str,
        device_proof_key_ref: &str,
        session_ref: &str,
    ) -> Result<Self, BridgeError> {
        if !identifier(pairwise_subject, 128)
            || !identifier(service_id, 128)
            || !identifier(device_id, 128)
            || !identifier(device_proof_key_ref, 240)
            || !identifier(session_ref, 128)
        {
            return Err(BridgeError::Contract);
        }
        Ok(Self {
            pairwise_subject: pairwise_subject.into(),
            service_id: service_id.into(),
            device_id: device_id.into(),
            device_proof_key_ref: device_proof_key_ref.into(),
            session_ref: session_ref.into(),
        })
    }

    pub(crate) fn matches(&self, status: &CurrentDeviceStatusV1) -> bool {
        self.pairwise_subject == status.pairwise_subject
            && self.service_id == status.service_id
            && self.device_id == status.device_id
            && self.device_proof_key_ref == status.device_proof_key_ref
            && self.session_ref == status.session_ref
    }
}

fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":._/-".contains(&byte))
}
