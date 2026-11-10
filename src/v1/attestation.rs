//! Bounded SAC1 COSE Sign1 structure and explicit caller-key verification.
//!
//! Parsing establishes structure and the signed snapshot/purpose. It does not
//! establish signature validity, key ownership, publisher trust or freshness.
use super::{
    Error, ObjectHash, Result,
    cbor::{self, Value},
};

pub const MAX_SIGN1_BYTES: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation {
    purpose: String,
    snapshot: ObjectHash,
    key_id: Option<Vec<u8>>,
    signature: [u8; 64],
    protected: Vec<u8>,
    payload: Vec<u8>,
}

impl Attestation {
    pub fn purpose(&self) -> &str {
        &self.purpose
    }
    pub fn snapshot(&self) -> ObjectHash {
        self.snapshot
    }
    pub fn key_id(&self) -> Option<&[u8]> {
        self.key_id.as_deref()
    }
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// COSE Sig_structure with the baseline empty external AAD. This is the
    /// input for an independent verifier selected by caller trust policy.
    pub fn signature_input(&self) -> Vec<u8> {
        cbor::encode(&Value::Array(vec![
            Value::Text("Signature1".into()),
            Value::Bytes(self.protected.clone()),
            Value::Bytes(Vec::new()),
            Value::Bytes(self.payload.clone()),
        ]))
    }

    /// Check against a caller-selected Ed25519 public key. `true` authenticates
    /// these signed bytes under that key; the caller still decides whether the
    /// key, purpose and snapshot are trusted or current.
    #[cfg(feature = "trust")]
    pub fn verify_ed25519(&self, public_key: &[u8; 32]) -> Result<bool> {
        let key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
            .map_err(|_| bad("invalid Ed25519 public key"))?;
        let signature = ed25519_dalek::Signature::from_bytes(&self.signature);
        Ok(key
            .verify_strict(&self.signature_input(), &signature)
            .is_ok())
    }
}

fn bad(message: &str) -> Error {
    Error::Corrupt(format!("attestation: {message}"))
}
fn map(value: &Value) -> Result<&[crate::cbor::MapEntry]> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(bad("header must be a map")),
    }
}
/// Parse exactly one tagged, deterministic SAC1 COSE Sign1 envelope.
/// Algorithm -19 is protected; payload is the embedded deterministic array
/// ["sac.snapshot.v1", purpose_text, snapshot_id_bytes]. No key lookup occurs.
pub fn parse_cose_sign1(encoded: &[u8]) -> Result<Attestation> {
    if encoded.len() > MAX_SIGN1_BYTES {
        return Err(Error::Limit("attestation bytes"));
    }
    // Tag 18 has this unique shortest encoding. The ordinary core parser keeps
    // rejecting tags everywhere else, including protected headers/payload.
    if encoded.first() != Some(&0xd2) {
        return Err(bad("expected canonical COSE Sign1 tag 18"));
    }
    let outer = cbor::decode(&encoded[1..])?;
    let Value::Array(fields) = outer else {
        return Err(bad("Sign1 must be an array"));
    };
    if fields.len() != 4 {
        return Err(bad("Sign1 must have four fields"));
    }
    let Value::Bytes(protected) = &fields[0] else {
        return Err(bad("protected header must be a byte string"));
    };
    let protected_map = cbor::decode(protected)?;
    let protected_headers = map(&protected_map)?;
    let unprotected = map(&fields[1])?;
    if !unprotected.is_empty() {
        return Err(bad("unprotected header must be empty"));
    }
    if protected_headers
        .iter()
        .any(|h| !matches!(h.key, Value::Uint(1 | 4)))
    {
        return Err(Error::Unsupported(
            "header outside SAC1 attestation recipe".into(),
        ));
    }
    let algorithm = protected_headers
        .iter()
        .find(|e| e.key == Value::Uint(1))
        .ok_or_else(|| bad("protected algorithm is required"))?;
    if algorithm.value != Value::NInt(18) {
        return Err(Error::Unsupported(
            "attestation algorithm must be fully specified Ed25519 (-19)".into(),
        ));
    }
    let key_id = protected_headers
        .iter()
        .find(|e| e.key == Value::Uint(4))
        .map(|entry| match &entry.value {
            Value::Bytes(id) if (1..=128).contains(&id.len()) => Ok(id.clone()),
            _ => Err(bad("protected key ID must be 1 through 128 bytes")),
        })
        .transpose()?;
    let Value::Bytes(payload) = &fields[2] else {
        return Err(bad("embedded payload is required"));
    };
    let payload_value = cbor::decode(payload)?;
    let Value::Array(subject) = payload_value else {
        return Err(bad("snapshot payload must be an array"));
    };
    if subject.len() != 3 || subject[0] != Value::Text("sac.snapshot.v1".into()) {
        return Err(bad("snapshot payload domain or arity"));
    }
    let Value::Text(purpose) = &subject[1] else {
        return Err(bad("purpose must be text"));
    };
    if !(1..=256).contains(&purpose.len()) {
        return Err(bad("purpose must be 1 through 256 UTF-8 bytes"));
    }
    let Value::Bytes(snapshot) = &subject[2] else {
        return Err(bad("snapshot ID must be bytes"));
    };
    let snapshot = ObjectHash(
        snapshot
            .as_slice()
            .try_into()
            .map_err(|_| bad("snapshot ID must be 32 bytes"))?,
    );
    let Value::Bytes(signature) = &fields[3] else {
        return Err(bad("signature must be a byte string"));
    };
    let signature = signature
        .as_slice()
        .try_into()
        .map_err(|_| bad("Ed25519 signature must be 64 bytes"))?;
    Ok(Attestation {
        purpose: purpose.clone(),
        snapshot,
        key_id,
        signature,
        protected: protected.clone(),
        payload: payload.clone(),
    })
}

/// Independent optional trust-material outcome. Structural validity alone never
/// means a signature or publisher was accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StructureStatus {
    ValidStructure,
    Invalid,
    Unsupported,
}
impl StructureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ValidStructure => "valid-structure",
            Self::Invalid => "invalid",
            Self::Unsupported => "unsupported",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationOutcome {
    pub index: usize,
    pub structure: StructureStatus,
    pub signature_accepted: bool,
    pub purpose: Option<String>,
    pub snapshot: Option<ObjectHash>,
    pub detail: Option<String>,
}

/// Assess every bounded catalogue entry independently. A malformed envelope,
/// unsupported recipe, or different signed snapshot is visible in its outcome;
/// optional trust material cannot prevent unrelated content recovery. Callers
/// requiring trust parse and verify with their authorized key/purpose policy.
pub fn assess_catalogue(
    catalogue: &super::CanonicalObject,
    expected_snapshot: ObjectHash,
) -> Result<Vec<AttestationOutcome>> {
    if catalogue.kind != 9 || catalogue.version != 1 {
        return Err(bad("expected attestation catalogue"));
    }
    super::validate_core_object(catalogue)?;
    let Value::Array(entries) = cbor::decode(&catalogue.bytes)? else {
        return Err(bad("catalogue must be an array"));
    };
    let mut outcomes = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let Value::Bytes(encoded) = entry else {
            return Err(bad("catalogue entry must be bytes"));
        };
        let mut outcome = AttestationOutcome {
            index,
            structure: StructureStatus::Invalid,
            signature_accepted: false,
            purpose: None,
            snapshot: None,
            detail: None,
        };
        match parse_cose_sign1(encoded) {
            Ok(parsed) => {
                outcome.structure = if parsed.snapshot() == expected_snapshot {
                    StructureStatus::ValidStructure
                } else {
                    StructureStatus::Invalid
                };
                outcome.purpose = Some(parsed.purpose().to_owned());
                outcome.snapshot = Some(parsed.snapshot());
                if parsed.snapshot() != expected_snapshot {
                    outcome.detail = Some("signed snapshot differs from selected snapshot".into());
                }
            }
            Err(error) => {
                outcome.structure = if matches!(error, Error::Unsupported(_)) {
                    StructureStatus::Unsupported
                } else {
                    StructureStatus::Invalid
                };
                outcome.detail = Some(error.to_string());
            }
        }
        outcomes.push(outcome);
    }
    Ok(outcomes)
}
