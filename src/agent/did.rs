//! DID Document and Resolver for ZeroClaw agent identity.
//!
//! Implements a minimal DID method `did:zeroclaw:zara/<version>` following
//! W3C DID Core 1.0. The DID document is generated dynamically from the
//! agent version — no distributed registry or blockchain required.
//!
//! ## DID Method
//!
//! ```
//! did:zeroclaw:zara/<version>
//! ```
//!
//! Example: `did:zeroclaw:zara/0.6.5`
//!
//! ## DID Document
//!
//! ```json
//! {
//!   "@context": [
//!     "https://www.w3.org/ns/did/v1",
//!     "https://zeroclaw.dev/did/v1"
//!   ],
//!   "id": "did:zeroclaw:zara/0.6.5",
//!   "verificationMethod": [{
//!     "id": "did:zeroclaw:zara/0.6.5#audit-chain",
//!     "type": "HmacVerificationKey2024",
//!     "controller": "did:zeroclaw:zara/0.6.5"
//!   }],
//!   "authentication": ["did:zeroclaw:zara/0.6.5#agent"],
//!   "assertionMethod": ["did:zeroclaw:zara/0.6.5#audit-chain"]
//! }
//! ```

use crate::agent::vi_issuer::{AgentIdentity, ViCredential};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

const DID_CONTEXT_V1: &str = "https://www.w3.org/ns/did/v1";
const ZEROCLAW_DID_CONTEXT: &str = "https://zeroclaw.dev/did/v1";
const HMAC_KEY_SIZE: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// Errors that can occur during DID operations.
#[derive(Debug, Clone)]
pub enum DIDError {
    /// The DID format is invalid.
    InvalidDID(String),
    /// The DID method is not supported.
    UnsupportedMethod(String),
    /// Verification failed.
    VerificationFailed(String),
    /// DID not found.
    NotFound(String),
}

impl std::fmt::Display for DIDError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DIDError::InvalidDID(d) => write!(f, "Invalid DID: {}", d),
            DIDError::UnsupportedMethod(m) => write!(f, "Unsupported DID method: {}", m),
            DIDError::VerificationFailed(e) => write!(f, "Verification failed: {}", e),
            DIDError::NotFound(d) => write!(f, "DID not found: {}", d),
        }
    }
}

impl std::error::Error for DIDError {}

/// A verification method entry in a DID Document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// Unique identifier of this verification method.
    pub id: String,
    /// Type of verification method.
    #[serde(rename = "type")]
    pub verification_type: String,
    /// Controller of this verification method.
    pub controller: String,
}

/// A DID Document conforming to W3C DID Core 1.0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDDocument {
    /// JSON-LD @context.
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// The DID that this document describes.
    pub id: String,
    /// Verification methods for this DID.
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    /// Authentication methods (can authenticate as the DID subject).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<String>,
    /// Assertion methods (can make assertions on behalf of the DID subject).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub assertion_method: Vec<String>,
}

/// DID Resolver for `did:zeroclaw:` method.
///
/// Generates DID Documents dynamically from agent version.
/// No distributed registry — this is a "static" DID method.
#[derive(Debug, Clone)]
pub struct DIDResolver {
    version: String,
    signing_key: Vec<u8>,
}

impl DIDResolver {
    /// Create a new resolver from version and HMAC signing key.
    ///
    /// The signing key must be 32 bytes (256 bits).
    pub fn new(version: String, signing_key: Vec<u8>) -> Self {
        Self { version, signing_key }
    }

    /// Create from an existing `AgentIdentity` and HMAC key bytes.
    pub fn from_identity(identity: &AgentIdentity, signing_key: Vec<u8>) -> Self {
        Self {
            version: identity.version.clone(),
            signing_key,
        }
    }

    /// Resolve a DID to its DID Document.
    ///
    /// Returns the DID Document if the DID is valid and supported.
    pub fn resolve(&self, did: &str) -> Result<DIDDocument, DIDError> {
        // Parse DID: did:zeroclaw:zara/<version>
        let parsed = Self::parse_did(did)?;

        // Validate method
        if parsed.method != "zeroclaw" {
            return Err(DIDError::UnsupportedMethod(parsed.method));
        }

        // Validate namespace
        if parsed.namespace != "zara" {
            return Err(DIDError::InvalidDID(format!(
                "Unknown namespace '{}' — expected 'zara'",
                parsed.namespace
            )));
        }

        // Validate version matches our resolver
        if parsed.id != self.version {
            return Err(DIDError::NotFound(format!(
                "DID version '{}' not found — current version is '{}'",
                parsed.id, self.version
            )));
        }

        Ok(self.generate_document(&parsed.did))
    }

    /// Verify a VI Credential against this DID.
    ///
    /// This performs off-chain verification using the DID Document's
    /// verification method.
    pub fn verify_credential(&self, cred: &ViCredential) -> Result<(), DIDError> {
        // Extract the subject DID from credential
        let subject_id = &cred.credential_subject.id;

        // Parse the subject DID
        let parsed = Self::parse_did(subject_id)?;

        // Validate it resolves to our document
        if parsed.id != self.version {
            return Err(DIDError::VerificationFailed(format!(
                "Subject DID version '{}' does not match resolver version '{}'",
                parsed.id, self.version
            )));
        }

        // Verify the proof using HMAC
        let subject_json = serde_json::to_string(&cred.credential_subject)
            .map_err(|e| DIDError::VerificationFailed(format!("Serialization failed: {}", e)))?;

        let expected_prefix = "hmac-sha256:";
        if !cred.proof.proof_value.starts_with(expected_prefix) {
            return Err(DIDError::VerificationFailed(
                "Invalid proof value format".to_string(),
            ));
        }

        let expected_hmac = &cred.proof.proof_value[expected_prefix.len()..];
        let computed_hmac = self.compute_hmac(&subject_json);

        if computed_hmac != expected_hmac {
            return Err(DIDError::VerificationFailed(
                "HMAC signature mismatch".to_string(),
            ));
        }

        Ok(())
    }

    /// Parse a DID string into its components.
    ///
    /// Handles both plain DIDs (`did:zeroclaw:zara/0.6.5`) and
    /// DIDs with fragments (`did:zeroclaw:zara/0.6.5#agent`).
    fn parse_did(did: &str) -> Result<ParsedDID, DIDError> {
        // DID format: did:<method>:<namespace>/<id> or did:<method>:<namespace>/<id>#<fragment>
        let Some(without_scheme) = did.strip_prefix("did:") else {
            return Err(DIDError::InvalidDID(format!(
                "DID must start with 'did:', got '{}'",
                did
            )));
        };

        // Strip fragment if present
        let (without_fragment, _fragment) = without_scheme
            .split_once('#')
            .unwrap_or((without_scheme, ""));

        let parts: Vec<&str> = without_fragment.splitn(3, ':').collect();
        if parts.len() < 2 {
            return Err(DIDError::InvalidDID(format!(
                "DID must have at least method and id: '{}'",
                did
            )));
        }

        let method = parts[0];
        let rest = parts[1];

        // Split namespace/id (e.g., "zara/0.6.5")
        let (namespace, id) = if let Some((ns, id_part)) = rest.split_once('/') {
            (ns.to_string(), id_part.to_string())
        } else {
            (rest.to_string(), String::new())
        };

        Ok(ParsedDID {
            did: did.to_string(),
            method: method.to_string(),
            namespace,
            id,
        })
    }

    /// Generate a DID Document for a parsed DID.
    fn generate_document(&self, did: &str) -> DIDDocument {
        let verification_method_id = format!("{}#audit-chain", did);
        let authentication_id = format!("{}#agent", did);

        DIDDocument {
            context: vec![DID_CONTEXT_V1.to_string(), ZEROCLAW_DID_CONTEXT.to_string()],
            id: did.to_string(),
            verification_method: vec![VerificationMethod {
                id: verification_method_id.clone(),
                verification_type: "HmacVerificationKey2024".to_string(),
                controller: did.to_string(),
            }],
            authentication: vec![authentication_id],
            assertion_method: vec![verification_method_id],
        }
    }

    /// Compute HMAC-SHA256 over data.
    fn compute_hmac(&self, data: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.signing_key)
            .expect("HMAC accepts any key size");
        mac.update(data.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}

/// Parsed DID components.
struct ParsedDID {
    did: String,
    method: String,
    namespace: String,
    id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::vi_issuer::{CredentialProof, CredentialSubject, ViCredential};
    use chrono::Utc;

    fn test_resolver() -> DIDResolver {
        let signing_key = vec![0u8; HMAC_KEY_SIZE];
        DIDResolver::new("0.6.5".to_string(), signing_key)
    }

    fn test_credential(subject_id: &str, proof_value: &str) -> ViCredential {
        ViCredential {
            context: vec!["https://www.w3.org/2018/credentials/v1".to_string()],
            id: "urn:zeroclaw:vi:test".to_string(),
            credential_type: vec!["VerifiableCredential".to_string(), "ZaraToolExecutionCredential".to_string()],
            issuer: "did:zeroclaw:zara/0.6.5".to_string(),
            issuance_date: Utc::now(),
            credential_subject: CredentialSubject {
                id: subject_id.to_string(),
                tool_name: "shell".to_string(),
                result_hash: "abc123".to_string(),
                audit_chain_hash: "def456".to_string(),
                success: true,
                output_digest: "digest".to_string(),
                channel: "test".to_string(),
                error: None,
            },
            proof: CredentialProof {
                proof_type: "HMAC2024".to_string(),
                verification_method: "did:zeroclaw:zara/0.6.5#audit-chain".to_string(),
                proof_value: proof_value.to_string(),
            },
        }
    }

    #[test]
    fn resolve_valid_did() {
        let resolver = test_resolver();
        let doc = resolver.resolve("did:zeroclaw:zara/0.6.5").unwrap();

        assert_eq!(doc.id, "did:zeroclaw:zara/0.6.5");
        assert_eq!(doc.context.len(), 2);
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.verification_method[0].id, "did:zeroclaw:zara/0.6.5#audit-chain");
        assert_eq!(doc.verification_method[0].verification_type, "HmacVerificationKey2024");
        assert_eq!(doc.authentication, vec!["did:zeroclaw:zara/0.6.5#agent"]);
        assert_eq!(doc.assertion_method, vec!["did:zeroclaw:zara/0.6.5#audit-chain"]);
    }

    #[test]
    fn resolve_invalid_did_format() {
        let resolver = test_resolver();
        let result = resolver.resolve("did:invalid");
        assert!(matches!(result, Err(DIDError::InvalidDID(_))));

        let result = resolver.resolve("not-a-did");
        assert!(matches!(result, Err(DIDError::InvalidDID(_))));
    }

    #[test]
    fn resolve_unsupported_method() {
        let resolver = test_resolver();
        let result = resolver.resolve("did:key:abc123");
        assert!(matches!(result, Err(DIDError::UnsupportedMethod(_))));
    }

    #[test]
    fn resolve_wrong_namespace() {
        let resolver = test_resolver();
        let result = resolver.resolve("did:zeroclaw:other/0.6.5");
        assert!(matches!(result, Err(DIDError::InvalidDID(_))));
    }

    #[test]
    fn resolve_wrong_version() {
        let resolver = test_resolver();
        let result = resolver.resolve("did:zeroclaw:zara/99.99.99");
        assert!(matches!(result, Err(DIDError::NotFound(_))));
    }

    #[test]
    fn verify_credential_valid() {
        let resolver = test_resolver();

        // Build a credential with a known HMAC
        let subject = CredentialSubject {
            id: "did:zeroclaw:zara/0.6.5#agent".to_string(),
            tool_name: "shell".to_string(),
            result_hash: "abc123".to_string(),
            audit_chain_hash: "def456".to_string(),
            success: true,
            output_digest: "digest".to_string(),
            channel: "test".to_string(),
            error: None,
        };
        let subject_json = serde_json::to_string(&subject).unwrap();

        // Compute HMAC with zero key
        let mut mac = HmacSha256::new_from_slice(&[0u8; 32]).unwrap();
        mac.update(subject_json.as_bytes());
        let hmac = hex::encode(mac.finalize().into_bytes());

        let cred = test_credential("did:zeroclaw:zara/0.6.5#agent", &format!("hmac-sha256:{}", hmac));
        let result = resolver.verify_credential(&cred);
        assert!(result.is_ok(), "Expected ok, got: {:?}", result);
    }

    #[test]
    fn verify_credential_wrong_subject_did() {
        let resolver = test_resolver();
        let cred = test_credential("did:zeroclaw:zara/99.99.99#agent", "hmac-sha256:abc");
        let result = resolver.verify_credential(&cred);
        assert!(matches!(result, Err(DIDError::VerificationFailed(_))));
    }
}
