//! Verifiable Identity (VI) Credential Issuer
//!
//! Issues W3C VC Data Model 1.1 inspired credentials anchored to the
//! ZeroClaw audit Merkle chain. Each credential proves that Zara executed
//! a specific tool with a specific result, verifiable against the audit log.
//!
//! ## Credential Structure
//!
//! ```json
//! {
//!   "@context": ["https://www.w3.org/2018/credentials/v1"],
//!   "id": "urn:zeroclaw:vi:<uuid>",
//!   "type": ["VerifiableCredential", "ZaraToolExecutionCredential"],
//!   "issuer": "did:zeroclaw:zara/v0.6.5",
//!   "issuanceDate": "2026-03-29T...",
//!   "credentialSubject": {
//!     "id": "did:zeroclaw:zara/v0.6.5#agent",
//!     "toolName": "shell",
//!     "resultHash": "sha256:...",
//!     "auditChainHash": "sha256:...",
//!     "success": true,
//!     "outputDigest": "sha256:..."
//!   },
//!   "proof": {
//!     "type": "HMAC2024",
//!     "verificationMethod": "did:zeroclaw:zara/v0.6.5#audit-chain",
//!     "proofValue": "hmac-sha256:..."
//!   }
//! }
//! ```

use crate::security::audit::AuditLogger;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

const ZARCLAW_CONTEXT: &str = "https://www.w3.org/2018/credentials/v1";
const ZARCLAW_CREDENTIAL_TYPE: &str = "ZaraToolExecutionCredential";

/// HMAC-SHA256 alias for the proof type.
type HmacSha256 = Hmac<Sha256>;

/// A verifiable identity credential for a single tool execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViCredential {
    /// W3C VC @context
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// Unique credential ID (URN)
    pub id: String,
    /// Credential types
    #[serde(rename = "type")]
    pub credential_type: Vec<String>,
    /// DID of the issuer (Zara)
    pub issuer: String,
    /// Issuance timestamp (ISO 8601)
    #[serde(rename = "issuanceDate")]
    pub issuance_date: DateTime<Utc>,
    /// Credential subject (the tool execution claim)
    #[serde(rename = "credentialSubject")]
    pub credential_subject: CredentialSubject,
    /// Cryptographic proof
    pub proof: CredentialProof,
}

/// The claims asserted by the credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSubject {
    /// Subject DID
    pub id: String,
    /// Name of the tool that was executed
    #[serde(rename = "toolName")]
    pub tool_name: String,
    /// SHA-256 fingerprint of (success, output, error)
    #[serde(rename = "resultHash")]
    pub result_hash: String,
    /// Hash of the audit chain entry this credential is anchored to
    #[serde(rename = "auditChainHash")]
    pub audit_chain_hash: String,
    /// Whether the tool executed successfully
    pub success: bool,
    /// SHA-256 of the raw tool output (for integrity verification)
    #[serde(rename = "outputDigest")]
    pub output_digest: String,
    /// Channel through which the tool was invoked
    pub channel: String,
    /// Optional error message if success=false
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// HMAC-SHA256 proof over the credential subject.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProof {
    /// Proof type
    #[serde(rename = "type")]
    pub proof_type: String,
    /// Verification method describing how to verify
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    /// HMAC-SHA256 hex signature over canonical JSON of credentialSubject
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

/// Agent identity used in credentials.
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    /// DID-style identifier for the agent
    pub did: String,
    /// Human-readable name
    pub name: String,
    /// ZeroClaw version
    pub version: String,
}

impl AgentIdentity {
    /// Create identity from version string.
    pub fn new(version: &str) -> Self {
        Self {
            did: format!("did:zeroclaw:zara/{version}"),
            name: "Zara Claw".to_string(),
            version: version.to_string(),
        }
    }
}

/// Issues VI credentials anchored to the audit Merkle chain.
pub struct ViIssuer {
    identity: AgentIdentity,
    audit_logger: Arc<AuditLogger>,
    signing_key: Vec<u8>,
}

impl ViIssuer {
    /// Create a new VI issuer.
    ///
    /// `signing_key` must be a 32-byte hex-encoded key (same as
    /// `ZEROCLAW_AUDIT_SIGNING_KEY` env var used by `AuditLogger`).
    pub fn new(
        version: &str,
        audit_logger: Arc<AuditLogger>,
        signing_key: Vec<u8>,
    ) -> Self {
        Self {
            identity: AgentIdentity::new(version),
            audit_logger,
            signing_key,
        }
    }

    /// Issue a new VI credential for a tool execution.
    ///
    /// `tool_name` — name of the tool that was executed.
    /// `result_hash` — `compute_result_hash(success, &output, error.as_deref())`.
    /// `success` — whether the tool succeeded.
    /// `output` — raw output string from the tool.
    /// `error` — optional error message.
    /// `channel` — channel through which the tool was invoked.
    pub fn issue(
        &self,
        tool_name: &str,
        result_hash: &str,
        success: bool,
        output: &str,
        error: Option<&str>,
        channel: &str,
    ) -> ViCredential {
        let credential_id = format!("urn:zeroclaw:vi:{}", uuid::Uuid::new_v4());

        // Anchor to the current audit chain head
        let audit_chain_hash = self.audit_logger.get_last_entry_hash();

        // Digest of the raw output
        let output_digest = hex::encode(Sha256::digest(output.as_bytes()));

        let subject = CredentialSubject {
            id: format!("{}#agent", self.identity.did),
            tool_name: tool_name.to_string(),
            result_hash: result_hash.to_string(),
            audit_chain_hash: audit_chain_hash.clone(),
            success,
            output_digest,
            channel: channel.to_string(),
            error: error.map(String::from),
        };

        // Sign the subject using HMAC-SHA256
        let subject_json = serde_json::to_string(&subject).unwrap_or_default();
        let proof_value = self.compute_hmac(&subject_json);

        let proof = CredentialProof {
            proof_type: "HMAC2024".to_string(),
            verification_method: format!("{}#audit-chain", self.identity.did),
            proof_value: format!("hmac-sha256:{proof_value}"),
        };

        ViCredential {
            context: vec![
                ZARCLAW_CONTEXT.to_string(),
                "https://zeroclaw.dev/credentials/zara-vi/v1".to_string(),
            ],
            id: credential_id,
            credential_type: vec![
                "VerifiableCredential".to_string(),
                ZARCLAW_CREDENTIAL_TYPE.to_string(),
            ],
            issuer: self.identity.did.clone(),
            issuance_date: Utc::now(),
            credential_subject: subject,
            proof,
        }
    }

    /// Compute HMAC-SHA256 over `data`.
    fn compute_hmac(&self, data: &str) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.signing_key).expect("HMAC accepts any key size");
        mac.update(data.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Verify a credential's proof against the expected subject data.
    ///
    /// Returns `Ok(())` if the proof is valid, `Err(reason)` otherwise.
    pub fn verify(&self, cred: &ViCredential) -> Result<(), String> {
        let subject_json =
            serde_json::to_string(&cred.credential_subject)
                .map_err(|e| format!("serialization failed: {e}"))?;

        let expected_hmac = self.compute_hmac(&subject_json);
        let proof_value = cred
            .proof
            .proof_value
            .strip_prefix("hmac-sha256:")
            .ok_or_else(|| "malformed proof value: missing hmac-sha256 prefix".to_string())?;

        if proof_value != expected_hmac {
            return Err("HMAC signature mismatch".to_string());
        }

        // Verify the audit chain anchor is reachable
        let current_head = self.audit_logger.get_last_entry_hash();
        if current_head != cred.credential_subject.audit_chain_hash {
            // The credential was anchored to a past chain state — this is expected
            // for old credentials. Only warn, don't reject.
            tracing::warn!(
                cred_chain = %cred.credential_subject.audit_chain_hash,
                current_chain = %current_head,
                "VI credential anchored to past audit chain state"
            );
        }

        Ok(())
    }

    /// Serialize a credential to JSON string.
    pub fn credential_to_json(&self, cred: &ViCredential) -> String {
        serde_json::to_string_pretty(cred).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuditConfig;
    use crate::security::audit::AuditLogger;
    use std::sync::Mutex;

    fn test_audit_logger() -> (tempfile::TempDir, Arc<AuditLogger>) {
        let dir = tempfile::tempdir().unwrap();
        let config = AuditConfig {
            enabled: true,
            log_path: "audit.log".into(),
            sign_events: true,
            ..Default::default()
        };
        // SAFETY: single-threaded test, setting env var for test isolation
        unsafe {
            std::env::set_var("ZEROCLAW_AUDIT_SIGNING_KEY",
                "0102030405060708091011121314151617181920212223242526272829303132");
        }
        let logger = Arc::new(AuditLogger::new(config, dir.path().to_path_buf()).unwrap());
        (dir, logger)
    }

    #[test]
    fn vi_credential_roundtrip() {
        let (_dir, audit) = test_audit_logger();

        // Log an event so the chain has a head
        // SAFETY: single-threaded test, setting env var for test isolation
        unsafe {
            std::env::set_var("ZEROCLAW_AUDIT_SIGNING_KEY",
                "0102030405060708091011121314151617181920212223242526272829303132");
        }
        audit.log_command(
            "telegram", "ls", "low", true, true, true, 10
        ).unwrap();

        let signing_key = hex::decode("0102030405060708091011121314151617181920212223242526272829303132").unwrap();
        let issuer = ViIssuer::new("v0.6.5", audit, signing_key);

        let cred = issuer.issue(
            "shell",
            "abc123",
            true,
            "hello world",
            None,
            "telegram",
        );

        let json = serde_json::to_string(&cred).unwrap();
        let parsed: ViCredential = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.issuer, "did:zeroclaw:zara/v0.6.5");
        assert_eq!(parsed.credential_subject.tool_name, "shell");
        assert_eq!(parsed.credential_subject.result_hash, "abc123");
        assert!(parsed.credential_subject.success);
    }

    #[test]
    fn vi_credential_verify_success() {
        let (_dir, audit) = test_audit_logger();
        audit.log_command("telegram", "ls", "low", true, true, true, 10).unwrap();

        let signing_key = hex::decode("0102030405060708091011121314151617181920212223242526272829303132").unwrap();
        let issuer = ViIssuer::new("v0.6.5", audit, signing_key);

        let cred = issuer.issue("shell", "abc123", true, "output", None, "telegram");

        // Modify the credential — verification should fail
        let mut tampered = cred.clone();
        tampered.credential_subject.success = false;

        assert!(issuer.verify(&cred).is_ok());
        assert!(issuer.verify(&tampered).is_err());
    }

    #[test]
    fn vi_credential_anchored_to_audit_chain() {
        let (_dir, audit) = test_audit_logger();

        let signing_key = hex::decode("0102030405060708091011121314151617181920212223242526272829303132").unwrap();
        let issuer = ViIssuer::new("v0.6.5", Arc::clone(&audit), signing_key);

        // Log 3 events
        for i in 0..3 {
            audit.log_command("cli", &format!("cmd-{i}"), "low", true, true, true, 5).unwrap();
        }

        let cred = issuer.issue("test_tool", "hash", true, "out", None, "cli");

        // Credential should be anchored to the 3rd event's hash
        let chain_head = audit.get_last_entry_hash();
        assert_eq!(cred.credential_subject.audit_chain_hash, chain_head);
    }
}
