//! VI Credential issuance hook.
//!
//! Issues W3C VC-style credentials after each successful tool execution,
//! anchored to the audit Merkle chain. Credentials are stored in memory
//! and can be retrieved via the `credentials()` method.

use async_trait::async_trait;
use std::sync::{Arc, RwLock};

use crate::agent::vi_issuer::{ViCredential, ViIssuer};
use crate::hooks::traits::HookHandler;
use crate::security::audit::AuditLogger;
use crate::tools::traits::ToolResult;
use std::time::Duration;

/// Hook that issues VI credentials after tool executions.
pub struct ViCredentialHook {
    issuer: ViIssuer,
    /// In-memory credential store (subject to memory pressure; persist if needed).
    credentials: RwLock<Vec<ViCredential>>,
}

impl ViCredentialHook {
    /// Create a new VI credential hook.
    ///
    /// `version` — ZeroClaw version string (e.g. "v0.6.5").
    /// `audit` — the shared `AuditLogger` instance (must be the same one used
    ///   by `CommandLoggerHook` to ensure credential proofs reference the correct
    ///   audit chain head).
    /// `signing_key` — 32-byte HMAC key for signing credentials.
    ///   Must match `ZEROCLAW_AUDIT_SIGNING_KEY` used by the audit logger.
    pub fn new(version: &str, audit: Arc<AuditLogger>, signing_key: Vec<u8>) -> Self {
        Self {
            issuer: ViIssuer::new(version, audit, signing_key),
            credentials: RwLock::new(Vec::new()),
        }
    }

    /// Returns all issued credentials (oldest first).
    pub fn credentials(&self) -> Vec<ViCredential> {
        self.credentials.read().unwrap().clone()
    }

    /// Returns the most recently issued credential, if any.
    pub fn last_credential(&self) -> Option<ViCredential> {
        self.credentials.read().unwrap().last().cloned()
    }
}

#[async_trait]
impl HookHandler for ViCredentialHook {
    fn name(&self) -> &str {
        "vi-credential"
    }

    fn priority(&self) -> i32 {
        50 // Run after CommandLoggerHook (-50) so audit entry is already written
    }

    async fn on_after_tool_call(
        &self,
        tool: &str,
        result: &ToolResult,
        _duration: Duration,
    ) {
        // Issue credential for both successful and failed executions
        let result_hash = crate::tools::compute_result_hash(
            result.success,
            &result.output,
            result.error.as_deref(),
        );

        let cred = self.issuer.issue(
            tool,
            &result_hash,
            result.success,
            &result.output,
            result.error.as_deref(),
            "channel", // channel info not available here; hook doesn't know it
        );

        tracing::debug!(
            credential_id = %cred.id,
            tool,
            success = result.success,
            "VI credential issued"
        );

        self.credentials.write().unwrap().push(cred);
    }
}
