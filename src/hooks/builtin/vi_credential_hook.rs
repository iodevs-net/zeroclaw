//! VI Credential issuance hook.
//!
//! Issues W3C VC-style credentials after each tool execution,
//! anchored to the audit Merkle chain. Credentials are persisted
//! to a SQLite store for off-chain verification.

use async_trait::async_trait;
use std::sync::Arc;

use crate::agent::vi_issuer::{ViCredential, ViCredentialStore, ViIssuer};
use crate::hooks::traits::HookHandler;
use crate::security::audit::AuditLogger;
use crate::tools::traits::ToolResult;
use std::time::Duration;

/// Hook that issues and persists VI credentials after tool executions.
pub struct ViCredentialHook {
    issuer: ViIssuer,
    store: Arc<ViCredentialStore>,
    /// Channel name injected at construction time.
    channel: String,
}

impl ViCredentialHook {
    /// Create a new VI credential hook with a persistent store.
    ///
    /// `version` — ZeroClaw version string (e.g. "v0.6.5").
    /// `audit` — shared `AuditLogger` (must be same instance as `CommandLoggerHook`).
    /// `signing_key` — 32-byte HMAC key for signing credentials.
    /// `store` — persistent SQLite credential store.
    /// `channel` — channel name for this hook instance.
    pub fn new(
        version: &str,
        audit: Arc<AuditLogger>,
        signing_key: Vec<u8>,
        store: Arc<ViCredentialStore>,
        channel: String,
    ) -> Self {
        Self {
            issuer: ViIssuer::new(version, audit, signing_key),
            store,
            channel,
        }
    }

    /// Returns the credential store (useful for gateway verification endpoint).
    pub fn store(&self) -> &Arc<ViCredentialStore> {
        &self.store
    }

    /// Returns the most recently issued credential, if any.
    pub fn last_credential(&self) -> Option<ViCredential> {
        self.store.list_recent(1).ok().and_then(|v| v.into_iter().next())
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
            &self.channel,
        );

        // Persist to SQLite
        if let Err(e) = self.store.save(&cred) {
            tracing::error!(hook = "vi-credential", credential_id = %cred.id, "failed to persist credential: {e}");
            return;
        }

        tracing::debug!(
            hook = "vi-credential",
            credential_id = %cred.id,
            tool,
            success = result.success,
            "VI credential persisted"
        );
    }
}
