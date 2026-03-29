use async_trait::async_trait;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::hooks::traits::HookHandler;
use crate::security::audit::{AuditLogger, CommandExecutionLog};
use crate::tools::compute_result_hash;
use crate::tools::traits::ToolResult;

/// Logs tool calls for auditing.
///
/// Logs to both:
/// - A volatile in-memory log (for runtime inspection)
/// - The persistent Merkle-hash chained audit log (via `AuditLogger`)
pub struct CommandLoggerHook {
    log: Arc<Mutex<Vec<String>>>,
    /// Shared audit logger — allows VI issuer to share the same chain state.
    audit: Option<Arc<AuditLogger>>,
    channel: String,
}

impl CommandLoggerHook {
    /// Create a new hook with optional audit logging.
    ///
    /// `zeroclaw_dir` is the ZeroClaw config directory (typically `~/.zeroclaw`).
    /// `channel` is the messaging channel name (e.g. "cli", "telegram").
    pub fn new(
        audit_config: crate::config::AuditConfig,
        zeroclaw_dir: std::path::PathBuf,
        channel: String,
    ) -> Self {
        let audit = AuditLogger::new(audit_config, zeroclaw_dir)
            .ok()
            .map(Arc::new);
        Self {
            log: Arc::new(Mutex::new(Vec::new())),
            audit,
            channel,
        }
    }

    /// Create a hook with a pre-built shared audit logger.
    ///
    /// Use this when you need to share the same `AuditLogger` instance with
    /// other components (e.g. `ViIssuer`).
    pub fn with_logger(logger: Arc<AuditLogger>, channel: String) -> Self {
        Self {
            log: Arc::new(Mutex::new(Vec::new())),
            audit: Some(logger),
            channel,
        }
    }

    /// Returns a reference to the shared audit logger, if one is configured.
    pub fn audit_logger(&self) -> Option<&Arc<AuditLogger>> {
        self.audit.as_ref()
    }

    #[cfg(test)]
    pub fn entries(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

impl Default for CommandLoggerHook {
    fn default() -> Self {
        Self {
            log: Arc::new(Mutex::new(Vec::new())),
            audit: None,
            channel: "cli".to_string(),
        }
    }
}

#[async_trait]
impl HookHandler for CommandLoggerHook {
    fn name(&self) -> &str {
        "command-logger"
    }

    fn priority(&self) -> i32 {
        -50
    }

    async fn on_after_tool_call(&self, tool: &str, result: &ToolResult, duration: Duration) {
        let entry = format!(
            "[{}] {} ({}ms) success={}",
            chrono::Utc::now().format("%H:%M:%S"),
            tool,
            duration.as_millis(),
            result.success,
        );
        tracing::info!(hook = "command-logger", "{}", entry);
        self.log.lock().unwrap().push(entry);

        // Log to the persistent Merkle audit trail
        if let Some(ref audit) = self.audit {
            let result_hash =
                compute_result_hash(result.success, &result.output, result.error.as_deref());
            let log_entry = CommandExecutionLog {
                channel: &self.channel,
                command: tool,
                risk_level: "medium", // TODO: pull from SecurityPolicy per-tool risk assessment
                approved: true,       // already approved before execution
                allowed: true,        // already allowed by policy
                success: result.success,
                duration_ms: duration.as_millis() as u64,
            };
            if let Err(e) = audit.log_command_event(log_entry) {
                tracing::warn!(hook = "command-logger", "audit log failed: {e}");
            }
            // Also log the result_hash for closed-loop verification
            tracing::debug!(hook = "command-logger", tool, result_hash, "tool execution logged");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn logs_tool_calls() {
        // Default hook has no audit logger configured (audit is optional)
        let hook = CommandLoggerHook::default();
        let result = ToolResult {
            success: true,
            output: "ok".into(),
            error: None,
        };
        hook.on_after_tool_call("shell", &result, Duration::from_millis(42))
            .await;
        let entries = hook.entries();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].contains("shell"));
        assert!(entries[0].contains("42ms"));
        assert!(entries[0].contains("success=true"));
    }
}
