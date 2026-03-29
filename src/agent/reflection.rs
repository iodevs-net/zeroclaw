//! Reflection engine for post-task analysis and memory hardening.
//!
//! This module analyzes conversation history to extract lessons learned,
//! architectural insights, and user preferences, which are then stored
//! in the agent's long-term memory.

use crate::memory::{Memory, MemoryCategory};
use crate::providers::{ChatMessage, ChatRequest, Provider};
use anyhow::Result;
use std::sync::Arc;

/// Engine for performing post-task reflection.
pub struct ReflectionEngine {
    provider: Arc<dyn Provider>,
    model: String,
}

impl ReflectionEngine {
    /// Create a new reflection engine.
    pub fn new(provider: Arc<dyn Provider>, model: String) -> Self {
        Self { provider, model }
    }

    /// Analyze the conversation history and extract lessons learned.
    pub async fn reflect(
        &self,
        history: &[ChatMessage],
        memory: &Arc<dyn Memory>,
        session_id: Option<&str>,
    ) -> Result<String> {
        if history.is_empty() {
            return Ok("No history to reflect upon.".into());
        }

        let reflection_prompt = r#"
Analyze the following conversation history between an AI Assistant (Zara Claw) and a User (Leonardo).
Extract "Lessons Learned" regarding:
1. Technical/Architectural insights (Rust patterns, project structure, bugs found).
2. User preferences (coding style, preferred tools, workflow).
3. System "Gotchas" or obstacles encountered and how they were resolved.

Format your response as a concise Markdown summary intended for Zara's MEMORY.md.
Do NOT use emojis. Maintain a Senior Full Stack Orchestrator tone.
If nothing significant was learned, respond with "NO_SIGNIFICANT_LEARNINGS".
"#;

        let mut messages = vec![ChatMessage::system(reflection_prompt)];
        // Add a condensed version of the history to the reflection request
        for msg in history.iter().rev().take(10).rev() {
            messages.push(msg.clone());
        }

        let response = self
            .provider
            .chat(
                ChatRequest {
                    messages: &messages,
                    tools: None,
                },
                &self.model,
                0.0, // deterministic
            )
            .await?;

        let text = response.text.unwrap_or_default();
        if text == "NO_SIGNIFICANT_LEARNINGS" || text.trim().is_empty() {
            return Ok("No significant learnings extracted.".into());
        }

        // Store the reflection in memory
        let key = format!("reflection_{}", chrono::Utc::now().to_rfc3339());
        memory
            .store(&key, &text, MemoryCategory::Core, session_id)
            .await?;

        Ok(text)
    }
}
