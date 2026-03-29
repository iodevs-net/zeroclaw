//! Tool for synchronizing documentation across multiple languages.
//!
//! This tool detects changes in the base documentation (usually README.md)
//! and uses an LLM to generate updated versions for all supported languages.

use crate::providers::{ChatMessage, ChatRequest, Provider};
use crate::tools::traits::{Tool, ToolResult};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use anyhow::Result;

pub struct DocSyncTool {
    provider: Arc<dyn Provider>,
    model: String,
    workspace_dir: PathBuf,
}

impl DocSyncTool {
    pub fn new(provider: Arc<dyn Provider>, model: String, workspace_dir: PathBuf) -> Self {
        Self {
            provider,
            model,
            workspace_dir,
        }
    }

    async fn translate(&self, content: &str, target_lang: &str) -> Result<String> {
        let system_prompt = format!(
            "You are a professional technical translator. \
             Translate the following Markdown documentation to {}. \
             Maintain the original Markdown structure, links, and code blocks. \
             Do not add any preamble or commentary. Respond only with the translated content.",
            target_lang
        );

        let messages = vec![
            ChatMessage::system(&system_prompt),
            ChatMessage::user(content),
        ];

        let response = self
            .provider
            .chat(
                ChatRequest {
                    messages: &messages,
                    tools: None,
                },
                &self.model,
                0.0,
            )
            .await?;

        Ok(response.text.unwrap_or_default())
    }

    fn get_target_languages(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            ("ar", "Arabic"), ("bn", "Bengali"), ("cs", "Czech"), ("da", "Danish"),
            ("de", "German"), ("el", "Greek"), ("es", "Spanish"), ("fi", "Finnish"),
            ("fr", "French"), ("he", "Hebrew"), ("hi", "Hindi"), ("hu", "Hungarian"),
            ("id", "Indonesian"), ("it", "Italian"), ("ja", "Japanese"), ("ko", "Korean"),
            ("nb", "Norwegian Bokmål"), ("nl", "Dutch"), ("pl", "Polish"), ("pt", "Portuguese"),
            ("ro", "Romanian"), ("ru", "Russian"), ("sv", "Swedish"), ("th", "Thai"),
            ("tl", "Tagalog"), ("tr", "Turkish"), ("uk", "Ukrainian"), ("ur", "Urdu"),
            ("vi", "Vietnamese"), ("zh-CN", "Chinese (Simplified)"),
        ]
    }
}

#[async_trait]
impl Tool for DocSyncTool {
    fn name(&self) -> &str {
        "doc_sync"
    }

    fn description(&self) -> &str {
        "Synchronize README.md translations across 30+ supported languages using AI translation."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "base_file": {
                    "type": "string",
                    "description": "The base file to translate (default: README.md)"
                },
                "languages": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Optional list of language codes to update (e.g. ['es', 'fr']). If omitted, updates all."
                }
            }
        })
    }

    async fn execute(&self, args: serde_json::Value) -> Result<ToolResult> {
        let base_file_name = args
            .get("base_file")
            .and_then(|v| v.as_str())
            .unwrap_or("README.md");
        
        let target_filter = args
            .get("languages")
            .and_then(|v| v.as_array())
            .map(|langs| {
                langs
                    .iter()
                    .filter_map(|l| l.as_str())
                    .collect::<Vec<_>>()
            });

        let base_path = self.workspace_dir.join(base_file_name);
        if !base_path.exists() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Base file not found: {}", base_path.display())),
            });
        }

        let content = tokio::fs::read_to_string(&base_path).await?;
        let mut results = Vec::new();
        let targets = self.get_target_languages();

        for (code, name) in targets {
            if let Some(ref filter) = target_filter {
                if !filter.contains(&code) {
                    continue;
                }
            }

            let target_file_name = if base_file_name == "README.md" {
                format!("README.{}.md", code)
            } else {
                // Handle sub-directory SUMMARY.md etc
                let path = Path::new(base_file_name);
                let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("README");
                format!("{}.{}.md", stem, code)
            };

            let target_path = self.workspace_dir.join(&target_file_name);
            
            // Check if directory exists (for docs/SUMMARY.es.md etc)
            if let Some(parent) = target_path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }

            match self.translate(&content, name).await {
                Ok(translated) => {
                    tokio::fs::write(&target_path, translated).await?;
                    results.push(format!("Updated {}", target_file_name));
                }
                Err(e) => {
                    results.push(format!("Failed to update {}: {}", target_file_name, e));
                }
            }
        }

        Ok(ToolResult {
            success: true,
            output: results.join("\n"),
            error: None,
        })
    }
}
