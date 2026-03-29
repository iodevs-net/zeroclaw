//! Semantic tool search for agentic tool selection.
//!
//! This module provides a mechanism to index tools by their descriptions
//! and retrieve the most relevant ones based on a natural language query.
//! It supports both keyword-based search and vector-based semantic search
//! using an [`EmbeddingProvider`].

use crate::memory::embeddings::EmbeddingProvider;
use crate::tools::Tool;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;

/// A searchable index of tools.
pub struct SemanticToolSearch {
    embedding_provider: Option<Arc<dyn EmbeddingProvider>>,
    /// Map of tool name to its embedding vector.
    embeddings: HashMap<String, Vec<f32>>,
    /// Map of tool name to its description (for keyword fallback).
    descriptions: HashMap<String, String>,
}

impl SemanticToolSearch {
    /// Create a new search index with an optional embedding provider.
    pub fn new(embedding_provider: Option<Arc<dyn EmbeddingProvider>>) -> Self {
        Self {
            embedding_provider,
            embeddings: HashMap::new(),
            descriptions: HashMap::new(),
        }
    }

    /// Index a set of tools.
    ///
    /// If an embedding provider is available, it will generate embeddings
    /// for all tool descriptions.
    pub async fn index_tools(&mut self, tools: &[Box<dyn Tool>]) -> Result<()> {
        let mut to_embed = Vec::new();
        let mut names = Vec::new();

        for tool in tools {
            let name = tool.name().to_string();
            let desc = tool.description().to_string();
            self.descriptions.insert(name.clone(), desc.clone());

            if self.embedding_provider.is_some() {
                to_embed.push(desc);
                names.push(name);
            }
        }

        if let Some(ref provider) = self.embedding_provider {
            if !to_embed.is_empty() {
                // Batch embed to save API calls/latency
                let texts: Vec<&str> = to_embed.iter().map(|s| s.as_str()).collect();
                let vectors = provider.embed(&texts).await?;
                for (name, vec) in names.into_iter().zip(vectors.into_iter()) {
                    self.embeddings.insert(name, vec);
                }
            }
        }

        Ok(())
    }

    /// Search for tools relevant to the query.
    ///
    /// Returns a list of tool names sorted by relevance.
    pub async fn search(&self, query: &str, limit: usize) -> Result<Vec<String>> {
        if let Some(ref provider) = self.embedding_provider {
            if !self.embeddings.is_empty() {
                return self.search_semantic(provider.as_ref(), query, limit).await;
            }
        }

        Ok(self.search_keyword(query, limit))
    }

    async fn search_semantic(
        &self,
        provider: &dyn EmbeddingProvider,
        query: &str,
        limit: usize,
    ) -> Result<Vec<String>> {
        let query_vec = provider.embed_one(query).await?;
        let mut scores: Vec<(String, f32)> = Vec::new();

        for (name, tool_vec) in &self.embeddings {
            let score = cosine_similarity(&query_vec, tool_vec);
            scores.push((name.clone(), score));
        }

        // Sort by score descending
        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        
        Ok(scores.into_iter().take(limit).map(|(name, _)| name).collect())
    }

    fn search_keyword(&self, query: &str, limit: usize) -> Vec<String> {
        let query_lower = query.to_lowercase();
        let query_words: Vec<&str> = query_lower.split_whitespace().collect();
        
        let mut scores: Vec<(String, f32)> = Vec::new();

        for (name, desc) in &self.descriptions {
            let mut score = 0.0;
            let desc_lower = desc.to_lowercase();
            let name_lower = name.to_lowercase();

            for word in &query_words {
                if name_lower.contains(word) {
                    score += 2.0;
                }
                if desc_lower.contains(word) {
                    score += 1.0;
                }
            }

            if score > 0.0 {
                scores.push((name.clone(), score));
            }
        }

        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scores.into_iter().take(limit).map(|(name, _)| name).collect()
    }
}

fn cosine_similarity(v1: &[f32], v2: &[f32]) -> f32 {
    if v1.len() != v2.len() || v1.is_empty() {
        return 0.0;
    }
    let dot_product: f32 = v1.iter().zip(v2.iter()).map(|(a, b)| a * b).sum();
    let norm1: f32 = v1.iter().map(|a| a * a).sum::<f32>().sqrt();
    let norm2: f32 = v2.iter().map(|a| a * a).sum::<f32>().sqrt();
    
    if norm1 == 0.0 || norm2 == 0.0 {
        return 0.0;
    }
    dot_product / (norm1 * norm2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::traits::{Tool, ToolResult};
    use async_trait::async_trait;

    struct MockTool(&'static str, &'static str);
    #[async_trait]
    impl Tool for MockTool {
        fn name(&self) -> &str { self.0 }
        fn description(&self) -> &str { self.1 }
        fn parameters_schema(&self) -> serde_json::Value { serde_json::json!({}) }
        async fn execute(&self, _a: serde_json::Value) -> Result<ToolResult> {
            Ok(ToolResult { success: true, output: "ok".into(), error: None })
        }
    }

    #[tokio::test]
    async fn keyword_search_works() {
        let mut search = SemanticToolSearch::new(None);
        let tools: Vec<Box<dyn Tool>> = vec![
            Box::new(MockTool("shell", "Execute shell commands")),
            Box::new(MockTool("file_read", "Read content from a file")),
        ];
        search.index_tools(&tools).await.unwrap();

        let results = search.search("execute command", 1).await.unwrap();
        assert_eq!(results, vec!["shell".to_string()]);

        let results = search.search("read file", 1).await.unwrap();
        assert_eq!(results, vec!["file_read".to_string()]);
    }
}
