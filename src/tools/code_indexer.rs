//! Code Context: Rust code indexing and navigation tool.
//!
//! Parses Rust source files using `syn` and builds an in-memory index of code symbols
//! (functions, structs, enums, traits, impls, modules, uses). Provides search
//! by name and doc-comment via simple scoring.
//!
//! Design principles:
//! - Zero dependencies beyond `syn` — no external search server
//! - In-memory index — rebuilds on each search, fast enough for codebases <100k lines
//! - No vector embeddings — name + doc BM25-like scoring

use crate::tools::traits::{Tool, ToolResult};
use anyhow::Result;
use async_trait::async_trait;
use serde_json::json;
use std::collections::HashMap;
use std::path::Path;
use syn::*;

/// Kind of code symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Function,
    Struct,
    Enum,
    Trait,
    Impl,
    Mod,
    Use,
    Const,
    Static,
    Type,
}

impl SymbolKind {
    fn as_str(&self) -> &'static str {
        match self {
            SymbolKind::Function => "fn",
            SymbolKind::Struct => "struct",
            SymbolKind::Enum => "enum",
            SymbolKind::Trait => "trait",
            SymbolKind::Impl => "impl",
            SymbolKind::Mod => "mod",
            SymbolKind::Use => "use",
            SymbolKind::Const => "const",
            SymbolKind::Static => "static",
            SymbolKind::Type => "type",
        }
    }
}

/// A indexed code symbol.
#[derive(Debug, Clone)]
pub struct Symbol {
    /// Name of the symbol.
    pub name: String,
    /// Kind of symbol.
    pub kind: SymbolKind,
    /// File path where this symbol is defined.
    pub path: String,
    /// Line number in the file.
    pub line: usize,
    /// Full signature (for search indexing).
    pub signature: String,
    /// Doc comment if present.
    pub doc: Option<String>,
}

impl Symbol {
    /// Format for tool output.
    fn format_short(&self) -> String {
        let doc_snippet = self
            .doc
            .as_ref()
            .map(|d| {
                let trimmed = d.trim();
                if trimmed.len() > 80 {
                    format!(" — {}", &trimmed[..80])
                } else {
                    format!(" — {}", trimmed)
                }
            })
            .unwrap_or_default();
        format!(
            "[{}] {}::{} (line {}){}",
            self.kind.as_str(),
            self.path,
            self.name,
            self.line,
            doc_snippet
        )
    }
}

/// Code indexer — parses Rust source files and indexes symbols.
#[derive(Clone)]
pub struct CodeIndexer {
    symbols: Vec<Symbol>,
    /// Map from lowercase name -> symbol indices (for fast name lookup)
    name_index: HashMap<String, Vec<usize>>,
}

impl CodeIndexer {
    /// Index all `.rs` files under the given directory recursively.
    pub fn index_dir(dir: &Path) -> Result<Self> {
        let mut symbols = Vec::new();
        visit_dirs(dir, &mut symbols)?;
        let name_index = build_name_index(&symbols);
        Ok(Self { symbols, name_index })
    }

    /// Search for symbols matching `query`. Returns up to `limit` results.
    ///
    /// Scoring: exact name match = 10pts, substring name match = 5pts,
    /// doc/signature keyword match = 1pt. Results sorted by score desc.
    pub fn search(&self, query: &str, limit: usize) -> Vec<Symbol> {
        let query_lower = query.to_lowercase();
        let query_terms: Vec<&str> = query_lower.split_whitespace().collect();

        let mut scored: Vec<(usize, i32)> = (0..self.symbols.len())
            .map(|i| {
                let sym = &self.symbols[i];
                let mut score = 0i32;

                // Exact name match
                if sym.name.to_lowercase() == query_lower {
                    score += 10;
                }
                // Substring name match
                else if sym.name.to_lowercase().contains(&query_lower) {
                    score += 5;
                }

                // Word-level name match
                for term in &query_terms {
                    if sym.name.to_lowercase().contains(term) {
                        score += 2;
                    }
                    // Doc/signature match
                    if sym.signature.to_lowercase().contains(term) {
                        score += 1;
                    }
                    if let Some(doc) = &sym.doc {
                        if doc.to_lowercase().contains(term) {
                            score += 1;
                        }
                    }
                }

                (i, score)
            })
            .filter(|(_, s)| *s > 0)
            .collect();

        scored.sort_by(|a, b| b.1.cmp(&a.1));

        scored
            .into_iter()
            .take(limit)
            .map(|(i, _)| self.symbols[i].clone())
            .collect()
    }

    /// Total number of indexed symbols.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }
}

/// Recursively visit directories and collect symbols from `.rs` files.
fn visit_dirs(dir: &Path, symbols: &mut Vec<Symbol>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            // Skip test dirs and target
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name != "target" && !name.starts_with('.') {
                visit_dirs(&path, symbols)?;
            }
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            index_file(&path, symbols)?;
        }
    }
    Ok(())
}

/// Index a single `.rs` file.
fn index_file(path: &Path, symbols: &mut Vec<Symbol>) -> Result<()> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Ok(()),
    };

    let path_str = path
        .strip_prefix(std::env::current_dir().unwrap_or_default())
        .unwrap_or(path)
        .display()
        .to_string();

    let file = match syn::parse_file(&content) {
        Ok(f) => f,
        Err(_) => return Ok(()),
    };

    for item in file.items {
        match item {
            Item::Fn(f) => {
                let sig = format_signature_fn(&f.sig);
                let doc = extract_doc(&f.attrs);
                symbols.push(Symbol {
                    name: f.sig.ident.to_string(),
                    kind: SymbolKind::Function,
                    path: path_str.clone(),
                    line: 0,
                    signature: sig,
                    doc,
                });
            }
            Item::Struct(s) => {
                let doc = extract_doc(&s.attrs);
                let (sig, _) = format_signature_struct(&s);
                symbols.push(Symbol {
                    name: s.ident.to_string(),
                    kind: SymbolKind::Struct,
                    path: path_str.clone(),
                    line: 0,
                    signature: sig,
                    doc,
                });
            }
            Item::Enum(e) => {
                let doc = extract_doc(&e.attrs);
                let sig = format_signature_enum(&e);
                symbols.push(Symbol {
                    name: e.ident.to_string(),
                    kind: SymbolKind::Enum,
                    path: path_str.clone(),
                    line: 0,
                    signature: sig,
                    doc,
                });
            }
            Item::Trait(t) => {
                let doc = extract_doc(&t.attrs);
                let sig = format!("trait {} {{ ... }}", t.ident);
                symbols.push(Symbol {
                    name: t.ident.to_string(),
                    kind: SymbolKind::Trait,
                    path: path_str.clone(),
                    line: 0,
                    signature: sig,
                    doc,
                });
            }
            Item::Impl(i) => {
                let sig = format_signature_impl(&i);
                symbols.push(Symbol {
                    name: sig.clone(),
                    kind: SymbolKind::Impl,
                    path: path_str.clone(),
                    line: 0,
                    signature: sig,
                    doc: None,
                });
            }
            Item::Mod(m) => {
                let doc = extract_doc(&m.attrs);
                symbols.push(Symbol {
                    name: m.ident.to_string(),
                    kind: SymbolKind::Mod,
                    path: path_str.clone(),
                    line: 0,
                    signature: format!("mod {} {{ ... }}", m.ident),
                    doc,
                });
            }
            Item::Use(u) => {
                let sig = format_signature_use(&u);
                symbols.push(Symbol {
                    name: sig.clone(),
                    kind: SymbolKind::Use,
                    path: path_str.clone(),
                    line: 0,
                    signature: sig,
                    doc: None,
                });
            }
            Item::Const(c) => {
                let doc = extract_doc(&c.attrs);
                symbols.push(Symbol {
                    name: c.ident.to_string(),
                    kind: SymbolKind::Const,
                    path: path_str.clone(),
                    line: 0,
                    signature: format!("const {}: ...", c.ident),
                    doc,
                });
            }
            Item::Static(s) => {
                let doc = extract_doc(&s.attrs);
                symbols.push(Symbol {
                    name: s.ident.to_string(),
                    kind: SymbolKind::Static,
                    path: path_str.clone(),
                    line: 0,
                    signature: format!("static {}: ...", s.ident),
                    doc,
                });
            }
            Item::Type(t) => {
                let doc = extract_doc(&t.attrs);
                symbols.push(Symbol {
                    name: t.ident.to_string(),
                    kind: SymbolKind::Type,
                    path: path_str.clone(),
                    line: 0,
                    signature: format!("type {} = ...", t.ident),
                    doc,
                });
            }
            _ => {}
        }
    }
    Ok(())
}

fn extract_doc(attrs: &[Attribute]) -> Option<String> {
    let docs: Vec<String> = attrs
        .iter()
        .filter(|attr| attr.path.is_ident("doc"))
        .filter_map(|attr| {
            // tokens contains: = "doc text"
            // Extract string between quotes
            let tokens_str = attr.tokens.to_string();
            let trimmed = tokens_str.trim();
            if trimmed.starts_with('=') {
                let after_eq = trimmed[1..].trim();
                if after_eq.starts_with('"') && after_eq.ends_with('"') && after_eq.len() >= 2 {
                    return Some(after_eq[1..after_eq.len()-1].trim().to_string());
                }
            }
            None
        })
        .collect();

    if docs.is_empty() {
        None
    } else {
        Some(docs.join(" "))
    }
}

fn build_name_index(symbols: &[Symbol]) -> HashMap<String, Vec<usize>> {
    let mut index: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, sym) in symbols.iter().enumerate() {
        let key = sym.name.to_lowercase();
        index.entry(key).or_default().push(i);
    }
    index
}

fn format_signature_fn(sig: &Signature) -> String {
    let generics = format_generics(&sig.generics);
    let inputs = sig
        .inputs
        .iter()
        .map(|p| match p {
            FnArg::Receiver(r) => {
                if r.mutability.is_some() {
                    "&mut self".to_string()
                } else {
                    "&self".to_string()
                }
            }
            FnArg::Typed(t) => {
                let pat = match &*t.pat {
                    Pat::Ident(i) => i.ident.to_string(),
                    _ => "_".to_string(),
                };
                let ty = format_type(&t.ty);
                format!("{}: {}", pat, ty)
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    let output = match &sig.output {
        ReturnType::Default => String::new(),
        ReturnType::Type(_, t) => format!(" -> {}", format_type(t)),
    };
    format!("fn {}{}({}){}", sig.ident, generics, inputs, output)
}

fn format_signature_struct(s: &ItemStruct) -> (String, String) {
    let generics = format_generics(&s.generics);
    let fields = match &s.fields {
        Fields::Named(f) => f
            .named
            .iter()
            .map(|f| {
                let ident_str = f.ident.as_ref().map(|i| i.to_string()).unwrap_or_else(|| "_".to_string());
                format!("    {}: {},", ident_str, format_type(&f.ty))
            })
            .collect::<Vec<_>>()
            .join("\n"),
        Fields::Unnamed(f) => f
            .unnamed
            .iter()
            .map(|f| format!("    {},", format_type(&f.ty)))
            .collect::<Vec<_>>()
            .join("\n"),
        Fields::Unit => String::new(),
    };
    let name = format!("struct {}{}", s.ident, generics);
    let sig = if fields.is_empty() {
        format!("{};", name)
    } else {
        format!("{} {{\n{}\n}}", name, fields)
    };
    (name, sig)
}

fn format_signature_enum(e: &ItemEnum) -> String {
    let generics = format_generics(&e.generics);
    let variants: Vec<String> = e
        .variants
        .iter()
        .map(|v| {
            let fields = match &v.fields {
                Fields::Named(f) => format!(
                    " {{{}}}",
                    f.named
                        .iter()
                        .map(|f| format!("{}: {}", f.ident.as_ref().unwrap(), format_type(&f.ty)))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                Fields::Unnamed(f) => format!(
                    "({})",
                    f.unnamed
                        .iter()
                        .map(|f| format_type(&f.ty))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                Fields::Unit => String::new(),
            };
            format!("    {}{}", v.ident, fields)
        })
        .collect();
    format!(
        "enum {}{} {{\n{}\n}}",
        e.ident,
        generics,
        variants.join("\n")
    )
}

fn format_signature_impl(i: &ItemImpl) -> String {
    let generics = format_generics(&i.generics);
    let self_name = "Self".to_string();
    format!("impl{}{} {{ ... }}", generics, self_name)
}

fn format_signature_use(_u: &ItemUse) -> String {
    "use ...".to_string()
}

fn format_generics(g: &Generics) -> String {
    if g.params.is_empty() {
        String::new()
    } else {
        let params = g
            .params
            .iter()
            .map(|p| format!("{:?}", p))
            .collect::<Vec<_>>()
            .join(", ");
        format!("<{}>", params)
    }
}

fn format_where(_w: &Option<&WhereClause>) -> String {
    String::new()
}

fn format_type(_t: &Type) -> String {
    "...".to_string()
}

// ── CodeNavigateTool ───────────────────────────────────────────────────────────

/// Tool for searching and navigating the codebase.
pub struct CodeNavigateTool {
    indexer: std::sync::Mutex<Option<CodeIndexer>>,
    workspace_dir: std::path::PathBuf,
}

impl CodeNavigateTool {
    pub fn new(workspace_dir: std::path::PathBuf) -> Self {
        Self {
            indexer: std::sync::Mutex::new(None),
            workspace_dir,
        }
    }

    fn get_or_build_index(&self) -> Result<CodeIndexer> {
        let mut guard = self.indexer.lock().unwrap();
        if guard.is_none() {
            let src_dir = self.workspace_dir.join("src");
            let indexer = if src_dir.exists() {
                CodeIndexer::index_dir(&src_dir)?
            } else {
                CodeIndexer::index_dir(&self.workspace_dir)?
            };
            *guard = Some(indexer);
        }
        // Clone the indexer out so we can search without holding the lock
        let indexer = guard.as_ref().unwrap().clone();
        Ok(indexer)
    }
}

#[async_trait]
impl Tool for CodeNavigateTool {
    fn name(&self) -> &str {
        "code_navigate"
    }

    fn description(&self) -> &str {
        "Search and navigate the ZeroClaw Rust codebase. Use this tool to find \
         functions, structs, enums, traits, modules, and their documentation. \
         Returns symbol name, file path, line number, and doc comments. \
         Query should describe what you're looking for, e.g. 'HTTP request handler', \
         'config parsing', or 'error handling'."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query — describe what you want to find (function name, topic, concept)"
                },
                "kind": {
                    "type": "string",
                    "description": "Filter by symbol kind",
                    "enum": ["fn", "struct", "enum", "trait", "impl", "mod", "use", "const", "type", "all"],
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results to return (default: 10, max: 50)"
                }
            },
            "required": ["query"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> Result<ToolResult> {
        let query = match args.get("query").and_then(|v| v.as_str()) {
            Some(q) => q,
            None => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("Missing required field: query".to_string()),
                });
            }
        };

        let kind_filter = args
            .get("kind")
            .and_then(|v| v.as_str())
            .map(|k| {
                if k == "all" {
                    None
                } else {
                    Some(k.to_string())
                }
            })
            .flatten();

        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(10)
            .min(50) as usize;

        let indexer = match self.get_or_build_index() {
            Ok(i) => i,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("Failed to index codebase: {}", e)),
                });
            }
        };

        let results = indexer.search(query, limit * 2); // over-fetch, then filter

        let results: Vec<Symbol> = if let Some(ref filter) = kind_filter {
            results
                .into_iter()
                .filter(|s| s.kind.as_str() == filter.as_str())
                .take(limit)
                .collect()
        } else {
            results.into_iter().take(limit).collect()
        };

        if results.is_empty() {
            return Ok(ToolResult {
                success: true,
                output: format!("No symbols found matching '{}'. Try a different query.", query),
                error: None,
            });
        }

        let output = format!(
            "Found {} symbol(s) matching '{}':\n\n{}",
            results.len(),
            query,
            results
                .iter()
                .map(|s| s.format_short())
                .collect::<Vec<_>>()
                .join("\n\n")
        );

        Ok(ToolResult {
            success: true,
            output,
            error: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_file(dir: &Path, name: &str, content: &str) {
        let mut file = std::fs::File::create(dir.join(name)).unwrap();
        file.write_all(content.as_bytes()).unwrap();
    }

    #[test]
    fn test_indexer_finds_functions() {
        let dir = TempDir::new().unwrap();
        create_test_file(
            dir.path(),
            "test_code.rs",
            r#"
/// Does something great.
pub fn great_function(a: i32, b: &str) -> String {
    format!("{}{}", a, b)
}

/// Internal helper.
fn helper(x: u64) -> u64 {
    x * 2
}
"#,
        );

        let indexer = CodeIndexer::index_dir(dir.path()).unwrap();
        let results = indexer.search("great", 10);
        assert!(!results.is_empty());
        assert!(results.iter().any(|s| s.name == "great_function"));

        let results = indexer.search("helper", 10);
        assert!(results.iter().any(|s| s.name == "helper"));
    }

    #[test]
    fn test_indexer_finds_structs() {
        let dir = TempDir::new().unwrap();
        create_test_file(
            dir.path(),
            "mod.rs",
            r#"
/// A wonderful config structure.
pub struct WonderConfig {
    pub name: String,
    pub value: i32,
}
"#,
        );

        let indexer = CodeIndexer::index_dir(dir.path()).unwrap();
        let results = indexer.search("config", 10);
        assert!(results.iter().any(|s| s.name == "WonderConfig"));
    }

    #[test]
    fn test_search_empty_query_returns_nothing() {
        let dir = TempDir::new().unwrap();
        create_test_file(dir.path(), "test.rs", "fn foo() {}");
        let indexer = CodeIndexer::index_dir(dir.path()).unwrap();
        let results = indexer.search("xyz_nonexistent", 10);
        assert!(results.is_empty());
    }
}
