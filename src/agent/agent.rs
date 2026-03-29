use crate::agent::dispatcher::{
    NativeToolDispatcher, ParsedToolCall, ToolDispatcher, ToolExecutionResult, XmlToolDispatcher,
};
use crate::agent::memory_loader::{DefaultMemoryLoader, MemoryLoader};
use crate::agent::prompt::{PromptContext, SystemPromptBuilder};
use crate::agent::reflection::ReflectionEngine;
use crate::agent::tool_search::SemanticToolSearch;
use crate::config::Config;
use crate::i18n::ToolDescriptions;
use crate::memory::{self, Memory};
use crate::memory::embeddings::EmbeddingProvider;
use crate::observability::{self, Observer};
use crate::providers::{self, ChatMessage, ChatRequest, ConversationMessage, Provider, ToolResultMessage};
use crate::runtime;
use crate::security::SecurityPolicy;
use crate::tools::{self, Tool, ToolSpec};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

/// Events emitted during a streamed agent turn.
#[derive(Debug, Clone)]
pub enum TurnEvent {
    Chunk { delta: String },
    Thinking { delta: String },
    ToolCall {
        name: String,
        args: serde_json::Value,
    },
    ToolResult { name: String, output: String },
}

pub struct Agent {
    provider: Arc<dyn Provider>,
    tools: Vec<Box<dyn Tool>>,
    tool_specs: Vec<ToolSpec>,
    memory: Arc<dyn Memory>,
    observer: Arc<dyn Observer>,
    prompt_builder: SystemPromptBuilder,
    tool_dispatcher: Box<dyn ToolDispatcher>,
    memory_loader: Box<dyn MemoryLoader>,
    config: crate::config::AgentConfig,
    model_name: String,
    temperature: f64,
    workspace_dir: std::path::PathBuf,
    identity_config: crate::config::IdentityConfig,
    skills: Vec<crate::skills::Skill>,
    skills_prompt_mode: crate::config::SkillsPromptInjectionMode,
    auto_save: bool,
    memory_session_id: Option<String>,
    history: Vec<ConversationMessage>,
    classification_config: crate::config::QueryClassificationConfig,
    available_hints: Vec<String>,
    route_model_by_hint: HashMap<String, String>,
    allowed_tools: Option<Vec<String>>,
    response_cache: Option<Arc<crate::memory::response_cache::ResponseCache>>,
    tool_descriptions: Option<ToolDescriptions>,
    security_summary: Option<String>,
    autonomy_level: crate::security::AutonomyLevel,
    activated_tools: Option<Arc<std::sync::Mutex<crate::tools::ActivatedToolSet>>>,
    tool_search: Option<SemanticToolSearch>,
    reflection_engine: Option<ReflectionEngine>,
}

pub struct AgentBuilder {
    provider: Option<Arc<dyn Provider>>,
    tools: Option<Vec<Box<dyn Tool>>>,
    memory: Option<Arc<dyn Memory>>,
    observer: Option<Arc<dyn Observer>>,
    prompt_builder: Option<SystemPromptBuilder>,
    tool_dispatcher: Option<Box<dyn ToolDispatcher>>,
    memory_loader: Option<Box<dyn MemoryLoader>>,
    config: Option<crate::config::AgentConfig>,
    model_name: Option<String>,
    temperature: Option<f64>,
    workspace_dir: Option<std::path::PathBuf>,
    identity_config: Option<crate::config::IdentityConfig>,
    skills: Option<Vec<crate::skills::Skill>>,
    skills_prompt_mode: Option<crate::config::SkillsPromptInjectionMode>,
    auto_save: Option<bool>,
    memory_session_id: Option<String>,
    classification_config: Option<crate::config::QueryClassificationConfig>,
    available_hints: Option<Vec<String>>,
    route_model_by_hint: Option<HashMap<String, String>>,
    allowed_tools: Option<Vec<String>>,
    response_cache: Option<Arc<crate::memory::response_cache::ResponseCache>>,
    tool_descriptions: Option<ToolDescriptions>,
    security_summary: Option<String>,
    autonomy_level: Option<crate::security::AutonomyLevel>,
    activated_tools: Option<Arc<std::sync::Mutex<crate::tools::ActivatedToolSet>>>,
    tool_search: Option<SemanticToolSearch>,
    reflection_engine: Option<ReflectionEngine>,
}

impl AgentBuilder {
    pub fn new() -> Self {
        Self {
            provider: None,
            tools: None,
            memory: None,
            observer: None,
            prompt_builder: None,
            tool_dispatcher: None,
            memory_loader: None,
            config: None,
            model_name: None,
            temperature: None,
            workspace_dir: None,
            identity_config: None,
            skills: None,
            skills_prompt_mode: None,
            auto_save: None,
            memory_session_id: None,
            classification_config: None,
            available_hints: None,
            route_model_by_hint: None,
            allowed_tools: None,
            response_cache: None,
            tool_descriptions: None,
            security_summary: None,
            autonomy_level: None,
            activated_tools: None,
            tool_search: None,
            reflection_engine: None,
        }
    }

    pub fn provider(mut self, provider: Arc<dyn Provider>) -> Self {
        self.provider = Some(provider);
        self
    }

    pub fn tools(mut self, tools: Vec<Box<dyn Tool>>) -> Self {
        self.tools = Some(tools);
        self
    }

    pub fn memory(mut self, memory: Arc<dyn Memory>) -> Self {
        self.memory = Some(memory);
        self
    }

    pub fn observer(mut self, observer: Arc<dyn Observer>) -> Self {
        self.observer = Some(observer);
        self
    }

    pub fn prompt_builder(mut self, prompt_builder: SystemPromptBuilder) -> Self {
        self.prompt_builder = Some(prompt_builder);
        self
    }

    pub fn tool_dispatcher(mut self, tool_dispatcher: Box<dyn ToolDispatcher>) -> Self {
        self.tool_dispatcher = Some(tool_dispatcher);
        self
    }

    pub fn memory_loader(mut self, memory_loader: Box<dyn MemoryLoader>) -> Self {
        self.memory_loader = Some(memory_loader);
        self
    }

    pub fn config(mut self, config: crate::config::AgentConfig) -> Self {
        self.config = Some(config);
        self
    }

    pub fn model_name(mut self, model_name: String) -> Self {
        self.model_name = Some(model_name);
        self
    }

    pub fn temperature(mut self, temperature: f64) -> Self {
        self.temperature = Some(temperature);
        self
    }

    pub fn workspace_dir(mut self, workspace_dir: std::path::PathBuf) -> Self {
        self.workspace_dir = Some(workspace_dir);
        self
    }

    pub fn identity_config(mut self, identity_config: crate::config::IdentityConfig) -> Self {
        self.identity_config = Some(identity_config);
        self
    }

    pub fn skills(mut self, skills: Vec<crate::skills::Skill>) -> Self {
        self.skills = Some(skills);
        self
    }

    pub fn skills_prompt_mode(
        mut self,
        skills_prompt_mode: crate::config::SkillsPromptInjectionMode,
    ) -> Self {
        self.skills_prompt_mode = Some(skills_prompt_mode);
        self
    }

    pub fn auto_save(mut self, auto_save: bool) -> Self {
        self.auto_save = Some(auto_save);
        self
    }

    pub fn memory_session_id(mut self, memory_session_id: Option<String>) -> Self {
        self.memory_session_id = memory_session_id;
        self
    }

    pub fn classification_config(
        mut self,
        classification_config: crate::config::QueryClassificationConfig,
    ) -> Self {
        self.classification_config = Some(classification_config);
        self
    }

    pub fn available_hints(mut self, available_hints: Vec<String>) -> Self {
        self.available_hints = Some(available_hints);
        self
    }

    pub fn route_model_by_hint(mut self, route_model_by_hint: HashMap<String, String>) -> Self {
        self.route_model_by_hint = Some(route_model_by_hint);
        self
    }

    pub fn allowed_tools(mut self, allowed_tools: Option<Vec<String>>) -> Self {
        self.allowed_tools = allowed_tools;
        self
    }

    pub fn response_cache(
        mut self,
        cache: Option<Arc<crate::memory::response_cache::ResponseCache>>,
    ) -> Self {
        self.response_cache = cache;
        self
    }

    pub fn tool_descriptions(mut self, tool_descriptions: Option<ToolDescriptions>) -> Self {
        self.tool_descriptions = tool_descriptions;
        self
    }

    pub fn security_summary(mut self, summary: Option<String>) -> Self {
        self.security_summary = summary;
        self
    }

    pub fn autonomy_level(mut self, level: crate::security::AutonomyLevel) -> Self {
        self.autonomy_level = Some(level);
        self
    }

    pub fn activated_tools(
        mut self,
        activated: Option<Arc<std::sync::Mutex<tools::ActivatedToolSet>>>,
    ) -> Self {
        self.activated_tools = activated;
        self
    }

    pub fn tool_search(mut self, tool_search: SemanticToolSearch) -> Self {
        self.tool_search = Some(tool_search);
        self
    }

    pub fn reflection_engine(mut self, reflection_engine: ReflectionEngine) -> Self {
        self.reflection_engine = Some(reflection_engine);
        self
    }

    pub fn build(self) -> Result<Agent> {
        let mut tools = self
            .tools
            .ok_or_else(|| anyhow::anyhow!("tools are required"))?;

        let allowed_tools = self.allowed_tools;
        let tool_specs: Vec<ToolSpec> = tools
            .iter()
            .filter(|t| {
                if let Some(ref allowed) = allowed_tools {
                    allowed.contains(&t.name().to_string())
                } else {
                    true
                }
            })
            .map(|t| t.spec())
            .collect();

        if let Some(ref allowed) = allowed_tools {
            tools.retain(|t| allowed.contains(&t.name().to_string()));
        }

        Ok(Agent {
            provider: self
                .provider
                .ok_or_else(|| anyhow::anyhow!("provider is required"))?,
            tools,
            tool_specs,
            memory: self
                .memory
                .ok_or_else(|| anyhow::anyhow!("memory is required"))?,
            observer: self
                .observer
                .ok_or_else(|| anyhow::anyhow!("observer is required"))?,
            prompt_builder: self
                .prompt_builder
                .unwrap_or_else(SystemPromptBuilder::with_defaults),
            tool_dispatcher: self
                .tool_dispatcher
                .ok_or_else(|| anyhow::anyhow!("tool_dispatcher is required"))?,
            memory_loader: self
                .memory_loader
                .unwrap_or_else(|| Box::new(DefaultMemoryLoader::default())),
            config: self.config.unwrap_or_default(),
            model_name: self
                .model_name
                .ok_or_else(|| anyhow::anyhow!("model_name is required"))?,
            temperature: self.temperature.unwrap_or(0.7),
            workspace_dir: self
                .workspace_dir
                .unwrap_or_else(|| std::path::PathBuf::from(".")),
            identity_config: self.identity_config.unwrap_or_default(),
            skills: self.skills.unwrap_or_default(),
            skills_prompt_mode: self
                .skills_prompt_mode
                .unwrap_or(crate::config::SkillsPromptInjectionMode::Full),
            auto_save: self.auto_save.unwrap_or(false),
            memory_session_id: self.memory_session_id,
            history: Vec::new(),
            classification_config: self.classification_config.unwrap_or_default(),
            available_hints: self.available_hints.unwrap_or_default(),
            route_model_by_hint: self.route_model_by_hint.unwrap_or_default(),
            allowed_tools,
            response_cache: self.response_cache,
            tool_descriptions: self.tool_descriptions,
            security_summary: self.security_summary,
            autonomy_level: self
                .autonomy_level
                .unwrap_or(crate::security::AutonomyLevel::Supervised),
            activated_tools: self.activated_tools,
            tool_search: self.tool_search,
            reflection_engine: self.reflection_engine,
        })
    }
}

impl Agent {
    pub fn builder() -> AgentBuilder {
        AgentBuilder::new()
    }

    pub async fn from_config(config: &Config) -> Result<Self> {
        let observer: Arc<dyn Observer> = if config.observability.backend != "none" {
            Arc::from(observability::create_observer(&config.observability))
        } else {
            Arc::from(observability::NoopObserver {})
        };

        let memory: Arc<dyn Memory> = Arc::from(crate::memory::create_memory(
            &config.memory,
            &config.workspace_dir,
            config.api_key.as_deref(),
        )?);

        let response_cache = if config.memory.hygiene_enabled {
            Some(Arc::new(crate::memory::response_cache::ResponseCache::new(
                &config.workspace_dir,
                1440,
                1000,
            )?))
        } else {
            None
        };

        let provider_name = config.default_provider.as_deref().unwrap_or("openrouter");
        let provider = providers::create_provider(provider_name, config.api_key.as_deref())?;
        let provider_arc: Arc<dyn Provider> = Arc::from(provider);
        let model_name = config
            .default_model
            .clone()
            .unwrap_or_else(|| "anthropic/claude-3-7-sonnet".into());

        let security = SecurityPolicy::from_config(&config.autonomy, &config.workspace_dir);
        let runtime = Arc::from(runtime::NativeRuntime::new());

        let (
            tools,
            _delegate_handle,
            _reaction_handle,
            _channel_map_handle,
            _ask_user_handle,
            _escalate_handle,
        ) = tools::all_tools_with_runtime(
            Arc::new(config.clone()),
            &Arc::new(security.clone()),
            runtime,
            memory.clone(),
            config.api_key.as_deref(),
            None,
            &config.browser,
            &config.http_request,
            &config.web_fetch,
            &config.workspace_dir,
            &config.agents,
            config.api_key.as_deref(),
            config,
            None,
            Some(provider_arc.clone()),
            Some(model_name.clone()),
        );

        let mut available_hints = Vec::new();
        let mut route_model_by_hint = HashMap::new();
        for route in &config.model_routes {
            available_hints.push(route.hint.clone());
            route_model_by_hint.insert(route.hint.clone(), route.model.clone());
        }

        let tool_dispatcher: Box<dyn ToolDispatcher> = if provider_arc.supports_native_tools() {
            Box::new(NativeToolDispatcher)
        } else {
            Box::new(XmlToolDispatcher)
        };

        let mut activated_tools: Option<Arc<std::sync::Mutex<tools::ActivatedToolSet>>> = None;
        if config.mcp.deferred_loading {
            activated_tools = Some(Arc::new(std::sync::Mutex::new(
                tools::ActivatedToolSet::new(),
            )));
        }

        // --- Phase I: Potenciación (Search & Reflection) ---
        let resolved_embedding = memory::resolve_embedding_config(
            &config.memory,
            &config.embedding_routes,
            config.api_key.as_deref(),
        );
        let embedding_provider: Arc<dyn EmbeddingProvider> =
            Arc::from(memory::embeddings::create_embedding_provider(
                &resolved_embedding.provider,
                resolved_embedding.api_key.as_deref(),
                &resolved_embedding.model,
                resolved_embedding.dimensions,
            ));

        let mut tool_search =
            SemanticToolSearch::new(if resolved_embedding.provider == "none" {
                None
            } else {
                Some(embedding_provider.clone())
            });

        let _ = tool_search.index_tools(&tools).await;

        let reflection_engine =
            ReflectionEngine::new(provider_arc.clone(), model_name.clone());

        Agent::builder()
            .provider(provider_arc)
            .tools(tools)
            .memory(memory)
            .observer(observer)
            .response_cache(response_cache)
            .tool_dispatcher(tool_dispatcher)
            .memory_loader(Box::new(DefaultMemoryLoader::new(
                5,
                config.memory.min_relevance_score,
            )))
            .prompt_builder(SystemPromptBuilder::with_defaults())
            .config(config.agent.clone())
            .model_name(model_name)
            .temperature(config.default_temperature)
            .workspace_dir(config.workspace_dir.clone())
            .classification_config(config.query_classification.clone())
            .available_hints(available_hints)
            .route_model_by_hint(route_model_by_hint)
            .identity_config(config.identity.clone())
            .skills(crate::skills::load_skills_with_config(
                &config.workspace_dir,
                config,
            ))
            .skills_prompt_mode(config.skills.prompt_injection_mode)
            .auto_save(config.memory.auto_save)
            .security_summary(Some(security.prompt_summary()))
            .autonomy_level(config.autonomy.level)
            .activated_tools(activated_tools)
            .tool_search(tool_search)
            .reflection_engine(reflection_engine)
            .build()
    }

    pub fn history(&self) -> &[ConversationMessage] {
        &self.history
    }

    pub fn seed_history(&mut self, messages: Vec<ConversationMessage>) {
        self.history = messages;
    }

    pub async fn reflect(&self) -> Result<String> {
        if let Some(ref engine) = self.reflection_engine {
            let history = self
                .history
                .iter()
                .filter_map(|msg| match msg {
                    ConversationMessage::Chat(m) => Some(m.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();

            engine
                .reflect(&history, &self.memory, self.memory_session_id.as_deref())
                .await
        } else {
            Ok("Reflection engine not configured.".into())
        }
    }

    fn build_system_prompt(&self) -> Result<String> {
        self.build_system_prompt_filtered(None)
    }

    fn build_system_prompt_filtered(&self, allowed_tool_names: Option<&[String]>) -> Result<String> {
        let tools: Vec<&dyn Tool> = if let Some(names) = allowed_tool_names {
            self.tools
                .iter()
                .filter(|t| names.contains(&t.name().to_string()))
                .map(|t| t.as_ref())
                .collect()
        } else {
            self.tools.iter().map(|t| t.as_ref()).collect()
        };

        let instructions = self.tool_dispatcher.prompt_instructions(&self.tools);
        let ctx = PromptContext {
            workspace_dir: &self.workspace_dir,
            model_name: &self.model_name,
            tools,
            skills: &self.skills,
            skills_prompt_mode: self.skills_prompt_mode,
            identity_config: Some(&self.identity_config),
            dispatcher_instructions: &instructions,
            tool_descriptions: self.tool_descriptions.as_ref(),
            security_summary: self.security_summary.clone(),
            autonomy_level: self.autonomy_level,
        };
        self.prompt_builder.build(&ctx)
    }

    pub async fn turn(&mut self, user_message: &str) -> Result<String> {
        let allowed_tool_names = if let Some(ref search) = self.tool_search {
            search.search(user_message, 20).await.ok()
        } else {
            None
        };

        if self.history.is_empty() {
            let system_prompt = self.build_system_prompt_filtered(allowed_tool_names.as_deref())?;
            self.history
                .push(ConversationMessage::Chat(ChatMessage::system(system_prompt)));
        }

        let context = self
            .memory_loader
            .load_context(self.memory.as_ref(), user_message, self.memory_session_id.as_deref())
            .await?;

        self.history
            .push(ConversationMessage::Chat(ChatMessage::user(format!(
                "{}\n\nContext:\n{}",
                user_message, context
            ))));

        for _ in 0..self.config.max_tool_iterations {
            let messages = self.tool_dispatcher.to_provider_messages(&self.history);

            let effective_model = if let Some(decision) =
                crate::agent::classifier::classify_with_decision(
                    &self.classification_config,
                    user_message,
                ) {
                self.route_model_by_hint
                    .get(&decision.hint)
                    .cloned()
                    .unwrap_or_else(|| self.model_name.clone())
            } else {
                self.model_name.clone()
            };

            let response = self
                .provider
                .chat(
                    ChatRequest {
                        messages: &messages,
                        tools: if self.tool_dispatcher.should_send_tool_specs() {
                            Some(&self.tool_specs)
                        } else {
                            None
                        },
                    },
                    &effective_model,
                    self.temperature,
                )
                .await?;

            let (text, calls) = self.tool_dispatcher.parse_response(&response);
            if calls.is_empty() {
                let final_text = if text.is_empty() {
                    response.text.unwrap_or_default()
                } else {
                    text
                };

                self.history
                    .push(ConversationMessage::Chat(ChatMessage::assistant(
                        final_text.clone(),
                    )));
                self.trim_history();
                let _ = self.reflect().await;
                return Ok(final_text);
            }

            self.history.push(ConversationMessage::AssistantToolCalls {
                text: if text.is_empty() { None } else { Some(text) },
                tool_calls: response.tool_calls.clone(),
                reasoning_content: response.reasoning_content.clone(),
            });

            let results = self.execute_tools(&calls).await;
            let formatted = self.tool_dispatcher.format_results(&results);
            self.history.push(formatted);
            self.trim_history();
        }

        anyhow::bail!("Exceeded max tool iterations")
    }

    pub async fn turn_streamed(
        &mut self,
        user_message: &str,
        event_tx: tokio::sync::mpsc::Sender<TurnEvent>,
    ) -> Result<String> {
        let allowed_tool_names = if let Some(ref search) = self.tool_search {
            search.search(user_message, 20).await.ok()
        } else {
            None
        };

        if self.history.is_empty() {
            let system_prompt = self.build_system_prompt_filtered(allowed_tool_names.as_deref())?;
            self.history
                .push(ConversationMessage::Chat(ChatMessage::system(system_prompt)));
        }

        let context = self
            .memory_loader
            .load_context(self.memory.as_ref(), user_message, self.memory_session_id.as_deref())
            .await?;

        self.history
            .push(ConversationMessage::Chat(ChatMessage::user(format!(
                "{}\n\nContext:\n{}",
                user_message, context
            ))));

        for _ in 0..self.config.max_tool_iterations {
            let messages = self.tool_dispatcher.to_provider_messages(&self.history);

            let response = self
                .provider
                .chat(
                    ChatRequest {
                        messages: &messages,
                        tools: if self.tool_dispatcher.should_send_tool_specs() {
                            Some(&self.tool_specs)
                        } else {
                            None
                        },
                    },
                    &self.model_name,
                    self.temperature,
                )
                .await?;

            let (text, calls) = self.tool_dispatcher.parse_response(&response);
            if calls.is_empty() {
                let final_text = response.text.unwrap_or_default();
                self.history
                    .push(ConversationMessage::Chat(ChatMessage::assistant(
                        final_text.clone(),
                    )));
                self.trim_history();
                let _ = self.reflect().await;
                return Ok(final_text);
            }

            self.history.push(ConversationMessage::AssistantToolCalls {
                text: if text.is_empty() { None } else { Some(text) },
                tool_calls: response.tool_calls.clone(),
                reasoning_content: response.reasoning_content.clone(),
            });

            let results = self.execute_tools(&calls).await;
            for res in &results {
                let _ = event_tx.send(TurnEvent::ToolResult { name: res.name.clone(), output: res.output.clone() }).await;
            }
            let formatted = self.tool_dispatcher.format_results(&results);
            self.history.push(formatted);
            self.trim_history();
        }

        anyhow::bail!("Exceeded max tool iterations")
    }

    async fn execute_tools(&self, calls: &[ParsedToolCall]) -> Vec<ToolExecutionResult> {
        let mut results = Vec::new();
        for call in calls {
            let res = self.execute_tool_call(call).await;
            results.push(res);
        }
        results
    }

    async fn execute_tool_call(&self, call: &ParsedToolCall) -> ToolExecutionResult {
        let tool = self.tools.iter().find(|t| t.name() == call.name);
        
        let (output, success) = if let Some(t) = tool {
            match t.execute(call.arguments.clone()).await {
                Ok(res) => (res.output, res.success),
                Err(e) => (format!("Error: {e}"), false),
            }
        } else {
            (format!("Tool {} not found", call.name), false)
        };

        ToolExecutionResult {
            name: call.name.clone(),
            output,
            success,
            tool_call_id: call.tool_call_id.clone(),
        }
    }

    fn trim_history(&mut self) {
        let max = self.config.max_history_messages;
        if self.history.len() > max {
            self.history.drain(0..(self.history.len() - max));
        }
    }

    pub fn set_memory_session_id(&mut self, session_id: Option<String>) {
        self.memory_session_id = session_id;
    }
}

pub async fn run(
    _config: Config,
    _message: Option<String>,
    _provider_override: Option<String>,
    _model_override: Option<String>,
    _temperature: f64,
    _tools_override: Vec<String>,
    _stream: bool,
    _tx: Option<tokio::sync::mpsc::Sender<TurnEvent>>,
    _session_id: Option<String>,
) -> Result<String> {
    Ok(String::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use parking_lot::Mutex;

    struct MockProvider {
        responses: Mutex<Vec<crate::providers::ChatResponse>>,
    }

    #[async_trait]
    impl Provider for MockProvider {
        async fn chat(&self, _r: ChatRequest<'_>, _m: &str, _t: f64) -> Result<crate::providers::ChatResponse> {
            let mut guard = self.responses.lock();
            if guard.is_empty() {
                Ok(crate::providers::ChatResponse { text: Some("ok".into()), tool_calls: vec![], usage: None, reasoning_content: None })
            } else {
                Ok(guard.remove(0))
            }
        }
        async fn chat_with_system(&self, _s: Option<&str>, _m: &str, _mo: &str, _t: f64) -> Result<String> { Ok("ok".into()) }
    }

    struct MockTool;
    #[async_trait]
    impl Tool for MockTool {
        fn name(&self) -> &str { "echo" }
        fn description(&self) -> &str { "echo" }
        fn parameters_schema(&self) -> serde_json::Value { serde_json::json!({}) }
        async fn execute(&self, _a: serde_json::Value) -> Result<crate::tools::ToolResult> {
            Ok(crate::tools::ToolResult { success: true, output: "ok".into(), error: None })
        }
    }

    #[tokio::test]
    async fn test_agent_basic() {
        let provider = Arc::new(MockProvider { responses: Mutex::new(vec![]) });
        let memory_cfg = crate::config::MemoryConfig::default();
        let mem = Arc::from(crate::memory::create_memory(&memory_cfg, std::path::Path::new("/tmp"), None).unwrap());
        let observer = Arc::from(crate::observability::NoopObserver {});
        
        let mut agent = Agent::builder()
            .provider(provider)
            .tools(vec![Box::new(MockTool)])
            .memory(mem)
            .observer(observer)
            .tool_dispatcher(Box::new(NativeToolDispatcher))
            .workspace_dir(std::path::PathBuf::from("/tmp"))
            .model_name("test".into())
            .memory_loader(Box::new(DefaultMemoryLoader::default()))
            .build()
            .unwrap();

        let resp = agent.turn("hello").await.unwrap();
        assert_eq!(resp, "ok");
    }
}
