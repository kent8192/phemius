//! Strict OpenRouter streaming client with no provider fallback or implicit retry.

use std::{collections::BTreeMap, fmt, time::Duration};

use eventsource_stream::Eventsource;
use futures_util::StreamExt;
use reqwest::{Client, redirect::Policy};
use serde_json::{Value, json};

use crate::cost::Usage;
use crate::model::{
    ModelFailure, ModelMessage, ModelRequest, ModelResponse, ModelResult, ToolCall,
};

const OPENROUTER_COMPLETIONS_URL: &str = "https://openrouter.ai/api/v1/chat/completions";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Trusted OpenRouter configuration. API keys are only loaded by this client.
pub struct OpenRouterConfig {
    endpoint: String,
}

impl OpenRouterConfig {
    /// Builds the production endpoint policy without reading credentials.
    pub fn production() -> Self {
        Self {
            endpoint: OPENROUTER_COMPLETIONS_URL.into(),
        }
    }

    fn for_test(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }
}

impl fmt::Debug for OpenRouterConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenRouterConfig")
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

/// A pooled OpenRouter client. It never stores credentials in request debug output.
#[derive(Clone)]
pub struct OpenRouterClient {
    client: Client,
    config: std::sync::Arc<OpenRouterConfig>,
    credentials: CredentialSource,
}

#[derive(Clone)]
enum CredentialSource {
    Environment,
    TestOnly(String),
}

impl CredentialSource {
    fn authorization(&self) -> ModelResult<String> {
        let api_key = match self {
            Self::Environment => std::env::var("OPENROUTER_API_KEY")
                .map_err(|_| ModelFailure::stopped("OPENROUTER_API_KEY is not configured"))?,
            Self::TestOnly(api_key) => api_key.clone(),
        };
        if api_key.is_empty() {
            return Err(ModelFailure::stopped("OPENROUTER_API_KEY is empty"));
        }
        Ok(format!("Bearer {api_key}"))
    }
}

impl OpenRouterClient {
    /// Builds the network client that reads its trusted environment key at send time.
    pub fn from_environment() -> ModelResult<Self> {
        Self::with_credentials(
            OpenRouterConfig::production(),
            CredentialSource::Environment,
        )
    }

    /// Builds one pooled, no-retry production client.
    pub fn new(config: OpenRouterConfig) -> ModelResult<Self> {
        Self::with_credentials(config, CredentialSource::Environment)
    }

    fn with_credentials(
        config: OpenRouterConfig,
        credentials: CredentialSource,
    ) -> ModelResult<Self> {
        let client = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .map_err(|error| {
                ModelFailure::stopped(format!("failed to build OpenRouter client: {error}"))
            })?;
        Ok(Self {
            client,
            config: std::sync::Arc::new(config),
            credentials,
        })
    }

    /// Builds a local/mock-only client for integration tests.
    #[doc(hidden)]
    pub fn for_test(endpoint: impl Into<String>, api_key: impl Into<String>) -> ModelResult<Self> {
        Self::with_credentials(
            OpenRouterConfig::for_test(endpoint),
            CredentialSource::TestOnly(api_key.into()),
        )
    }

    /// Builds a local/mock-only endpoint client that retains no production credential.
    #[doc(hidden)]
    pub fn for_test_with_environment(endpoint: impl Into<String>) -> ModelResult<Self> {
        Self::with_credentials(
            OpenRouterConfig::for_test(endpoint),
            CredentialSource::Environment,
        )
    }

    /// Streams, aggregates, and validates exactly one OpenRouter completion.
    pub async fn complete(&self, request: ModelRequest) -> ModelResult<ModelResponse> {
        if request.model.trim().is_empty() {
            return Err(ModelFailure::stopped("model ID is empty"));
        }
        if request.messages.is_empty() {
            return Err(ModelFailure::stopped("model request has no messages"));
        }
        let request_body = request_body(&request);
        let authorization = self.credentials.authorization()?;
        let response = self
            .client
            .post(&self.config.endpoint)
            .header("Authorization", authorization)
            .header("HTTP-Referer", "https://github.com/kent8192/phemius")
            .header("X-Title", "Phemius")
            .json(&request_body)
            .send()
            .await
            .map_err(|error| {
                ModelFailure::ambiguous(format!("OpenRouter transport failure: {error}"))
            })?;
        if !response.status().is_success() {
            return Err(ModelFailure::stopped(format!(
                "OpenRouter returned HTTP {}",
                response.status()
            )));
        }

        let mut accumulator = SseAccumulator::default();
        let mut events = response.bytes_stream().eventsource();
        while let Some(event) = events.next().await {
            let event = event.map_err(|error| {
                ModelFailure::stopped(format!("malformed OpenRouter SSE stream: {error}"))
            })?;
            accumulator.feed(&event.event, &event.data)?;
            if accumulator.done {
                break;
            }
        }
        let response = accumulator.finish()?;
        request.validate_tool_calls(&response.tool_calls)?;
        Ok(response)
    }
}

impl fmt::Debug for OpenRouterClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenRouterClient")
            .finish_non_exhaustive()
    }
}

/// Parses complete SSE text into one strict model response.
pub fn parse_sse_events(events: impl AsRef<str>) -> ModelResult<ModelResponse> {
    let mut accumulator = SseAccumulator::default();
    let mut event = String::new();
    let mut data: Vec<String> = Vec::new();
    for line in events.as_ref().lines() {
        if line.is_empty() {
            if !data.is_empty() || !event.is_empty() {
                accumulator.feed(&event, &data.join("\n"))?;
                event.clear();
                data.clear();
            }
            continue;
        }
        if let Some(value) = line.strip_prefix("event:") {
            event = value.trim_start().into();
        } else if let Some(value) = line.strip_prefix("data:") {
            data.push(value.trim_start().into());
        } else if !line.starts_with(':') {
            return Err(ModelFailure::stopped("malformed SSE field"));
        }
    }
    if !data.is_empty() || !event.is_empty() {
        accumulator.feed(&event, &data.join("\n"))?;
    }
    accumulator.finish()
}

fn request_body(request: &ModelRequest) -> Value {
    json!({
        "model": request.model,
        "messages": request.messages.iter().map(message_body).collect::<Vec<_>>(),
        "tools": request.tools.iter().map(tool_body).collect::<Vec<_>>(),
        "stream": true,
        "provider": {
            "allow_fallbacks": false,
            "require_parameters": true,
        },
        "plugins": [{
            "id": "context-compression",
            "enabled": false,
        }],
    })
}

fn message_body(message: &ModelMessage) -> Value {
    json!({"role": message.role, "content": message.content})
}

fn tool_body(tool: &crate::model::ToolDefinition) -> Value {
    json!({
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.input_schema,
        },
    })
}

#[derive(Default)]
struct SseAccumulator {
    choices: BTreeMap<usize, ChoiceAccumulator>,
    usage: Option<Usage>,
    done: bool,
}

#[derive(Default)]
struct ChoiceAccumulator {
    text: String,
    tools: BTreeMap<usize, ToolAccumulator>,
}

#[derive(Default)]
struct ToolAccumulator {
    id: Option<String>,
    name: Option<String>,
    arguments: String,
}

impl SseAccumulator {
    fn feed(&mut self, event: &str, data: &str) -> ModelResult<()> {
        if self.done {
            return Err(ModelFailure::stopped("received SSE data after [DONE]"));
        }
        if event == "error" {
            return Err(ModelFailure::stopped("OpenRouter sent an SSE error event"));
        }
        if data == "[DONE]" {
            self.done = true;
            return Ok(());
        }
        let payload: Value = serde_json::from_str(data)
            .map_err(|_| ModelFailure::stopped("malformed OpenRouter SSE payload"))?;
        if let Some(usage) = payload.get("usage") {
            self.usage = Some(parse_usage(usage)?);
        }
        let choices = payload
            .get("choices")
            .and_then(Value::as_array)
            .ok_or_else(|| ModelFailure::stopped("OpenRouter SSE payload has no choices"))?;
        if choices.is_empty() && self.usage.is_none() {
            return Err(ModelFailure::stopped(
                "OpenRouter SSE payload has empty choices",
            ));
        }
        for choice in choices {
            let choice = choice
                .as_object()
                .ok_or_else(|| ModelFailure::stopped("OpenRouter choice is not an object"))?;
            let index = choice
                .get("index")
                .and_then(Value::as_u64)
                .ok_or_else(|| ModelFailure::stopped("OpenRouter choice has no index"))?
                .try_into()
                .map_err(|_| ModelFailure::stopped("OpenRouter choice index is too large"))?;
            let delta = choice
                .get("delta")
                .and_then(Value::as_object)
                .ok_or_else(|| ModelFailure::stopped("OpenRouter choice has no delta"))?;
            let target = self.choices.entry(index).or_default();
            if let Some(content) = delta.get("content").filter(|content| !content.is_null()) {
                let content = content
                    .as_str()
                    .ok_or_else(|| ModelFailure::stopped("OpenRouter content delta is not text"))?;
                target.text.push_str(content);
            }
            if let Some(calls) = delta.get("tool_calls") {
                for call in calls.as_array().ok_or_else(|| {
                    ModelFailure::stopped("OpenRouter tool_calls delta is not an array")
                })? {
                    let call = call.as_object().ok_or_else(|| {
                        ModelFailure::stopped("OpenRouter tool call is not an object")
                    })?;
                    let tool_index = call
                        .get("index")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| ModelFailure::stopped("OpenRouter tool call has no index"))?
                        .try_into()
                        .map_err(|_| ModelFailure::stopped("OpenRouter tool index is too large"))?;
                    let tool = target.tools.entry(tool_index).or_default();
                    if let Some(id) = call.get("id") {
                        tool.id = Some(
                            id.as_str()
                                .ok_or_else(|| {
                                    ModelFailure::stopped("OpenRouter tool call ID is not text")
                                })?
                                .into(),
                        );
                    }
                    if let Some(function) = call.get("function") {
                        let function = function.as_object().ok_or_else(|| {
                            ModelFailure::stopped("OpenRouter function delta is not an object")
                        })?;
                        if let Some(name) = function.get("name") {
                            tool.name.get_or_insert_with(String::new).push_str(
                                name.as_str().ok_or_else(|| {
                                    ModelFailure::stopped("OpenRouter tool name is not text")
                                })?,
                            );
                        }
                        if let Some(arguments) = function.get("arguments") {
                            tool.arguments.push_str(arguments.as_str().ok_or_else(|| {
                                ModelFailure::stopped("OpenRouter tool arguments are not text")
                            })?);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn finish(self) -> ModelResult<ModelResponse> {
        if !self.done {
            return Err(ModelFailure::ambiguous(
                "OpenRouter stream ended before [DONE]",
            ));
        }
        let choice = self
            .choices
            .get(&0)
            .ok_or_else(|| ModelFailure::stopped("OpenRouter completion has no choice zero"))?;
        let tool_calls = choice
            .tools
            .values()
            .map(|call| {
                let name = call
                    .name
                    .clone()
                    .ok_or_else(|| ModelFailure::stopped("OpenRouter tool call has no name"))?;
                let arguments = serde_json::from_str(&call.arguments).map_err(|_| {
                    ModelFailure::stopped("OpenRouter tool call arguments are invalid JSON")
                })?;
                Ok(ToolCall {
                    id: call.id.clone(),
                    name,
                    arguments,
                })
            })
            .collect::<ModelResult<Vec<_>>>()?;
        if choice.text.is_empty() && tool_calls.is_empty() {
            return Err(ModelFailure::stopped("OpenRouter completion is empty"));
        }
        Ok(ModelResponse {
            text: choice.text.clone(),
            tool_calls,
            usage: self.usage,
        })
    }
}

fn parse_usage(value: &Value) -> ModelResult<Usage> {
    let object = value
        .as_object()
        .ok_or_else(|| ModelFailure::stopped("OpenRouter usage is not an object"))?;
    let input_tokens = object
        .get("prompt_tokens")
        .or_else(|| object.get("input_tokens"))
        .and_then(Value::as_u64)
        .ok_or_else(|| ModelFailure::stopped("OpenRouter usage has no input token count"))?;
    let output_tokens = object
        .get("completion_tokens")
        .or_else(|| object.get("output_tokens"))
        .and_then(Value::as_u64)
        .ok_or_else(|| ModelFailure::stopped("OpenRouter usage has no output token count"))?;
    Ok(Usage::new(input_tokens, output_tokens))
}
