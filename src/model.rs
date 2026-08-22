//! Concrete model request, response, and deterministic evaluation types.

use std::collections::VecDeque;

use serde_json::{Value, json};

use crate::openrouter::OpenRouterClient;

/// The pinned default OpenRouter model.
pub const DEFAULT_MODEL: &str = "deepseek/deepseek-v4-pro-0813";

/// A failure classification that controls durable session handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelFailureClass {
    /// The call definitively stopped before a valid completion was available.
    Stopped,
    /// The call may have reached the provider, but completion cannot be proven.
    Ambiguous,
}

/// A model failure that never includes request credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelFailure {
    class: ModelFailureClass,
    message: String,
}

impl ModelFailure {
    /// Creates a stopped failure.
    pub fn stopped(message: impl Into<String>) -> Self {
        Self {
            class: ModelFailureClass::Stopped,
            message: message.into(),
        }
    }

    /// Creates an ambiguous failure.
    pub fn ambiguous(message: impl Into<String>) -> Self {
        Self {
            class: ModelFailureClass::Ambiguous,
            message: message.into(),
        }
    }

    /// Returns the durable-handling classification.
    pub fn class(&self) -> ModelFailureClass {
        self.class
    }
}

impl std::fmt::Display for ModelFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ModelFailure {}

/// Result produced by model backends.
pub type ModelResult<T> = std::result::Result<T, ModelFailure>;

/// One chat message sent to the configured model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelMessage {
    /// OpenAI-compatible message role.
    pub role: String,
    /// Plain text content.
    pub content: String,
}

impl ModelMessage {
    /// Builds a user message.
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: "user".into(),
            content: content.into(),
        }
    }
}

/// A named function whose arguments are validated before dispatch.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolDefinition {
    /// Stable function name exposed to the model.
    pub name: String,
    /// Short operator-facing description.
    pub description: String,
    /// JSON Schema-like object contract enforced by this client.
    pub input_schema: Value,
}

impl ToolDefinition {
    /// Creates an object-input tool from its properties and required property names.
    pub fn object(
        name: impl Into<String>,
        description: impl Into<String>,
        properties: Value,
        required: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            input_schema: json!({
                "type": "object",
                "properties": properties,
                "required": required.into_iter().map(Into::into).collect::<Vec<String>>(),
                "additionalProperties": false,
            }),
        }
    }

    fn validates(&self, arguments: &Value) -> bool {
        validates_schema(&self.input_schema, arguments)
    }
}

/// A model request, with per-role and per-session model selection.
#[derive(Clone, Debug, PartialEq)]
pub struct ModelRequest {
    /// Logical runtime role, such as writer or critic.
    pub role: String,
    /// OpenRouter model ID selected for this request.
    pub model: String,
    /// Complete ordered conversation input.
    pub messages: Vec<ModelMessage>,
    /// Functions that may be returned and dispatched after validation.
    pub tools: Vec<ToolDefinition>,
}

impl ModelRequest {
    /// Creates a request using the pinned default model.
    pub fn new(
        role: impl Into<String>,
        messages: Vec<ModelMessage>,
        tools: Vec<ToolDefinition>,
    ) -> Self {
        Self {
            role: role.into(),
            model: DEFAULT_MODEL.into(),
            messages,
            tools,
        }
    }

    /// Replaces the model for this single role/session request.
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    pub(crate) fn validate_tool_calls(&self, calls: &[ToolCall]) -> ModelResult<()> {
        for call in calls {
            let Some(tool) = self.tools.iter().find(|tool| tool.name == call.name) else {
                return Err(ModelFailure::stopped(format!(
                    "model requested unknown tool {}",
                    call.name
                )));
            };
            if !tool.validates(&call.arguments) {
                return Err(ModelFailure::stopped(format!(
                    "model supplied invalid arguments for tool {}",
                    call.name
                )));
            }
        }
        Ok(())
    }
}

/// A fully assembled model tool call. It is not executable until the controller dispatches it.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolCall {
    /// Provider call identifier, retained for the subsequent tool-result message.
    pub id: Option<String>,
    /// Lookup key for the concrete controller dispatcher.
    pub name: String,
    /// Client-validated JSON arguments.
    pub arguments: Value,
}

/// One completed model turn.
#[derive(Clone, Debug, PartialEq)]
pub struct ModelResponse {
    /// Aggregated text content for choice zero.
    pub text: String,
    /// Calls validated by the selected backend before dispatch can occur.
    pub tool_calls: Vec<ToolCall>,
}

/// Deterministic model backend for evaluation and tests only.
#[derive(Clone, Debug)]
pub struct ScriptedModel {
    responses: VecDeque<ModelResult<ModelResponse>>,
}

impl ScriptedModel {
    /// Creates a backend that consumes responses in order.
    pub fn new(responses: impl IntoIterator<Item = ModelResult<ModelResponse>>) -> Self {
        Self {
            responses: responses.into_iter().collect(),
        }
    }

    fn complete(&mut self, request: &ModelRequest) -> ModelResult<ModelResponse> {
        let response = self
            .responses
            .pop_front()
            .ok_or_else(|| ModelFailure::stopped("scripted model has no remaining response"))??;
        request.validate_tool_calls(&response.tool_calls)?;
        Ok(response)
    }
}

/// The two concrete model backends used by Phemius.
#[derive(Clone)]
pub enum ModelBackend {
    /// The only network provider.
    OpenRouter(OpenRouterClient),
    /// Ordered recorded responses for deterministic evaluation.
    Scripted(ScriptedModel),
}

impl ModelBackend {
    /// Completes one request without provider fallback or implicit retry.
    pub async fn complete(&mut self, request: ModelRequest) -> ModelResult<ModelResponse> {
        match self {
            Self::OpenRouter(client) => client.complete(request).await,
            Self::Scripted(client) => client.complete(&request),
        }
    }
}

fn validates_schema(schema: &Value, value: &Value) -> bool {
    if let Some(expected) = schema.get("type").and_then(Value::as_str) {
        let matches = match expected {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "boolean" => value.is_boolean(),
            "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
            "number" => value.is_number(),
            "null" => value.is_null(),
            "string" => value.is_string(),
            _ => false,
        };
        if !matches {
            return false;
        }
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array)
        && !values.contains(value)
    {
        return false;
    }
    let Some(object) = value.as_object() else {
        return true;
    };
    let properties = schema.get("properties").and_then(Value::as_object);
    if schema
        .get("required")
        .and_then(Value::as_array)
        .is_some_and(|required| {
            required
                .iter()
                .filter_map(Value::as_str)
                .any(|name| !object.contains_key(name))
        })
    {
        return false;
    }
    if schema.get("additionalProperties").and_then(Value::as_bool) == Some(false)
        && object
            .keys()
            .any(|name| !properties.is_some_and(|properties| properties.contains_key(name)))
    {
        return false;
    }
    properties.is_none_or(|properties| {
        object.iter().all(|(name, value)| {
            properties
                .get(name)
                .is_none_or(|property_schema| validates_schema(property_schema, value))
        })
    })
}
