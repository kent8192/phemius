//! Concrete model request, response, and deterministic evaluation types.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use regex::Regex;
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
#[derive(Debug)]
pub struct ScriptedModel {
    responses: VecDeque<ModelResult<ModelResponse>>,
    shared_responses: Option<Arc<Mutex<VecDeque<ModelResult<ModelResponse>>>>>,
}

impl Clone for ScriptedModel {
    fn clone(&self) -> Self {
        self.shared_clone()
    }
}

impl ScriptedModel {
    /// Creates a backend that consumes responses in order.
    pub fn new(responses: impl IntoIterator<Item = ModelResult<ModelResponse>>) -> Self {
        Self {
            responses: VecDeque::new(),
            shared_responses: Some(Arc::new(Mutex::new(responses.into_iter().collect()))),
        }
    }

    /// Creates a scripted backend whose clones consume one shared response queue.
    ///
    /// This mode is intended for bounded concurrent workflow tests: each critic clone observes
    /// the next deterministic response instead of replaying a private queue from its first item.
    pub fn shared(responses: impl IntoIterator<Item = ModelResult<ModelResponse>>) -> Self {
        Self {
            responses: VecDeque::new(),
            shared_responses: Some(Arc::new(Mutex::new(responses.into_iter().collect()))),
        }
    }

    /// Returns a clone that consumes the same deterministic queue as its siblings.
    pub fn shared_clone(&self) -> Self {
        if let Some(shared_responses) = &self.shared_responses {
            return Self {
                responses: VecDeque::new(),
                shared_responses: Some(Arc::clone(shared_responses)),
            };
        }
        Self::shared(self.responses.iter().cloned())
    }

    fn complete(&mut self, request: &ModelRequest) -> ModelResult<ModelResponse> {
        let response = if let Some(responses) = &self.shared_responses {
            responses
                .lock()
                .map_err(|_| ModelFailure::stopped("scripted response queue is poisoned"))?
                .pop_front()
                .ok_or_else(|| {
                    ModelFailure::stopped("scripted model has no remaining response")
                })??
        } else {
            self.responses.pop_front().ok_or_else(|| {
                ModelFailure::stopped("scripted model has no remaining response")
            })??
        };
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

    /// Clones a backend for bounded parallel work without replaying scripted responses.
    pub fn parallel_clone(&self) -> Self {
        match self {
            Self::OpenRouter(client) => Self::OpenRouter(client.clone()),
            Self::Scripted(client) => Self::Scripted(client.shared_clone()),
        }
    }
}

fn validates_schema(schema: &Value, value: &Value) -> bool {
    schema_is_supported(schema) && validates_supported_schema(schema, value)
}

fn schema_is_supported(schema: &Value) -> bool {
    let Value::Object(schema) = schema else {
        return schema.is_boolean();
    };
    schema.keys().all(|key| {
        matches!(
            key.as_str(),
            "$id"
                | "$schema"
                | "additionalProperties"
                | "allOf"
                | "anyOf"
                | "const"
                | "default"
                | "deprecated"
                | "description"
                | "enum"
                | "examples"
                | "exclusiveMaximum"
                | "exclusiveMinimum"
                | "maxItems"
                | "maxLength"
                | "maxProperties"
                | "maximum"
                | "minItems"
                | "minLength"
                | "minProperties"
                | "minimum"
                | "pattern"
                | "properties"
                | "readOnly"
                | "required"
                | "title"
                | "type"
                | "items"
        )
    }) && schema_values_are_supported(schema)
}

fn schema_values_are_supported(schema: &serde_json::Map<String, Value>) -> bool {
    if !schema.get("$id").is_none_or(Value::is_string)
        || !schema.get("$schema").is_none_or(Value::is_string)
        || !schema.get("title").is_none_or(Value::is_string)
        || !schema.get("description").is_none_or(Value::is_string)
        || !schema.get("deprecated").is_none_or(Value::is_boolean)
        || !schema.get("readOnly").is_none_or(Value::is_boolean)
        || !valid_type(schema.get("type"))
        || !valid_enum(schema.get("enum"))
        || !valid_nonnegative_integer(schema.get("minLength"))
        || !valid_nonnegative_integer(schema.get("maxLength"))
        || !schema.get("pattern").is_none_or(|pattern| {
            pattern
                .as_str()
                .is_some_and(|pattern| Regex::new(pattern).is_ok())
        })
        || !valid_nonnegative_integer(schema.get("minItems"))
        || !valid_nonnegative_integer(schema.get("maxItems"))
        || !valid_nonnegative_integer(schema.get("minProperties"))
        || !valid_nonnegative_integer(schema.get("maxProperties"))
        || !valid_number(schema.get("minimum"))
        || !valid_number(schema.get("maximum"))
        || !valid_number(schema.get("exclusiveMinimum"))
        || !valid_number(schema.get("exclusiveMaximum"))
        || !valid_required(schema.get("required"))
    {
        return false;
    }
    if let Some(properties) = schema.get("properties") {
        let Some(properties) = properties.as_object() else {
            return false;
        };
        if !properties.values().all(schema_is_supported) {
            return false;
        }
    }
    if let Some(items) = schema.get("items")
        && !schema_is_supported(items)
    {
        return false;
    }
    if let Some(additional) = schema.get("additionalProperties")
        && !additional.is_boolean()
        && !schema_is_supported(additional)
    {
        return false;
    }
    ["allOf", "anyOf"].into_iter().all(|key| {
        schema.get(key).is_none_or(|schemas| {
            schemas.as_array().is_some_and(|schemas| {
                !schemas.is_empty() && schemas.iter().all(schema_is_supported)
            })
        })
    })
}

fn valid_type(expected: Option<&Value>) -> bool {
    expected.is_none_or(|expected| match expected {
        Value::String(expected) => valid_type_name(expected),
        Value::Array(expected) => {
            !expected.is_empty()
                && expected
                    .iter()
                    .filter_map(Value::as_str)
                    .all(valid_type_name)
                && expected.iter().all(Value::is_string)
        }
        _ => false,
    })
}

fn valid_type_name(expected: &str) -> bool {
    matches!(
        expected,
        "object" | "array" | "boolean" | "integer" | "number" | "null" | "string"
    )
}

fn valid_enum(values: Option<&Value>) -> bool {
    values.is_none_or(|values| values.as_array().is_some_and(|values| !values.is_empty()))
}

fn valid_nonnegative_integer(value: Option<&Value>) -> bool {
    value.is_none_or(|value| {
        value
            .as_u64()
            .is_some_and(|value| usize::try_from(value).is_ok())
    })
}

fn valid_number(value: Option<&Value>) -> bool {
    value.is_none_or(|value| safe_f64(value).is_some())
}

fn valid_required(required: Option<&Value>) -> bool {
    required.is_none_or(|required| {
        required
            .as_array()
            .is_some_and(|required| required.iter().all(Value::is_string))
    })
}

fn validates_supported_schema(schema: &Value, value: &Value) -> bool {
    let Value::Object(schema) = schema else {
        return schema == &Value::Bool(true);
    };
    if !matches_type(schema.get("type"), value)
        || !matches_enum(schema.get("enum"), value)
        || !matches_const(schema.get("const"), value)
        || !matches_all_of(schema.get("allOf"), value)
        || !matches_any_of(schema.get("anyOf"), value)
    {
        return false;
    }
    validates_string(schema, value)
        && validates_array(schema, value)
        && validates_number(schema, value)
        && validates_object(schema, value)
}

fn matches_type(expected: Option<&Value>, value: &Value) -> bool {
    expected.is_none_or(|expected| match expected {
        Value::String(expected) => matches_single_type(expected, value),
        Value::Array(expected) => {
            !expected.is_empty()
                && expected.iter().all(Value::is_string)
                && expected
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|expected| matches_single_type(expected, value))
        }
        _ => false,
    })
}

fn matches_single_type(expected: &str, value: &Value) -> bool {
    match expected {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "boolean" => value.is_boolean(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "number" => value.is_number(),
        "null" => value.is_null(),
        "string" => value.is_string(),
        _ => false,
    }
}

fn matches_enum(values: Option<&Value>, value: &Value) -> bool {
    values.is_none_or(|values| {
        values
            .as_array()
            .is_some_and(|values| !values.is_empty() && values.contains(value))
    })
}

fn matches_const(expected: Option<&Value>, value: &Value) -> bool {
    expected.is_none_or(|expected| expected == value)
}

fn matches_all_of(schemas: Option<&Value>, value: &Value) -> bool {
    schemas.is_none_or(|schemas| {
        schemas
            .as_array()
            .is_some_and(|schemas| schemas.iter().all(|schema| validates_schema(schema, value)))
    })
}

fn matches_any_of(schemas: Option<&Value>, value: &Value) -> bool {
    schemas.is_none_or(|schemas| {
        schemas
            .as_array()
            .is_some_and(|schemas| schemas.iter().any(|schema| validates_schema(schema, value)))
    })
}

fn validates_string(schema: &serde_json::Map<String, Value>, value: &Value) -> bool {
    let Some(value) = value.as_str() else {
        return true;
    };
    let length = value.chars().count();
    minimum(schema.get("minLength"), length)
        && maximum(schema.get("maxLength"), length)
        && schema.get("pattern").is_none_or(|pattern| {
            pattern
                .as_str()
                .is_some_and(|pattern| Regex::new(pattern).is_ok_and(|regex| regex.is_match(value)))
        })
}

fn validates_array(schema: &serde_json::Map<String, Value>, value: &Value) -> bool {
    let Some(values) = value.as_array() else {
        return true;
    };
    minimum(schema.get("minItems"), values.len())
        && maximum(schema.get("maxItems"), values.len())
        && schema
            .get("items")
            .is_none_or(|items| values.iter().all(|value| validates_schema(items, value)))
}

fn validates_number(schema: &serde_json::Map<String, Value>, value: &Value) -> bool {
    let Some(value) = safe_f64(value) else {
        return !value.is_number();
    };
    inclusive_bound(schema.get("minimum"), value, f64::ge)
        && inclusive_bound(schema.get("maximum"), value, f64::le)
        && exclusive_bound(schema.get("exclusiveMinimum"), value, f64::gt)
        && exclusive_bound(schema.get("exclusiveMaximum"), value, f64::lt)
}

fn safe_f64(value: &Value) -> Option<f64> {
    let number = value.as_number()?;
    if number
        .as_i64()
        .is_some_and(|value| value.unsigned_abs() > (1_u64 << 53))
        || number.as_u64().is_some_and(|value| value > (1_u64 << 53))
    {
        return None;
    }
    number.as_f64()
}

fn inclusive_bound(bound: Option<&Value>, value: f64, compare: fn(&f64, &f64) -> bool) -> bool {
    bound.is_none_or(|bound| safe_f64(bound).is_some_and(|bound| compare(&value, &bound)))
}

fn exclusive_bound(bound: Option<&Value>, value: f64, compare: fn(&f64, &f64) -> bool) -> bool {
    bound.is_none_or(|bound| safe_f64(bound).is_some_and(|bound| compare(&value, &bound)))
}

fn validates_object(schema: &serde_json::Map<String, Value>, value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return true;
    };
    let properties = schema.get("properties").and_then(Value::as_object);
    if !minimum(schema.get("minProperties"), object.len())
        || !maximum(schema.get("maxProperties"), object.len())
        || !required_properties_present(schema.get("required"), object)
    {
        return false;
    }
    object.iter().all(|(name, value)| {
        match properties.and_then(|properties| properties.get(name)) {
            Some(property) => validates_schema(property, value),
            None => schema
                .get("additionalProperties")
                .map_or(true, |additional| validates_schema(additional, value)),
        }
    })
}

fn required_properties_present(
    required: Option<&Value>,
    object: &serde_json::Map<String, Value>,
) -> bool {
    required.is_none_or(|required| {
        required.as_array().is_some_and(|required| {
            required
                .iter()
                .all(|name| name.as_str().is_some_and(|name| object.contains_key(name)))
        })
    })
}

fn minimum(bound: Option<&Value>, value: usize) -> bool {
    bound.is_none_or(|bound| {
        bound
            .as_u64()
            .and_then(|bound| usize::try_from(bound).ok())
            .is_some_and(|bound| value >= bound)
    })
}

fn maximum(bound: Option<&Value>, value: usize) -> bool {
    bound.is_none_or(|bound| {
        bound
            .as_u64()
            .and_then(|bound| usize::try_from(bound).ok())
            .is_some_and(|bound| value <= bound)
    })
}
