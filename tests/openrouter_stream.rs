use std::sync::{Arc, Mutex as StdMutex, MutexGuard};

use phemius::{
    model::{
        DEFAULT_MODEL, ModelBackend, ModelFailureClass, ModelMessage, ModelRequest, ModelResponse,
        ScriptedModel, ToolCall, ToolDefinition,
    },
    openrouter::{OpenRouterClient, parse_sse_events},
};
use rstest::*;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Mutex,
};

#[rstest]
fn assembles_split_text_and_indexed_tool_arguments_until_done() {
    let response = parse_sse_events(fixture_sse_with_split_tool_call()).unwrap();

    assert_eq!(response.text, "first second");
    assert_eq!(response.tool_calls.len(), 1);
    assert_eq!(response.tool_calls[0].name, "read_file");
    assert_eq!(
        response.tool_calls[0].arguments,
        json!({"path":"前提/作品.md"})
    );
}

#[rstest]
fn assembles_split_tool_name_by_index_until_done() {
    let response = parse_sse_events(fixture_sse_with_split_tool_name()).unwrap();

    assert_eq!(response.tool_calls.len(), 1);
    assert_eq!(response.tool_calls[0].name, "read_file");
    assert_eq!(
        response.tool_calls[0].arguments,
        json!({"path":"前提/作品.md"})
    );
}

#[rstest]
fn eof_before_done_is_ambiguous() {
    let error = parse_sse_events(fixture_sse_without_done()).unwrap_err();

    assert_eq!(error.class(), ModelFailureClass::Ambiguous);
}

#[rstest]
#[tokio::test]
async fn request_disables_router_fallback_and_context_compression() {
    let server = RecordingHttpServer::start(fixture_success_sse()).await;
    let client = OpenRouterClient::for_test(server.url(), "test-key").unwrap();

    client.complete(fixture_request()).await.unwrap();

    let json = server.single_json_request().await;
    assert_eq!(json["model"], "deepseek/deepseek-v4-pro-0813");
    assert_eq!(json["stream"], true);
    assert_eq!(json["provider"]["allow_fallbacks"], false);
    assert_eq!(json["provider"]["require_parameters"], true);
    assert_eq!(json["provider"].get("models"), None);
    assert_eq!(json["plugins"][0]["id"], "context-compression");
    assert_eq!(json["plugins"][0]["enabled"], false);
}

#[rstest]
#[tokio::test]
async fn production_client_reads_the_environment_key_at_request_time() {
    let environment = EnvironmentVariable::set("OPENROUTER_API_KEY", "construction-key");
    let server = RecordingHttpServer::start(fixture_success_sse()).await;
    let client = OpenRouterClient::for_test_with_environment(server.url()).unwrap();

    environment.replace("request-key");
    client.complete(fixture_request()).await.unwrap();

    assert_eq!(server.single_authorization().await, "Bearer request-key");
}

#[rstest]
#[tokio::test]
async fn client_rejects_unknown_or_invalid_tool_calls_after_done() {
    let server = RecordingHttpServer::start(
		"data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"read_file\",\"arguments\":\"{}\"}}]}}]}\n\ndata: [DONE]\n\n",
	)
	.await;
    let client = OpenRouterClient::for_test(server.url(), "test-key").unwrap();

    let error = client.complete(fixture_request()).await.unwrap_err();

    assert_eq!(error.class(), ModelFailureClass::Stopped);
}

#[rstest]
fn request_defaults_to_the_pinned_model_and_allows_role_override() {
    let request = fixture_request().with_model("deepseek/custom-session-model");

    assert_eq!(fixture_request().model, DEFAULT_MODEL);
    assert_eq!(request.role, "writer");
    assert_eq!(request.model, "deepseek/custom-session-model");
}

#[rstest]
#[tokio::test]
async fn scripted_backend_consumes_one_validated_response_per_call() {
    let response = ModelResponse {
        text: String::new(),
        tool_calls: vec![ToolCall {
            id: Some("call_1".into()),
            name: "read_file".into(),
            arguments: json!({"path": "前提/作品.md"}),
        }],
    };
    let mut backend = ModelBackend::Scripted(ScriptedModel::new([Ok(response.clone())]));

    assert_eq!(backend.complete(fixture_request()).await.unwrap(), response);
    assert_eq!(
        backend
            .complete(fixture_request())
            .await
            .unwrap_err()
            .class(),
        ModelFailureClass::Stopped
    );
}

#[rstest]
#[tokio::test]
async fn constrained_tool_arguments_reject_invalid_values() {
    let invalid_arguments = [
        json!({"path": "x", "sections": [1]}),
        json!({"path": "前提/作品.md", "sections": []}),
        json!({"path": "前提/作品.md", "sections": [0]}),
        json!({"path": "前提/作品.md", "sections": [1, 2, 3]}),
    ];

    for arguments in invalid_arguments {
        let response = ModelResponse {
            text: String::new(),
            tool_calls: vec![ToolCall {
                id: Some("call_1".into()),
                name: "read_sections".into(),
                arguments,
            }],
        };
        let mut backend = ModelBackend::Scripted(ScriptedModel::new([Ok(response)]));

        assert_eq!(
            backend
                .complete(constrained_request())
                .await
                .unwrap_err()
                .class(),
            ModelFailureClass::Stopped
        );
    }
}

#[rstest]
#[tokio::test]
async fn constrained_tool_arguments_accept_valid_combinator_values() {
    let response = ModelResponse {
        text: String::new(),
        tool_calls: vec![ToolCall {
            id: Some("call_1".into()),
            name: "read_sections".into(),
            arguments: json!({"path": "前提/作品.md", "sections": [1, 2]}),
        }],
    };
    let mut backend = ModelBackend::Scripted(ScriptedModel::new([Ok(response.clone())]));

    assert_eq!(
        backend.complete(constrained_request()).await.unwrap(),
        response
    );
}

#[rstest]
#[tokio::test]
async fn unsupported_tool_schema_constraints_fail_closed() {
    let response = ModelResponse {
        text: String::new(),
        tool_calls: vec![ToolCall {
            id: Some("call_1".into()),
            name: "read_uri".into(),
            arguments: json!({"uri": "https://example.test"}),
        }],
    };
    let request = ModelRequest::new(
        "writer",
        vec![ModelMessage::user("Read a URI.")],
        vec![ToolDefinition {
            name: "read_uri".into(),
            description: "Reads a URI.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"uri": {"type": "string", "format": "uri"}},
                "required": ["uri"],
            }),
        }],
    );
    let mut backend = ModelBackend::Scripted(ScriptedModel::new([Ok(response)]));

    assert_eq!(
        backend.complete(request).await.unwrap_err().class(),
        ModelFailureClass::Stopped
    );
}

fn fixture_request() -> ModelRequest {
    ModelRequest::new(
        "writer",
        vec![ModelMessage::user("Read the source.")],
        vec![ToolDefinition::object(
            "read_file",
            "Reads one source file.",
            json!({"path": {"type": "string"}}),
            ["path"],
        )],
    )
}

fn fixture_success_sse() -> &'static str {
    "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n"
}

fn fixture_sse_with_split_tool_call() -> &'static str {
    "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"first \",\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"read_file\",\"arguments\":\"{\\\"path\\\":\\\"前提/\"}}]}}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"second\",\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"作品.md\\\"}\"}}]}}]}\n\ndata: [DONE]\n\n"
}

fn fixture_sse_with_split_tool_name() -> &'static str {
    "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"read_\",\"arguments\":\"{\\\"path\\\":\\\"前提/作品.md\\\"}\"}}]}}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"file\"}}]}}]}\n\ndata: [DONE]\n\n"
}

fn fixture_sse_without_done() -> &'static str {
    "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"}}]}\n\n"
}

fn constrained_request() -> ModelRequest {
    ModelRequest::new(
        "writer",
        vec![ModelMessage::user("Read constrained source sections.")],
        vec![ToolDefinition {
            name: "read_sections".into(),
            description: "Reads bounded source sections.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "minLength": 4, "pattern": "^前提/"},
                    "sections": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 2,
                        "items": {
                            "allOf": [{"type": "integer", "minimum": 1}, {"maximum": 2}],
                            "anyOf": [{"const": 1}, {"const": 2}],
                        },
                    },
                },
                "required": ["path", "sections"],
                "additionalProperties": false,
            }),
        }],
    )
}

struct RecordingHttpServer {
    url: String,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    _task: tokio::task::JoinHandle<()>,
}

impl RecordingHttpServer {
    async fn start(response: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/chat/completions", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&buffer[..read]);
                if let Some(header_end) =
                    request.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    let headers = std::str::from_utf8(&request[..header_end]).unwrap();
                    let content_length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .unwrap()
                        .parse::<usize>()
                        .unwrap();
                    if request.len() >= header_end + 4 + content_length {
                        let body = &request[header_end + 4..header_end + 4 + content_length];
                        let authorization = headers
                            .lines()
                            .find_map(|line| line.strip_prefix("authorization: "))
                            .unwrap_or_default()
                            .into();
                        recorded.lock().await.push(RecordedRequest {
                            body: serde_json::from_slice(body).unwrap(),
                            authorization,
                        });
                        break;
                    }
                }
            }
            stream
				.write_all(
					format!(
						"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{response}",
						response.len()
					)
					.as_bytes(),
				)
				.await
				.unwrap();
        });
        Self {
            url,
            requests,
            _task: task,
        }
    }

    fn url(&self) -> &str {
        &self.url
    }

    async fn single_json_request(&self) -> Value {
        let requests = self.requests.lock().await;
        assert_eq!(requests.len(), 1);
        requests[0].body.clone()
    }

    async fn single_authorization(&self) -> String {
        let requests = self.requests.lock().await;
        assert_eq!(requests.len(), 1);
        requests[0].authorization.clone()
    }
}

struct RecordedRequest {
    body: Value,
    authorization: String,
}

struct EnvironmentVariable {
    name: &'static str,
    original: Option<std::ffi::OsString>,
    _lock: MutexGuard<'static, ()>,
}

impl EnvironmentVariable {
    fn set(name: &'static str, value: &str) -> Self {
        let _lock = ENVIRONMENT_LOCK.lock().unwrap();
        let original = std::env::var_os(name);
        // SAFETY: the lock serializes this test's environment changes, and Drop restores the value.
        unsafe { std::env::set_var(name, value) };
        Self {
            name,
            original,
            _lock,
        }
    }

    fn replace(&self, value: &str) {
        // SAFETY: this guard restores the process environment in Drop after the test completes.
        unsafe { std::env::set_var(self.name, value) };
    }
}

static ENVIRONMENT_LOCK: StdMutex<()> = StdMutex::new(());

impl Drop for EnvironmentVariable {
    fn drop(&mut self) {
        // SAFETY: this guard restores the value captured before the test changed it.
        unsafe {
            match &self.original {
                Some(value) => std::env::set_var(self.name, value),
                None => std::env::remove_var(self.name),
            }
        }
    }
}

impl Drop for RecordingHttpServer {
    fn drop(&mut self) {
        self._task.abort();
    }
}
