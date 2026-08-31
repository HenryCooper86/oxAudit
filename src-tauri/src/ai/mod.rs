pub mod errors;
pub mod sse;
pub mod usage;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use futures::StreamExt;
use serde::Serialize;
use serde_json::Value;

use crate::credentials::ResolvedAiSettings;
use crate::models::{
    AiSettings, AiStatus, ChatMessage, ChatRequest, ChatResponse, CveItem, Finding, Usage,
};

use errors::LlmError;

/// One typed event in the AI stream, emitted to the frontend as `ai://event`.
#[derive(Serialize, Clone, Debug)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum AiStreamEvent {
    /// A text fragment.
    Delta { content: String },
    /// A reasoning fragment (e.g. `reasoning_content` on o1/R1-style models).
    Reasoning { content: String },
    /// Token usage reported mid-stream (OpenAI `stream_options.include_usage`).
    Usage { usage: Usage },
    /// Local, approximate context consumption before this model request.
    ContextBudget {
        estimated_tokens: u32,
        context_window: u32,
        reserved_output_tokens: u32,
    },
    /// Older conversation turns were summarized to fit the context window; the
    /// model now works from `summary` instead of the folded messages. Emitted
    /// once, before the first `ContextBudget` of the compacted turn.
    ContextCompacted {
        summarized_messages: u32,
        summary: String,
    },
    /// The model requested a tool call; the loop is about to execute it.
    ToolStart {
        tool_call_id: String,
        name: String,
        arguments: String,
    },
    /// A tool finished (or failed); `result_preview` is a bounded excerpt.
    ToolResult {
        tool_call_id: String,
        name: String,
        success: bool,
        duration_ms: u64,
        result_preview: String,
    },
    /// The `ask_user` tool needs answers (renders an interactive modal).
    AskUser {
        request_id: String,
        questions: Value,
    },
    /// A message the user submitted mid-run was folded into the conversation
    /// at an iteration boundary.
    Steer { text: String },
    /// The agent's todo list changed. Carries the whole list, so the UI never
    /// has to reconstruct state from a sequence of operations.
    Todos { items: Value },
    /// A tool call requires human approval (permission pipeline).
    PermissionRequest {
        request_id: String,
        tool: String,
        arguments: String,
    },
}

/// A structured tool call requested by the model.
#[derive(Debug, Clone)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: Value,
}

/// Outcome of one model turn (may contain tool calls to execute).
pub struct StreamOutcome {
    pub content: String,
    pub usage: Option<Usage>,
    pub tool_calls: Vec<ToolCall>,
}

pub struct AiClient {
    pub http: reqwest::Client,
}

impl AiClient {
    pub fn new(http: reqwest::Client) -> Self {
        Self { http }
    }

    fn base_url(settings: &AiSettings) -> String {
        settings.base_url.trim_end_matches('/').to_string()
    }

    fn request_body(settings: &AiSettings, req: &ChatRequest, stream: bool) -> serde_json::Value {
        serde_json::json!({
            "model": settings.model,
            "messages": req.messages,
            "temperature": req.temperature.unwrap_or(settings.temperature),
            "max_tokens": req.max_tokens.unwrap_or(settings.max_tokens),
            "stream": stream,
            "stream_options": { "include_usage": true },
        })
    }

    /// Body for the agent loop: wire-ready messages + OpenAI tool definitions.
    fn loop_request_body(
        settings: &AiSettings,
        messages: &[Value],
        tools: &[Value],
    ) -> serde_json::Value {
        serde_json::json!({
            "model": settings.model,
            "messages": messages,
            "temperature": settings.temperature,
            "max_tokens": settings.max_tokens,
            "tools": tools,
            "tool_choice": "auto",
            "stream": true,
            "stream_options": { "include_usage": true },
        })
    }

    pub(crate) fn estimate_context_tokens(messages: &[Value], tools: &[Value]) -> u32 {
        let message_chars = messages
            .iter()
            .map(|message| message.to_string().chars().count())
            .sum::<usize>();
        let tool_chars = tools
            .iter()
            .map(|tool| tool.to_string().chars().count())
            .sum::<usize>();
        let framing = messages.len().saturating_mul(4);
        ((message_chars.saturating_add(tool_chars).saturating_add(3)) / 4)
            .saturating_add(framing)
            .min(u32::MAX as usize) as u32
    }

    fn context_fits(estimated_tokens: u32, settings: &AiSettings) -> bool {
        estimated_tokens.saturating_add(settings.max_tokens) <= settings.context_window
    }

    fn authed_request(
        &self,
        url: &str,
        settings: &ResolvedAiSettings,
        body: &serde_json::Value,
        stream: bool,
    ) -> reqwest::RequestBuilder {
        let mut builder = self.http.post(url).json(body);
        if let Some(api_key) = settings.api_key.as_ref() {
            builder = builder.bearer_auth(api_key.as_str());
        }
        if !stream {
            // No total timeout for streams: a long generation would trip it.
            // Idle protection is handled per-chunk inside stream_chat; connect
            // timeout is set on the shared client (see AppState::new).
            builder = builder.timeout(std::time::Duration::from_secs(
                settings.timeout_secs.max(10),
            ));
        }
        builder
    }

    /// Send a non-streaming chat completion request (OpenAI-compatible API).
    pub async fn chat(
        &self,
        settings: &ResolvedAiSettings,
        req: ChatRequest,
    ) -> Result<ChatResponse, String> {
        let url = format!("{}/chat/completions", Self::base_url(settings));
        let body = Self::request_body(settings, &req, false);
        let resp = self
            .authed_request(&url, settings, &body, false)
            .send()
            .await
            .map_err(|e| LlmError::NetworkError(e.to_string()).user_message())?;
        let status = resp.status();
        if !status.is_success() {
            let retry_after = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());
            let text = resp.text().await.unwrap_or_default();
            return Err(errors::classify(status.as_u16(), &text, retry_after).user_message());
        }
        let json: Value = resp
            .json()
            .await
            .map_err(|e| LlmError::ParseError(e.to_string()).user_message())?;

        let content = json
            .get("choices")
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|c| c.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string();

        let model = json.get("model").and_then(|m| m.as_str()).map(String::from);
        let usage = json.get("usage").map(|u| Usage {
            prompt_tokens: u.get("prompt_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            completion_tokens: u
                .get("completion_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32,
            total_tokens: u.get("total_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        });

        Ok(ChatResponse {
            content,
            model,
            usage,
        })
    }

    /// Stream a model turn against wire-ready `messages` + OpenAI tool
    /// definitions. Accumulates streamed tool-call deltas and returns them in
    /// `StreamOutcome` for the agent loop to execute.
    ///
    /// Retry policy (y-agent provider attempt contract): only transient
    /// handshake failures retry — 5xx/network with backoff, 429 honoring
    /// `Retry-After` once. Once the stream is open, mid-stream errors surface
    /// via the returned `Err` and partial content is never replayed.
    ///
    /// `cancel` (optional) is checked between chunks.
    pub async fn stream_chat(
        &self,
        settings: &ResolvedAiSettings,
        messages: Vec<Value>,
        tools: Vec<Value>,
        cancel: Option<Arc<AtomicBool>>,
        mut on_event: impl FnMut(AiStreamEvent) + Send,
    ) -> Result<StreamOutcome, LlmError> {
        let estimated_tokens = Self::estimate_context_tokens(&messages, &tools);
        on_event(AiStreamEvent::ContextBudget {
            estimated_tokens,
            context_window: settings.context_window,
            reserved_output_tokens: settings.max_tokens,
        });
        if !Self::context_fits(estimated_tokens, settings) {
            return Err(LlmError::ContextWindowExceeded);
        }
        let url = format!("{}/chat/completions", Self::base_url(settings));
        let body = Self::loop_request_body(settings, &messages, &tools);

        // ---- handshake with bounded retry ----
        let mut resp = {
            let mut attempt = 0usize;
            loop {
                let builder = self.authed_request(&url, settings, &body, true);
                match builder.send().await {
                    Ok(r) => break r,
                    Err(e) => {
                        let err = LlmError::NetworkError(e.to_string());
                        if attempt < 2 && err.is_transient() {
                            attempt += 1;
                            tokio::time::sleep(std::time::Duration::from_secs(attempt as u64))
                                .await;
                            continue;
                        }
                        return Err(err);
                    }
                }
            }
        };

        let status = resp.status();
        if !status.is_success() {
            let retry_after = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());
            let text = resp.text().await.unwrap_or_default();
            let err = errors::classify(status.as_u16(), &text, retry_after);

            // one retry for transient failures / rate limits
            let retry_delay = match &err {
                LlmError::RateLimited { retry_after_secs } => Some(std::time::Duration::from_secs(
                    retry_after_secs.unwrap_or(1).min(10),
                )),
                e if e.is_transient() => Some(std::time::Duration::from_secs(2)),
                _ => None,
            };
            if let Some(delay) = retry_delay {
                tokio::time::sleep(delay).await;
                let builder = self.authed_request(&url, settings, &body, true);
                match builder.send().await {
                    Ok(r) if r.status().is_success() => resp = r,
                    Ok(r2) => {
                        let status2 = r2.status();
                        let ra2 = r2
                            .headers()
                            .get(reqwest::header::RETRY_AFTER)
                            .and_then(|v| v.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok());
                        let t2 = r2.text().await.unwrap_or_default();
                        return Err(errors::classify(status2.as_u16(), &t2, ra2));
                    }
                    Err(e) => return Err(LlmError::NetworkError(e.to_string())),
                }
            } else {
                return Err(err);
            }
        }

        // ---- stream ----
        let mut decoder = sse::SseDecoder::new();
        let mut stream = resp.bytes_stream();
        let mut full_text = String::new();
        let mut final_usage: Option<Usage> = None;
        let mut accumulator = ToolCallAccumulator::new();
        let idle = std::time::Duration::from_secs(settings.timeout_secs.max(10));
        let mut done = false;

        while !done {
            if let Some(cancel) = &cancel {
                if cancel.load(Ordering::Relaxed) {
                    return Err(LlmError::Cancelled);
                }
            }
            let chunk = tokio::time::timeout(idle, stream.next()).await;
            let bytes = match chunk {
                Err(_) => return Err(LlmError::Timeout),
                Ok(None) => break,
                Ok(Some(Ok(b))) => b,
                Ok(Some(Err(e))) => {
                    return Err(LlmError::NetworkError(format!("stream read error: {e}")));
                }
            };
            decoder.push(&bytes);
            while let Some(data) = decoder.next_data() {
                if data.trim() == "[DONE]" {
                    done = true;
                    break;
                }
                let parsed: Value = match serde_json::from_str(&data) {
                    Ok(v) => v,
                    Err(_) => continue, // malformed event — skip, keep stream alive
                };
                if let Some(u) = parsed.get("usage") {
                    let usage = Usage {
                        prompt_tokens: u.get("prompt_tokens").and_then(|v| v.as_u64()).unwrap_or(0)
                            as u32,
                        completion_tokens: u
                            .get("completion_tokens")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0) as u32,
                        total_tokens: u.get("total_tokens").and_then(|v| v.as_u64()).unwrap_or(0)
                            as u32,
                    };
                    final_usage = Some(usage.clone());
                    on_event(AiStreamEvent::Usage { usage });
                }
                if let Some(choice) = parsed
                    .get("choices")
                    .and_then(|c| c.as_array())
                    .and_then(|a| a.first())
                {
                    if let Some(delta) = choice.get("delta") {
                        if let Some(c) = delta.get("content").and_then(|v| v.as_str()) {
                            if !c.is_empty() {
                                full_text.push_str(c);
                                on_event(AiStreamEvent::Delta {
                                    content: c.to_string(),
                                });
                            }
                        }
                        if let Some(r) = delta.get("reasoning_content").and_then(|v| v.as_str()) {
                            if !r.is_empty() {
                                on_event(AiStreamEvent::Reasoning {
                                    content: r.to_string(),
                                });
                            }
                        }
                        if let Some(tcs) = delta.get("tool_calls").and_then(|v| v.as_array()) {
                            for tc in tcs {
                                accumulator.process_delta(
                                    tc.get("index").and_then(|v| v.as_u64()).map(|v| v as usize),
                                    tc.get("id").and_then(|v| v.as_str()),
                                    tc.get("function")
                                        .and_then(|f| f.get("name"))
                                        .and_then(|v| v.as_str()),
                                    tc.get("function")
                                        .and_then(|f| f.get("arguments"))
                                        .and_then(|v| v.as_str()),
                                );
                            }
                        }
                    }
                }
            }
        }

        let tool_calls = accumulator.drain();

        Ok(StreamOutcome {
            content: full_text,
            usage: final_usage,
            tool_calls,
        })
    }

    /// Test connectivity with a 1-token ping; classified errors.
    pub async fn test_connection(&self, settings: &ResolvedAiSettings) -> Result<AiStatus, String> {
        let url = format!("{}/models", Self::base_url(settings));
        let timeout = std::time::Duration::from_secs(settings.timeout_secs.max(10));
        let mut builder = self.http.get(&url).timeout(timeout);
        if let Some(api_key) = settings.api_key.as_ref() {
            builder = builder.bearer_auth(api_key.as_str());
        }
        let started = Instant::now();
        let resp = builder
            .send()
            .await
            .map_err(|e| LlmError::NetworkError(e.to_string()).user_message())?;
        let latency = started.elapsed().as_millis() as u64;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            let err = errors::classify(status.as_u16(), &text, None);
            return Ok(AiStatus {
                ok: false,
                message: err.user_message(),
                model: None,
                latency_ms: latency,
            });
        }
        let json: Value = resp.json().await.unwrap_or(Value::Null);
        let count = json
            .get("data")
            .and_then(|d| d.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        Ok(AiStatus {
            ok: true,
            message: if count > 0 {
                format!("connected — {count} models available")
            } else {
                "connected".into()
            },
            model: Some(settings.model.clone()),
            latency_ms: latency,
        })
    }
}

/// Build a message list analyzing a scan finding.
pub fn analyze_finding_messages(finding: &Finding, settings: &AiSettings) -> Vec<ChatMessage> {
    let user = format!(
        "Analyze this vulnerability finding from a source code scan and explain it \
in depth, then give concrete remediation steps for THIS code.\n\n\
--- Finding ---\n\
Category: {}\n\
Rule: {} ({})\n\
Severity: {}\n\
CWE: {}\n\
Description: {}\n\
File: {}:{}\n\
Matched code:\n```\n{}\n```\n\n\
Context:\n```\n{}\n```\n\n\
Recommendation from scanner: {}\n\n\
Answer in markdown with sections: 1) What this is and why it matters, \
2) Exploitability assessment, 3) Fix for this specific code, 4) Prevention.",
        finding.category,
        finding.rule_name,
        finding.rule_id,
        finding.severity,
        finding.cwe.as_deref().unwrap_or("n/a"),
        finding.description,
        finding.file_path,
        finding.line,
        finding.match_text,
        finding.context,
        finding.recommendation,
    );
    vec![
        ChatMessage {
            role: "system".into(),
            content: settings.system_prompt.clone(),
        },
        ChatMessage {
            role: "user".into(),
            content: user,
        },
    ]
}

/// Build a message list for researching a CVE.
pub fn research_cve_messages(
    cve: &CveItem,
    osv: Option<&Value>,
    settings: &AiSettings,
) -> Vec<ChatMessage> {
    let osv_section = osv
        .map(|o| serde_json::to_string_pretty(o).unwrap_or_default())
        .unwrap_or_else(|| "no OSV record".into());
    let user = format!(
        "Research the following vulnerability and produce a structured security \
research briefing in markdown.\n\n\
--- CVE record ---\n\
ID: {}\n\
Severity: {}\n\
CVSS: {}\n\
Published: {}\n\
Modified: {}\n\
Affected products: {}\n\
CWEs: {}\n\
Description:\n{}\n\n\
References:\n{}\n\n\
--- OSV enrichment (JSON) ---\n{}\n\n\
Sections: 1) Summary in plain language, 2) Affected components and versions, \
3) Attack vectors & exploitability, 4) Known exploits (only what is confirmed by the \
record above — do not invent), 5) Mitigation & patching guidance, 6) Detection/hunting ideas.",
        cve.id,
        cve.severity.as_deref().unwrap_or("unknown"),
        cve.cvss_score
            .map(|s| s.to_string())
            .unwrap_or_else(|| "n/a".into()),
        cve.published.as_deref().unwrap_or("unknown"),
        cve.modified.as_deref().unwrap_or("unknown"),
        cve.affected_products.join(", "),
        cve.cwes.join(", "),
        cve.description,
        cve.references.join("\n"),
        osv_section,
    );
    vec![
        ChatMessage {
            role: "system".into(),
            content: settings.system_prompt.clone(),
        },
        ChatMessage {
            role: "user".into(),
            content: user,
        },
    ]
}

// ---------------------------------------------------------------------------
// Tool-call accumulation from streamed deltas (y-agent tool_call_accumulator)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ToolCallAccumulator {
    entries: Vec<AccEntry>,
}

#[derive(Default)]
struct AccEntry {
    id: Option<String>,
    name: Option<String>,
    arguments: String,
}

impl ToolCallAccumulator {
    fn new() -> Self {
        Self::default()
    }

    /// Feed one streamed delta. Some OpenAI-compatible providers omit `index`.
    /// In that case, an existing ID is authoritative, an argument-only delta
    /// continues the latest open call, and a newly identified call gets a new
    /// slot. This preserves both fragmented and parallel unindexed calls.
    fn process_delta(
        &mut self,
        index: Option<usize>,
        id: Option<&str>,
        name: Option<&str>,
        args: Option<&str>,
    ) {
        let nonempty_id = id.filter(|value| !value.is_empty());
        let nonempty_name = name.filter(|value| !value.is_empty());
        let idx = match index {
            Some(i) => i,
            None => {
                if let Some(id) = nonempty_id {
                    self.entries
                        .iter()
                        .position(|entry| entry.id.as_deref() == Some(id))
                        .unwrap_or(self.entries.len())
                } else if nonempty_name.is_some() {
                    self.entries
                        .last()
                        .filter(|entry| entry.name.is_none())
                        .map_or(self.entries.len(), |_| self.entries.len() - 1)
                } else {
                    self.entries.len().saturating_sub(1)
                }
            }
        };
        while self.entries.len() <= idx {
            self.entries.push(AccEntry::default());
        }
        let entry = &mut self.entries[idx];
        if let Some(id) = nonempty_id {
            entry.id = Some(id.to_string());
        }
        if let Some(name) = nonempty_name {
            entry.name = Some(name.to_string());
        }
        if let Some(args) = args {
            entry.arguments.push_str(args);
        }
    }

    /// Flush completed tool calls (call on [DONE] / stream end).
    fn drain(&mut self) -> Vec<ToolCall> {
        let mut out = Vec::new();
        for entry in self.entries.drain(..) {
            if let (Some(id), Some(name)) = (entry.id, entry.name) {
                let raw = entry.arguments.trim();
                let arguments = if raw.is_empty() {
                    serde_json::json!({})
                } else {
                    serde_json::from_str(raw).unwrap_or_else(|_| serde_json::json!({ "raw": raw }))
                };
                out.push(ToolCall {
                    id,
                    name,
                    arguments,
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulates_single_call() {
        let mut acc = ToolCallAccumulator::new();
        acc.process_delta(
            Some(0),
            Some("call_1"),
            Some("search_cve"),
            Some("{\"query\": \"log4"),
        );
        acc.process_delta(Some(0), None, None, Some("j\"}"));
        let calls = acc.drain();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id, "call_1");
        assert_eq!(calls[0].name, "search_cve");
        assert_eq!(calls[0].arguments["query"], "log4j");
    }

    #[test]
    fn parallel_calls_with_indices() {
        let mut acc = ToolCallAccumulator::new();
        acc.process_delta(
            Some(0),
            Some("a"),
            Some("glob"),
            Some("{\"pattern\": \"**/*.rs\"}"),
        );
        acc.process_delta(
            Some(1),
            Some("b"),
            Some("grep_project"),
            Some("{\"pattern\": \"eval\"}"),
        );
        let calls = acc.drain();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].name, "glob");
        assert_eq!(calls[1].name, "grep_project");
    }

    #[test]
    fn none_index_gets_sequential_slots() {
        // the y-agent fix: index=None must NOT collapse into slot 0
        let mut acc = ToolCallAccumulator::new();
        acc.process_delta(None, Some("x"), Some("glob"), Some("{\"pattern\": \"a\"}"));
        acc.process_delta(
            None,
            Some("y"),
            Some("search_cve"),
            Some("{\"query\": \"b\"}"),
        );
        let calls = acc.drain();
        assert_eq!(calls.len(), 2, "both calls must survive");
        assert_eq!(calls[0].name, "glob");
        assert_eq!(calls[1].name, "search_cve");
    }

    #[test]
    fn none_index_argument_fragments_stay_with_the_open_call() {
        let mut acc = ToolCallAccumulator::new();
        acc.process_delta(
            None,
            Some("call_1"),
            Some("read_file"),
            Some("{\"path\":\""),
        );
        acc.process_delta(None, None, None, Some("src/main.rs\"}"));

        let calls = acc.drain();
        assert_eq!(calls.len(), 1, "one fragmented call must not be split");
        assert_eq!(calls[0].id, "call_1");
        assert_eq!(calls[0].name, "read_file");
        assert_eq!(calls[0].arguments["path"], "src/main.rs");
    }

    #[test]
    fn invalid_args_fall_back_to_raw() {
        let mut acc = ToolCallAccumulator::new();
        acc.process_delta(Some(0), Some("c"), Some("read_file"), Some("not json"));
        let calls = acc.drain();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].arguments["raw"], "not json");
    }

    #[test]
    fn context_estimate_accounts_for_messages_tools_and_framing() {
        let messages = vec![serde_json::json!({ "role": "user", "content": "hello" })];
        let without_tools = AiClient::estimate_context_tokens(&messages, &[]);
        let with_tools = AiClient::estimate_context_tokens(
            &messages,
            &[serde_json::json!({ "type": "function", "name": "search" })],
        );
        assert!(without_tools >= 4);
        assert!(with_tools > without_tools);
    }

    #[test]
    fn context_preflight_reserves_output_tokens() {
        let settings = AiSettings {
            context_window: 1_000,
            max_tokens: 200,
            ..AiSettings::default()
        };
        assert!(AiClient::context_fits(800, &settings));
        assert!(!AiClient::context_fits(801, &settings));
    }
}
