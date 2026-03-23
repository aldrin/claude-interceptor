/// Translate Claude Code hook events into the canonical schema.
///
/// Hook event mapping:
///   PreToolUse   → ToolCall     (Gate)
///   PostToolUse  → ToolResult   (Observe)
///   Stop         → AgentEnd     (Observe)
///   Notification → Notification (Observe)
///   others       → Ignore
use interceptor_core::schema::{next_event_id, now_ms, InterceptedEvent, InterceptionPoint};

pub enum TranslateResult {
    Gate(InterceptedEvent),
    Observe(InterceptedEvent),
    Ignore,
}

pub fn translate(body: &serde_json::Value) -> TranslateResult {
    let event_type = body
        .get("hook_event_name")
        .or_else(|| body.get("hookEventName"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let session_id = body
        .get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let base = || InterceptedEvent {
        v: 1,
        event_id: next_event_id(&session_id),
        session_id: session_id.clone(),
        agent: "claude-code".to_string(),
        timestamp_ms: now_ms(),
        raw_payload: body.clone(),
        ..Default::default()
    };

    match event_type {
        "PreToolUse" => TranslateResult::Gate(InterceptedEvent {
            interception_point: InterceptionPoint::ToolCall,
            tool_name: Some(
                body.get("tool_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
            ),
            parameters: body.get("tool_input").cloned(),
            working_directory: body.get("cwd").and_then(|v| v.as_str()).map(String::from),
            ..base()
        }),

        "PostToolUse" => TranslateResult::Observe(InterceptedEvent {
            interception_point: InterceptionPoint::ToolResult,
            tool_name: body.get("tool_name").and_then(|v| v.as_str()).map(String::from),
            outcome: Some(
                if body
                    .get("tool_response")
                    .and_then(|r| r.get("is_error"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    "error"
                } else {
                    "ok"
                }
                .to_string(),
            ),
            result: body.get("tool_response").and_then(extract_result),
            ..base()
        }),

        "Stop" => TranslateResult::Observe(InterceptedEvent {
            interception_point: InterceptionPoint::AgentEnd,
            reason: body
                .get("last_assistant_message")
                .and_then(|v| v.as_str())
                .map(String::from),
            ..base()
        }),

        "Notification" => TranslateResult::Observe(InterceptedEvent {
            interception_point: InterceptionPoint::Notification,
            reason: body.get("message").and_then(|v| v.as_str()).map(String::from),
            ..base()
        }),

        _ => TranslateResult::Ignore,
    }
}

fn extract_result(resp: &serde_json::Value) -> Option<serde_json::Value> {
    if let Some(stdout) = resp.get("stdout").and_then(|v| v.as_str()) {
        if !stdout.is_empty() {
            return Some(serde_json::Value::String(stdout.to_string()));
        }
    }
    if let Some(stderr) = resp.get("stderr").and_then(|v| v.as_str()) {
        if !stderr.is_empty() {
            return Some(serde_json::Value::String(stderr.to_string()));
        }
    }
    if let Some(content) = resp.get("file").and_then(|f| f.get("content")).and_then(|v| v.as_str())
    {
        if !content.is_empty() {
            return Some(serde_json::Value::String(content.to_string()));
        }
    }
    if let Some(filenames) = resp.get("filenames") {
        if filenames.is_array() {
            return Some(filenames.clone());
        }
    }
    None
}
