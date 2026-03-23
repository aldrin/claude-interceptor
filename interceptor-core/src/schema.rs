/// Canonical schema for intercepted Claude Code events.
///
/// Hook events are translated into `InterceptedEvent` before being sent
/// to the server for policy evaluation and recording.
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterceptionPoint {
    ToolCall,
    ToolResult,
    AgentEnd,
    #[default]
    Notification,
}

impl InterceptionPoint {
    pub fn label(&self) -> &'static str {
        match self {
            Self::ToolCall => "TOOL_CALL",
            Self::ToolResult => "TOOL_RESULT",
            Self::AgentEnd => "AGENT_END",
            Self::Notification => "NOTIFY",
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct InterceptedEvent {
    pub v: u32,
    pub event_id: String,
    pub session_id: String,
    pub agent: String,
    pub interception_point: InterceptionPoint,
    pub timestamp_ms: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    pub raw_payload: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow { reason: String },
    Deny { reason: String },
    PassThrough,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluatedEvent {
    #[serde(flatten)]
    pub event: InterceptedEvent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<PolicyDecision>,
    pub eval_duration_us: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InterceptResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<PolicyDecision>,
}

static EVENT_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn next_event_id(session_id: &str) -> String {
    let n = EVENT_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{session_id}-{n}")
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
