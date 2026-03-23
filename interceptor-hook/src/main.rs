mod translate;

use std::io::{self, Read};
use std::process;

use interceptor_core::schema::{InterceptResponse, InterceptedEvent, PolicyDecision};

use translate::TranslateResult;

const DEFAULT_ADDR: &str = "127.0.0.1:4319";

const USAGE: &str = "\
Usage: interceptor-hook [--addr <host:port>]

Claude Code hook that reads a JSON event from stdin, translates it to
the canonical schema, and POSTs to the interceptor server. Outputs a
JSON hook response on stdout. Allows if the server is unreachable.

Environment:
  INTERCEPTOR_ADDR  Server address (default: 127.0.0.1:4319)
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{USAGE}");
        return;
    }

    let mut addr: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => {
                i += 1;
                addr = args.get(i).cloned();
            }
            other => {
                eprintln!("unknown argument: {other}");
                eprint!("{USAGE}");
                process::exit(1);
            }
        }
        i += 1;
    }

    let addr = addr.unwrap_or_else(|| {
        std::env::var("INTERCEPTOR_ADDR").unwrap_or_else(|_| DEFAULT_ADDR.to_string())
    });

    let mut input = String::new();
    if io::stdin().take(1024 * 1024).read_to_string(&mut input).is_err() {
        return;
    }
    if input.trim().is_empty() {
        return;
    }

    let body: serde_json::Value = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(_) => return,
    };

    match translate::translate(&body) {
        TranslateResult::Gate(event) => {
            if let Some(resp) = post_to_server(&addr, &event) {
                if let Some(PolicyDecision::Deny { reason }) = resp.decision {
                    print_deny(&reason);
                }
            }
        }
        TranslateResult::Observe(event) => {
            let _ = post_to_server(&addr, &event);
        }
        TranslateResult::Ignore => {}
    }
}

fn print_deny(reason: &str) {
    let response = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    });
    println!("{response}");
}

fn post_to_server(addr: &str, event: &InterceptedEvent) -> Option<InterceptResponse> {
    let url = format!("http://{addr}/intercept");
    let body = serde_json::to_string(event).ok()?;

    match ureq::post(&url)
        .set("Content-Type", "application/json")
        .send_string(&body)
    {
        Ok(resp) => {
            let body_str = resp.into_string().unwrap_or_default();
            Some(serde_json::from_str(&body_str).unwrap_or(InterceptResponse { decision: None }))
        }
        Err(_) => None,
    }
}
