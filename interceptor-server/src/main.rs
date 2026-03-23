mod server;
mod tui;

use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, warn};

use interceptor_core::policy;
use interceptor_core::record::Recorder;
use interceptor_core::schema::EvaluatedEvent;

const DEFAULT_ADDR: &str = "127.0.0.1:4319";
const CHANNEL_CAPACITY: usize = 10_000;

const USAGE: &str = "\
Usage: interceptor-server [OPTIONS]

Options:
  --tui     Run with a live terminal UI
  --help    Print this help message

Environment:
  INTERCEPTOR_ADDR        Listen address (default: 127.0.0.1:4319)
  INTERCEPTOR_POLICY_DIR  Directory containing .rego policy files (default: policies)
  INTERCEPTOR_LOG_DIR     Directory for event log files (default: logs)
  RUST_LOG                Log level filter (default: info)
";

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{USAGE}");
        return;
    }

    let tui_mode = args.iter().any(|a| a == "--tui");

    for arg in &args {
        if arg != "--tui" {
            eprintln!("unknown argument: {arg}");
            eprint!("{USAGE}");
            std::process::exit(2);
        }
    }

    if tui_mode {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::ERROR)
            .with_writer(std::io::stderr)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .with_writer(std::io::stderr)
            .init();
    }

    let addr = env::var("INTERCEPTOR_ADDR").unwrap_or_else(|_| DEFAULT_ADDR.to_string());
    let policy_dir = env::var("INTERCEPTOR_POLICY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("policies"));
    let log_dir = env::var("INTERCEPTOR_LOG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("logs"));

    if !addr.starts_with("127.")
        && !addr.starts_with("[::1]")
        && !addr.starts_with("localhost")
    {
        warn!(
            "binding to non-loopback address {addr} — the policy endpoint will be network-accessible"
        );
    }

    let engine = policy::build_engine(&policy_dir);
    let recorder = Arc::new(Recorder::open(&log_dir));
    let policy_display = policy_dir.display().to_string();

    info!("policies loaded from {}", policy_display);

    if tui_mode {
        let (tx, rx) = mpsc::channel::<EvaluatedEvent>(CHANNEL_CAPACITY);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let server_addr = addr.clone();
        let server_handle = tokio::spawn(async move {
            server::run_server(server_addr, engine, recorder, Some(tx), async {
                let _ = shutdown_rx.await;
            })
            .await;
        });

        let tui_handle =
            tokio::task::spawn_blocking(move || tui::run_tui(rx, addr, policy_display));

        match tui_handle.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => error!("TUI error: {e}"),
            Err(e) => error!("TUI task panicked: {e}"),
        }

        let _ = shutdown_tx.send(());
        let _ = server_handle.await;
    } else {
        server::run_server(addr, engine, recorder, None, shutdown_signal()).await;
    }
}

async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("shutdown signal received, draining connections");
}
