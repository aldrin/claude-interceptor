use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use tokio::sync::mpsc;
use tracing::error;

use interceptor_core::Engine;
use interceptor_core::policy;
use interceptor_core::record::Recorder;
use interceptor_core::schema::{
    EvaluatedEvent, InterceptResponse, InterceptedEvent, InterceptionPoint,
};

const MAX_BODY_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
struct AppState {
    engine: Arc<Mutex<Engine>>,
    recorder: Arc<Recorder>,
    tui_tx: Option<mpsc::Sender<EvaluatedEvent>>,
}

pub async fn run_server(
    addr: String,
    engine: Engine,
    recorder: Arc<Recorder>,
    tui_tx: Option<mpsc::Sender<EvaluatedEvent>>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) {
    let state = AppState {
        engine: Arc::new(Mutex::new(engine)),
        recorder,
        tui_tx,
    };

    let app = Router::new()
        .route("/intercept", post(handle_intercept))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| {
            error!("failed to bind {addr}: {e}");
            std::process::exit(1);
        });

    tracing::info!("interceptor-server listening on {addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .unwrap_or_else(|e| {
            error!("server error: {e}");
            std::process::exit(1);
        });

    tracing::info!("server shut down");
}

async fn handle_intercept(
    State(state): State<AppState>,
    Json(event): Json<InterceptedEvent>,
) -> Response {
    let needs_decision = event.interception_point == InterceptionPoint::ToolCall;

    let engine = state.engine.clone();
    let recorder = state.recorder.clone();

    let evaluated = match tokio::task::spawn_blocking(move || {
        let start = Instant::now();
        let decision = if needs_decision {
            Some(policy::evaluate(&engine, &event))
        } else {
            None
        };

        let evaluated = EvaluatedEvent {
            event,
            decision,
            eval_duration_us: start.elapsed().as_micros() as u64,
        };

        recorder.record(&evaluated);
        evaluated
    })
    .await
    {
        Ok(ev) => ev,
        Err(e) => {
            error!("evaluation task panicked: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if let Some(tx) = &state.tui_tx {
        let _ = tx.try_send(evaluated.clone());
    }

    Json(InterceptResponse {
        decision: evaluated.decision,
    })
    .into_response()
}
