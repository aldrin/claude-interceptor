/// Event recording with daily JSONL rotation.
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tracing::{error, info};

use crate::schema::EvaluatedEvent;

pub struct Recorder {
    inner: Mutex<RecorderInner>,
}

struct RecorderInner {
    writer: BufWriter<File>,
    log_dir: PathBuf,
    current_date: String,
}

impl RecorderInner {
    fn rotate_if_needed(&mut self) {
        let today = utc_date();
        if today == self.current_date {
            return;
        }
        let path = self.log_dir.join(format!("{today}.jsonl"));
        match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(file) => {
                info!("rotated to {}", path.display());
                self.writer = BufWriter::new(file);
                self.current_date = today;
            }
            Err(e) => {
                error!("failed to rotate log file: {e}");
            }
        }
    }
}

impl Recorder {
    pub fn open(log_dir: &Path) -> Self {
        fs::create_dir_all(log_dir).unwrap_or_else(|e| {
            error!("cannot create log dir {}: {e}", log_dir.display());
            std::process::exit(1);
        });

        let today = utc_date();
        let path = log_dir.join(format!("{today}.jsonl"));

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap_or_else(|e| {
                error!("cannot open log file {}: {e}", path.display());
                std::process::exit(1);
            });

        info!("recording events to {}", path.display());

        Self {
            inner: Mutex::new(RecorderInner {
                writer: BufWriter::new(file),
                log_dir: log_dir.to_path_buf(),
                current_date: today,
            }),
        }
    }

    pub fn record(&self, event: &EvaluatedEvent) {
        let line = match serde_json::to_string(event) {
            Ok(s) => s,
            Err(e) => {
                error!("failed to serialize event: {e}");
                return;
            }
        };

        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.rotate_if_needed();
        if let Err(e) = writeln!(inner.writer, "{line}") {
            error!("failed to write event record: {e}");
        }
        let _ = inner.writer.flush();
    }
}

fn utc_date() -> String {
    let now = time::OffsetDateTime::now_utc();
    now.format(time::macros::format_description!("[year]-[month]-[day]"))
        .unwrap_or_else(|_| "unknown".to_string())
}
