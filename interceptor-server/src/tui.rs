use std::collections::VecDeque;
use std::io::{self, Stdout};
use std::time::{Duration, Instant};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    prelude::CrosstermBackend,
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{
        Block, Padding, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
    },
    Frame, Terminal,
};
use tokio::sync::mpsc;

use interceptor_core::schema::{EvaluatedEvent, InterceptionPoint, PolicyDecision};

const MAX_EVENTS: usize = 10_000;
const POLL_MS: u64 = 50;

// Fixed column widths used in format_event.
const COL_TIME: usize = 9;     // "HH:MM:SSZ"
const COL_AGENT: usize = 12;
const COL_TOOL: usize = 12;
const COL_HOOK: usize = 12;    // "TOOL_RESULT "
const COL_VERDICT: usize = 16; // "ALLOW  (999.9ms)"

struct App {
    events: VecDeque<EvaluatedEvent>,
    total_count: u64,
    allow_count: u64,
    deny_count: u64,
    pass_count: u64,
    scroll_offset: usize,
    start_time: Instant,
    addr: String,
    policy_dir: String,
}

impl App {
    fn new(addr: String, policy_dir: String) -> Self {
        Self {
            events: VecDeque::new(),
            total_count: 0,
            allow_count: 0,
            deny_count: 0,
            pass_count: 0,
            scroll_offset: 0,
            start_time: Instant::now(),
            addr,
            policy_dir,
        }
    }

    fn push_event(&mut self, event: EvaluatedEvent) {
        self.total_count += 1;
        match &event.decision {
            Some(PolicyDecision::Allow { .. }) => self.allow_count += 1,
            Some(PolicyDecision::Deny { .. }) => self.deny_count += 1,
            Some(PolicyDecision::PassThrough) => self.pass_count += 1,
            None => {}
        }
        self.events.push_front(event);
        if self.events.len() > MAX_EVENTS {
            self.events.pop_back();
        }
    }

    fn scroll_up(&mut self, n: usize) {
        self.scroll_offset = self.scroll_offset.saturating_sub(n);
    }

    fn scroll_down(&mut self, n: usize, visible_rows: usize) {
        let max = self.events.len().saturating_sub(visible_rows);
        self.scroll_offset = (self.scroll_offset + n).min(max);
    }

    fn scroll_home(&mut self) {
        self.scroll_offset = 0;
    }

    fn uptime_string(&self) -> String {
        let secs = self.start_time.elapsed().as_secs();
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        let s = secs % 60;
        format!("{h:02}:{m:02}:{s:02}")
    }
}

struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}

pub fn run_tui(
    mut rx: mpsc::Receiver<EvaluatedEvent>,
    addr: String,
    policy_dir: String,
) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;

    let mut guard = TerminalGuard { terminal };
    let mut app = App::new(addr, policy_dir);

    loop {
        while let Ok(ev) = rx.try_recv() {
            app.push_event(ev);
        }

        guard.terminal.draw(|f| draw(f, &app))?;

        if event::poll(Duration::from_millis(POLL_MS))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    let visible = visible_rows(&guard.terminal);
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Up | KeyCode::Char('k') => app.scroll_up(1),
                        KeyCode::Down | KeyCode::Char('j') => app.scroll_down(1, visible),
                        KeyCode::PageUp => app.scroll_up(visible),
                        KeyCode::PageDown => app.scroll_down(visible, visible),
                        KeyCode::Home | KeyCode::Char('g') => app.scroll_home(),
                        _ => {}
                    }
                }
            }
        }
    }

    Ok(())
}

fn visible_rows(terminal: &Terminal<CrosstermBackend<Stdout>>) -> usize {
    let total = terminal.size().map(|s| s.height as usize).unwrap_or(24);
    total.saturating_sub(4)
}

fn draw(f: &mut Frame, app: &App) {
    let [header_area, columns_area, list_area, footer_area] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(f.area());

    draw_header(f, header_area, app);
    draw_columns(f, columns_area);
    draw_list(f, list_area, app);
    draw_footer(f, footer_area);
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let line = Line::from(vec![
        Span::styled(
            " interceptor ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("| "),
        Span::styled(&app.addr, Style::default().fg(Color::White)),
        Span::raw(" | "),
        Span::styled(
            &app.policy_dir,
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::DIM),
        ),
        Span::raw(" | "),
        Span::styled(
            format!("^ {}", app.uptime_string()),
            Style::default().fg(Color::Blue),
        ),
        Span::raw(" | "),
        Span::raw(format!("{} ", app.total_count)),
        Span::styled("events", Style::default().add_modifier(Modifier::DIM)),
        Span::raw(" "),
        Span::styled(
            format!("{}", app.allow_count),
            Style::default().fg(Color::Green),
        ),
        Span::styled("/", Style::default().add_modifier(Modifier::DIM)),
        Span::styled(
            format!("{}", app.deny_count),
            Style::default().fg(Color::Red),
        ),
        Span::styled("/", Style::default().add_modifier(Modifier::DIM)),
        Span::styled(
            format!("{}", app.pass_count),
            Style::default().fg(Color::DarkGray),
        ),
    ]);

    f.render_widget(Paragraph::new(line), area);
}

fn draw_columns(f: &mut Frame, area: Rect) {
    let header = format!(
        " {:<COL_TIME$}  {:<COL_AGENT$}  {:<COL_TOOL$}  {:<COL_HOOK$}{:<COL_VERDICT$}  {}",
        "TIME", "AGENT", "TOOL", "HOOK", "VERDICT", "SUMMARY"
    );
    let line = Line::from(Span::styled(
        header,
        Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
    ));
    f.render_widget(Paragraph::new(line), area);
}

fn draw_list(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default().padding(Padding::horizontal(1));
    let inner = block.inner(area);

    let visible = inner.height as usize;
    let total = app.events.len();

    let lines: Vec<Line> = app
        .events
        .iter()
        .skip(app.scroll_offset)
        .take(visible)
        .map(|ev| format_event(ev, inner.width as usize))
        .collect();

    if lines.is_empty() {
        let empty = Paragraph::new(Line::from(Span::styled(
            "Waiting for events...",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::ITALIC),
        )))
        .block(block);
        f.render_widget(empty, area);
    } else {
        let paragraph = Paragraph::new(lines).block(block);
        f.render_widget(paragraph, area);
    }

    if total > visible {
        let mut scrollbar_state =
            ScrollbarState::new(total.saturating_sub(visible)).position(app.scroll_offset);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .thumb_style(Style::default().fg(Color::DarkGray))
                .track_style(Style::default().fg(Color::Black)),
            area,
            &mut scrollbar_state,
        );
    }
}

fn format_event(ev: &EvaluatedEvent, width: usize) -> Line<'static> {
    let time_str = {
        let ts = time::OffsetDateTime::from_unix_timestamp((ev.event.timestamp_ms / 1000) as i64)
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
        ts.format(time::macros::format_description!("[hour]:[minute]:[second]Z"))
            .unwrap_or_else(|_| "??:??:??Z".to_string())
    };

    let agent_display = format!("{:<COL_AGENT$}", ev.event.agent);
    let tool_display = format!("{:<COL_TOOL$}", ev.event.tool_name.as_deref().unwrap_or("—"));

    let summary = if ev.event.interception_point == InterceptionPoint::ToolResult {
        result_summary(ev)
    } else if let Some(p) = &ev.event.parameters {
        parameter_summary(p)
    } else {
        first_line(ev.event.reason.as_deref().unwrap_or(""))
    };

    let hook_display = format!("{:<COL_HOOK$}", ev.event.interception_point.label());

    let (verdict_str, verdict_color) = match &ev.decision {
        Some(decision) => {
            let dur = format_duration(ev.eval_duration_us);
            let (label, color) = match decision {
                PolicyDecision::Allow { .. } => ("ALLOW", Color::Green),
                PolicyDecision::Deny { .. } => ("DENY", Color::Red),
                PolicyDecision::PassThrough => ("PASS", Color::DarkGray),
            };
            (format!("{:<COL_VERDICT$}", format!("{label:<7}({dur})")), color)
        }
        None => (format!("{:<COL_VERDICT$}", ""), Color::DarkGray),
    };

    let prefix_len = COL_TIME + 2 + COL_AGENT + 2 + COL_TOOL + 2 + COL_HOOK + COL_VERDICT + 2;
    let summary_max = width.saturating_sub(prefix_len);
    let summary = truncate_display(&summary, summary_max);

    Line::from(vec![
        Span::styled(time_str, Style::default().fg(Color::DarkGray)),
        Span::raw("  "),
        Span::styled(agent_display, Style::default().fg(Color::Blue)),
        Span::raw("  "),
        Span::styled(tool_display, Style::default().fg(Color::Cyan).bold()),
        Span::raw("  "),
        Span::styled(hook_display, Style::default().fg(Color::Blue).dim()),
        Span::styled(verdict_str, Style::default().fg(verdict_color).bold()),
        Span::raw("  "),
        Span::styled(summary, Style::default().fg(Color::White).dim()),
    ])
}

fn format_duration(us: u64) -> String {
    if us >= 1000 {
        format!("{:.1}ms", us as f64 / 1000.0)
    } else {
        format!("{us}us")
    }
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").to_string()
}

fn result_summary(ev: &EvaluatedEvent) -> String {
    let outcome = ev.event.outcome.as_deref().unwrap_or("ok");
    match &ev.event.result {
        Some(v) => {
            let preview = match v.as_str() {
                Some(s) => s.to_string(),
                None => v.to_string(),
            };
            let first_line = preview.lines().next().unwrap_or("");
            format!("[{outcome}] {first_line}")
        }
        None => format!("[{outcome}]"),
    }
}

fn parameter_summary(params: &serde_json::Value) -> String {
    if let Some(cmd) = params.get("command").and_then(|v| v.as_str()) {
        return cmd.to_string();
    }
    if let Some(path) = params.get("file_path").and_then(|v| v.as_str()) {
        return path.to_string();
    }
    if let Some(pat) = params.get("pattern").and_then(|v| v.as_str()) {
        return pat.to_string();
    }
    if let Some(query) = params.get("query").and_then(|v| v.as_str()) {
        return query.to_string();
    }
    let s = params.to_string();
    if s == "null" {
        String::new()
    } else {
        s
    }
}

fn truncate_display(s: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    let char_count = s.chars().count();
    if char_count <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max.saturating_sub(3)).collect();
        format!("{cut}...")
    }
}

fn draw_footer(f: &mut Frame, area: Rect) {
    let line = Line::from(vec![
        Span::styled(" q", Style::default().fg(Color::Yellow).bold()),
        Span::styled(" quit  ", Style::default().fg(Color::DarkGray)),
        Span::styled("up/dn", Style::default().fg(Color::Yellow).bold()),
        Span::styled(" scroll  ", Style::default().fg(Color::DarkGray)),
        Span::styled("PgUp/PgDn", Style::default().fg(Color::Yellow).bold()),
        Span::styled(" page  ", Style::default().fg(Color::DarkGray)),
        Span::styled("g", Style::default().fg(Color::Yellow).bold()),
        Span::styled(" top", Style::default().fg(Color::DarkGray)),
    ]);
    f.render_widget(Paragraph::new(line), area);
}
