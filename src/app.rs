#![allow(unused)]
use crate::AppEvent;
use crate::EventType;
use crate::Severity;
use crate::helper::format_timestamp_ns;
use crate::ui::*;
use crate::write::BatchInfo;
use crate::write::LogConfig;
use crate::write::PER_BATCH_SIZE;
use crate::write::RuntimeLogConfig;
use crate::write::log_path;
use crate::write::prune_batch_info;
use crate::write::read_batch;
use crate::write::read_batch_info;
use crate::write::segment_path;
use crate::write::serialize_event_data;
use crate::write::write_batch_info_to_disk;
use crate::write::write_to_disk;
use anyhow::Result;
use color_eyre::config::FilterCallback;
use crossterm::event::ModifierKeyCode;
use crossterm::event::MouseButton;
use crossterm::event::MouseEvent;
use crossterm::event::MouseEventKind;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::LeaveAlternateScreen;
use futures::SinkExt;
use libc::READ_IMPLIES_EXEC;
use libc::setspent;
use nix::time::ClockId;
use nix::time::clock_gettime;
use ratatui::layout::Position;
use ratatui::layout::Rect;
use ratatui::widgets::ListState;
use ratatui::{DefaultTerminal, widgets::ScrollbarState};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::fs::File;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::thread::sleep;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tokio::sync::watch;
use tracing::info;

use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;

#[derive(Debug, PartialEq)]
pub enum ViewMode {
    Live,
    History,
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
pub struct UiEvent {
    pub event: AppEvent,
    pub timestamp: String,
    pub severity: Severity,
}

impl UiEvent {
    pub fn new(ev: AppEvent, twle_hr_format: bool, wallclock_ns: u64) -> Self {
        let timestamp = format_timestamp_ns(ev.timestamp(), twle_hr_format, wallclock_ns);
        let severity = ev.severity();

        UiEvent {
            event: ev,
            timestamp,
            severity,
        }
    }
}

#[derive(Debug)]
pub struct App {
    pub running: bool,
    pub events: Vec<UiEvent>,
    pub alert: Option<String>,
    pub crit_ev_count: usize,
    pub high_ev_count: usize,
    pub med_ev_count: usize,
    pub low_ev_count: usize,
    pub info_ev_count: usize,
    pub selected_tab: Focus,
    pub selected_event: Option<UiEvent>,
    pub filtered_events: Vec<usize>,
    pub searching: bool,
    pub search_query: String,
    pub pause: bool,
    pub event_idx: usize,
    pub event_name: &'static str,
    pub g_char: bool,
    pub twle_hr_format: bool,
    pub wallclock_offset_ns: u64,
    pub sev_state: ListState,
    pub stream_state: ListState,
    pub filter_state: ListState,
    pub sev_area: Rect,
    pub filter_area: Rect,
    pub stream_area: Rect,
    pub view_mode: ViewMode,
    pub view_port: Viewport,
    pub current_batch: usize,
    pub loaded_range: (usize, usize),
    pub total_batches: usize,
    pub follow_tail: bool,
}

#[derive(Debug)]
pub struct Viewport {
    /// Number of visible rows.
    pub height: usize,

    /// Global index of self.events[0]
    pub window_start: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Focus {
    Sidebar,
    Stream,
    Detail,
    Filter,
}

impl Default for App {
    fn default() -> Self {
        Self {
            running: true,
            events: Vec::with_capacity(10),
            alert: None,
            crit_ev_count: 0,
            high_ev_count: 0,
            med_ev_count: 0,
            low_ev_count: 0,
            info_ev_count: 0,
            selected_tab: Focus::Stream,
            selected_event: None,
            filtered_events: Vec::with_capacity(10),
            searching: false,
            search_query: String::new(),
            pause: false,
            event_idx: 0,
            event_name: "",
            g_char: false,
            twle_hr_format: false,
            wallclock_offset_ns: 0,
            sev_state: ListState::default(),
            filter_state: ListState::default(),
            filter_area: Rect::default(),
            stream_area: Rect::default(),
            stream_state: ListState::default(),
            view_mode: ViewMode::Live,
            current_batch: 0,
            view_port: Viewport {
                height: 0,
                window_start: 0,
            },
            loaded_range: (0, 0),
            total_batches: 0,
            follow_tail: false,
            sev_area: Rect::default(),
        }
    }
}

pub async fn writer_thread(
    mut receiver: Receiver<UiEvent>,
    sender: &Sender<UiEvent>,
    batch_tx: Sender<bool>,
    log_config: RuntimeLogConfig,
) -> anyhow::Result<()> {
    let mut batch = Vec::with_capacity(PER_BATCH_SIZE);
    let mut batch_info = BatchInfo::default();
    let mut count = 0;
    let mut path = log_path()?;
    let mut segment_id = 0;
    let mut total_size = 0;
    let mut oldest_segment_id = 0;

    while let Some(event) = receiver.recv().await {
        sender.try_send(event.clone());
        batch.push(event);

        if batch.len() >= PER_BATCH_SIZE {
            let serialized_data = serialize_event_data(&batch)?;
            let batch_size = 4 + serialized_data.len() as u64;

            let mut file_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

            if file_size > 0 && file_size + batch_size > log_config.max_segment_size {
                segment_id += 1;
                path = segment_path(segment_id);
                file_size = 0;
            }

            let start_offset = write_to_disk(&path, serialized_data)?;
            file_size += batch_size;
            total_size += batch_size;

            while total_size > log_config.max_storage_size && oldest_segment_id < segment_id {
                let path = segment_path(oldest_segment_id);

                let size = std::fs::metadata(&path)?.len();

                tracing::info!(
                    "exceeded set max_storage_size, removing old batch - {}",
                    path.display()
                );

                std::fs::remove_file(&path)?;
                prune_batch_info(oldest_segment_id)?;

                total_size -= size;
                oldest_segment_id += 1;
            }

            count += 1;
            batch_info.file_offset = start_offset;
            batch_info.count = count;
            batch_info.segment_id = segment_id;

            write_batch_info_to_disk(batch_info)?;
            batch_tx.send(true).await?;
            batch.clear();
        }
    }

    Ok(())
}

fn row_at(area: Rect, col: u16, row: u16, len: usize) -> Option<usize> {
    if !area.contains(Position::new(col, row)) {
        return None;
    }

    let rel = row - area.y;

    if rel == 0 {
        return None;
    }

    let idx = (rel - 1) as usize;

    (idx < len).then_some(idx)
}

fn row_at_stream(app: &App, col: u16, row: u16) -> Option<usize> {
    let area = app.stream_area;
    if !area.contains(Position::new(col, row)) {
        return None;
    }
    let rel = (row - area.y) as usize;
    let idx = rel + app.stream_state.offset() - 1;
    (idx < app.filtered_events.len()).then_some(idx)
}

pub const FILTEREVENTS: [&str; 7] = [
    "All",
    "ProcessStart",
    "ProcessExit",
    "FileOpen",
    "FileClose",
    "NetworkAccept",
    "NetworkConnect",
];

impl App {
    pub fn new() -> Self {
        Self::default()
    }

    fn ensure_batches_loaded(&mut self, global_selected: usize) -> anyhow::Result<()> {
        if self.total_batches == 0 {
            return Ok(());
        }

        let last_batch = self.total_batches.saturating_sub(1);
        let batch = (global_selected / PER_BATCH_SIZE).min(last_batch);
        let (lo, hi) = self.loaded_range;

        if batch >= lo && batch <= hi {
            return Ok(());
        }

        let (new_lo, new_hi) = if batch < lo {
            (batch.saturating_sub(1), batch)
        } else {
            (batch, (batch + 1).min(last_batch))
        };

        self.load_batch_range(new_lo, new_hi)
    }

    fn load_batch_range(&mut self, lo: usize, hi: usize) -> anyhow::Result<()> {
        self.events.clear();
        self.filtered_events.clear();

        for b in lo..=hi {
            let batch_events = read_batch(b)?;
            for ev in batch_events {
                let idx = self.events.len();
                self.events.push(ev);
                if self.search_query.is_empty()
                    || match_query(&self.events[idx], &self.search_query)
                {
                    self.filtered_events.push(idx);
                }
            }
        }

        self.loaded_range = (lo, hi);
        self.view_port.window_start = lo * PER_BATCH_SIZE;
        Ok(())
    }

    pub async fn push(&mut self, ev: AppEvent, writer_tx: &Sender<UiEvent>) -> anyhow::Result<()> {
        if self.event_name.is_empty() {
            self.event_name = "All";
        }

        let filter = ev.matches_filter(self.filter_state.selected().unwrap_or(0));
        self.event_name = filter.1;

        if !filter.0 {
            return Ok(());
        }

        let ev = UiEvent::new(ev, self.twle_hr_format, self.wallclock_offset_ns);

        if self
            .sev_state
            .selected()
            .is_none_or(|i| ev.severity == SEVERITY_FILTERS[i].0)
        {
            match ev.event.severity() {
                Severity::Critical => self.crit_ev_count += 1,
                Severity::High => self.high_ev_count += 1,
                Severity::Medium => self.med_ev_count += 1,
                Severity::Low => self.low_ev_count += 1,
                Severity::Info => self.info_ev_count += 1,
            }

            match self.view_mode {
                ViewMode::Live => {
                    let idx = self.events.len();

                    self.events.push(ev.clone());

                    writer_tx.send(ev).await?;

                    if self.search_query.is_empty()
                        || match_query(&self.events[idx], &self.search_query)
                    {
                        self.filtered_events.push(idx);
                    }
                }

                ViewMode::History => {
                    writer_tx.send(ev).await?;
                }
            }

            if self.filtered_events.is_empty() {
                self.stream_state.select(Some(0));
            } else {
                self.stream_state.select(Some(
                    self.stream_state
                        .selected()
                        .unwrap_or(0)
                        .min(self.filtered_events.len() - 1),
                ));
            }
        }

        Ok(())
    }

    pub fn search_events(&mut self) {
        self.filtered_events.clear();

        for (i, ev) in self.events.iter().enumerate() {
            if self.search_query.is_empty() || match_query(ev, &self.search_query) {
                self.filtered_events.push(i);
            }
        }

        self.stream_state.select(Some(
            self.stream_state
                .selected()
                .unwrap_or(0)
                .min(self.filtered_events.len().saturating_sub(1)),
        ));
    }

    fn handle_mouse(&mut self, mouse: MouseEvent) {
        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some(idx) = row_at(
                    self.sev_area,
                    mouse.column,
                    mouse.row,
                    SEVERITY_FILTERS.len(),
                ) {
                    if self.sev_state.selected() == Some(idx) {
                        self.sev_state.select(None);
                    } else {
                        self.sev_state.select(Some(idx));
                    }
                }
                if let Some(idx) = row_at(
                    self.filter_area,
                    mouse.column,
                    mouse.row,
                    FILTEREVENTS.len(),
                ) {
                    if self.filter_state.selected() == Some(idx) {
                        self.filter_state.select(None);
                    } else {
                        self.filter_state.select(Some(idx));
                    }
                }
                if let Some(idx) = row_at_stream(self, mouse.column, mouse.row) {
                    self.stream_state.select(Some(idx));
                }
            }
            MouseEventKind::ScrollDown => self.scroll_down(),
            MouseEventKind::ScrollUp => {
                self.follow_tail = false;
                self.scroll_up()
            }
            _ => {}
        }
    }

    fn handle_key(&mut self, key: KeyEvent) {
        if self.searching {
            match key.code {
                KeyCode::Char('w') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.search_clear();
                }
                KeyCode::Char(c) => {
                    self.search_push(c);
                }
                KeyCode::Backspace => {
                    self.search_pop();
                }
                KeyCode::Esc | KeyCode::Enter => {
                    self.searching = false;
                }

                _ => {}
            }
        }

        match key.code {
            KeyCode::Tab => {
                self.selected_tab = match self.selected_tab {
                    Focus::Sidebar => Focus::Stream,
                    Focus::Stream => Focus::Detail,
                    Focus::Detail => Focus::Sidebar,
                    _ => Focus::Stream,
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected_tab == Focus::Stream {
                    self.follow_tail = false;
                    self.scroll_up();
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected_tab == Focus::Stream {
                    self.scroll_down()
                }
            }
            KeyCode::Enter => {
                let idx = self.stream_state.selected().unwrap_or(0);
            }
            KeyCode::Char('g') => {
                if self.g_char {
                    self.g_char = false;
                    self.follow_tail = false;

                    if self.view_mode == ViewMode::History {
                        tracing::info!("in history.");
                        if let Err(e) = self.ensure_batches_loaded(0) {
                            tracing::error!("failed to load batch: {e}");
                            return;
                        }
                    }
                    self.view_port.window_start = self.loaded_range.0 * PER_BATCH_SIZE;
                    self.stream_state.select(Some(0));
                    self.get_selected();
                } else {
                    self.g_char = true;
                }
            }

            KeyCode::Char('G') => {
                if !self.pause {
                    self.follow_tail = true;
                }

                if let Some(last) = self.filtered_events.len().checked_sub(1) {
                    self.stream_state.select(Some(last));
                    self.get_selected();
                }
            }

            KeyCode::Char('q') => self.running = false,
            KeyCode::Char('t') => {
                self.twle_hr_format = !self.twle_hr_format;
            }
            KeyCode::Char('f') | KeyCode::Char('/') => {
                self.searching = true;
                self.search_query.clear();
            }
            KeyCode::Char('l') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                tracing::info!("clearning..");
                self.view_mode = ViewMode::Live;
                self.events.clear();
                self.filtered_events.clear();
                self.view_port.window_start = 0;
                self.stream_state.select(None);
                self.selected_event = None;
            }
            KeyCode::Char('p') => self.pause = !self.pause,
            _ => {
                self.g_char = false;
            }
        }
    }

    pub async fn run(
        mut self,
        mut terminal: DefaultTerminal,
        mut rx: Receiver<AppEvent>,
        mut sh_tx: watch::Sender<bool>,
        mut writer_tx: Sender<UiEvent>,
        mut batch_rx: Receiver<bool>,
        mut live_mode_rx: Receiver<UiEvent>,
    ) -> color_eyre::Result<()> {
        let mut last_tick = std::time::Instant::now();
        let tick_rate = Duration::from_millis(100);
        let mut changed = false;
        let realtime_ns = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_nanos() as u64;

        let mono = clock_gettime(ClockId::CLOCK_MONOTONIC)?;
        let mono_ns = mono.tv_sec() as u64 * 1_000_000_000 + mono.tv_nsec() as u64;

        self.wallclock_offset_ns = realtime_ns - mono_ns;

        while self.running {
            while let Ok(event) = rx.try_recv() {
                if !self.pause {
                    self.push(event, &writer_tx).await;
                }
            }

            let mut changed = false;
            while batch_rx.try_recv().is_ok() {
                changed = true;
                self.total_batches = read_batch_info().unwrap().len();
            }

            if self.follow_tail {
                let mut added = false;

                while let Ok(event) = live_mode_rx.try_recv() {
                    let idx = self.events.len();
                    self.events.push(event);

                    if self.search_query.is_empty()
                        || match_query(&self.events[idx], &self.search_query)
                    {
                        self.filtered_events.push(idx);
                    }

                    added = true;
                }

                if added && !self.filtered_events.is_empty() {
                    let last = self.filtered_events.len() - 1;

                    self.stream_state.select(Some(last));
                    self.view_port.window_start =
                        last.saturating_sub(self.view_port.height.saturating_sub(1));
                    self.get_selected();
                }
            }

            if last_tick.elapsed() >= tick_rate {
                terminal.draw(|frame| {
                    render(frame, &mut self);
                });
                last_tick = Instant::now();
            }

            let timeout = tick_rate
                .checked_sub(last_tick.elapsed())
                .unwrap_or(Duration::ZERO);

            if event::poll(timeout)? {
                match event::read()? {
                    Event::Key(key) => self.handle_key(key),
                    Event::Mouse(mev) => self.handle_mouse(mev),
                    _ => {}
                }
            }
        }

        if !self.running {
            execute!(
                terminal.backend_mut(),
                LeaveAlternateScreen,
                DisableMouseCapture
            )?;
            sh_tx.send(true);
        }

        Ok(())
    }

    pub fn scroll_up(&mut self) {
        let local = self.stream_state.selected().unwrap_or(0);
        let global = self.view_port.window_start + local;
        let next_global = global.saturating_sub(1);

        if self.view_mode == ViewMode::History {
            if let Err(e) = self.ensure_batches_loaded(next_global) {
                tracing::error!("failed to load batch: {e}");
                return;
            }
        }

        let next_local = next_global.saturating_sub(self.view_port.window_start);
        self.stream_state.select(Some(next_local));
        self.get_selected();
    }

    pub fn scroll_down(&mut self) {
        let local = self.stream_state.selected().unwrap_or(0);
        let global = self.view_port.window_start + local;
        let next_global = global + 1;

        if self.view_mode == ViewMode::History {
            if let Err(e) = self.ensure_batches_loaded(next_global) {
                tracing::error!("failed to load batch: {e}");
                return;
            }
        }

        let next_local = next_global
            .saturating_sub(self.view_port.window_start)
            .min(self.filtered_events.len().saturating_sub(1));
        self.stream_state.select(Some(next_local));
        self.get_selected();
    }

    pub fn get_selected(&mut self) {
        let Some(selected) = self.stream_state.selected() else {
            self.selected_event = None;
            return;
        };

        if let Some(&idx) = self.filtered_events.get(selected) {
            self.selected_event = self.events.get(idx).cloned();
        } else {
            self.selected_event = None;
        }
    }

    pub fn search_push(&mut self, c: char) {
        self.search_query.push(c);
        self.search_events();
    }
    pub fn search_pop(&mut self) {
        self.search_query.pop();
        self.search_events();
    }

    pub fn search_clear(&mut self) {
        self.search_query.clear();
        self.search_events();
    }

    pub fn selected_event(&self) -> Option<&UiEvent> {
        self.filtered_events
            .get(self.stream_state.selected().unwrap_or(0))
            .and_then(|&idx| self.events.get(idx))
    }
}

pub fn match_query(e: &UiEvent, st: &str) -> bool {
    let detail = &e.event.detail();
    let kind = &e.event.kind_label();
    if st.bytes().all(|b| b.is_ascii_digit()) {
        if e.event.pid().to_string().contains(st) {
            return true;
        }
    }
    detail.contains(st) || kind.contains(st)
}
