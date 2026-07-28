#![allow(unused)]
use crate::AppEvent;
use crate::Severity;
use crate::helper::format_timestamp_ns;
use crate::ui::*;
use crate::write::write_to_disk;
use color_eyre::config::FilterCallback;
use crossterm::event::ModifierKeyCode;
use crossterm::event::MouseButton;
use crossterm::event::MouseEvent;
use crossterm::event::MouseEventKind;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::LeaveAlternateScreen;
use futures::SinkExt;
use libc::setspent;
use nix::time::ClockId;
use nix::time::clock_gettime;
use ratatui::layout::Position;
use ratatui::layout::Rect;
use ratatui::widgets::ListState;
use ratatui::{DefaultTerminal, widgets::ScrollbarState};
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tokio::sync::watch;

use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;

const EVENT_BATCH_SIZE: usize = 1024;

#[derive(Debug, Clone)]
pub struct UiEvent {
    pub event: AppEvent,
    pub detail: String,
    pub kind: &'static str,
    pub timestamp: String,
    pub severity: Severity,
}

impl UiEvent {
    pub fn new(ev: AppEvent, twle_hr_format: bool, wallclock_ns: u64) -> Self {
        let detail = ev.detail();
        let kind = ev.kind_label();
        let timestamp = format_timestamp_ns(ev.timestamp(), twle_hr_format, wallclock_ns);
        let severity = ev.severity();

        UiEvent {
            event: ev,
            detail,
            kind,
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
    pub horizontal_scroll_state: ScrollbarState,
    pub horizontal_scroll: usize,
    pub vertical_scroll_state: ScrollbarState,
    pub vertical_scroll: usize,
    pub selected_tab: Focus,
    pub selected: usize,
    pub selected_event: Option<UiEvent>,
    pub filtered_events: Vec<usize>,
    pub searching: bool,
    pub search_query: String,
    pub pause: bool,
    pub filter_mode: bool,
    pub event_idx: usize,
    pub event_name: String,
    pub g_char: bool,
    pub twle_hr_format: bool,
    pub pid_conn_counts: HashMap<u32, (usize, u64)>,
    pub pid_ports_seen: HashMap<u32, HashSet<u16>>,
    pub wallclock_offset_ns: u64,
    pub filter_state: ListState,
    pub stream_state: ListState,
    pub filter_area: Rect,
    pub stream_area: Rect,
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
            horizontal_scroll_state: ScrollbarState::new(0),
            horizontal_scroll: 0,
            vertical_scroll_state: ScrollbarState::new(0),
            vertical_scroll: 0,
            selected_tab: Focus::Stream,
            selected_event: None,
            filtered_events: Vec::with_capacity(10),
            selected: 0,
            searching: false,
            search_query: String::new(),
            pause: false,
            filter_mode: false,
            event_idx: 0,
            event_name: String::new(),
            g_char: false,
            twle_hr_format: false,
            pid_conn_counts: HashMap::new(),
            pid_ports_seen: HashMap::new(),
            wallclock_offset_ns: 0,
            filter_state: ListState::default(),
            filter_area: Rect::default(),
            stream_area: Rect::default(),
            stream_state: ListState::default(),
        }
    }
}

pub async fn writer_thread(mut receiver: Receiver<AppEvent>) -> anyhow::Result<()> {
    let mut batch = Vec::with_capacity(1024);
    while let Some(event) = receiver.recv().await {
        batch.push(event);

        if batch.len() >= 1024 {
            write_to_disk(&batch)?;
            batch.clear();
        }
    }
    Ok(())
}

fn row_at(area: Rect, col: u16, row: u16) -> Option<usize> {
    if !area.contains(Position::new(col, row)) {
        return None;
    }

    let rel = row - area.y;

    if rel == 0 {
        return None;
    }

    let idx = (rel - 1) as usize;

    (idx < SEVERITY_FILTERS.len()).then_some(idx)
}

fn row_at_stream(app: &App, col: u16, row: u16) -> Option<usize> {
    let area = app.stream_area;
    if !area.contains(Position::new(col, row)) {
        return None;
    }

    let rel = row - area.y;

    if rel == 0 {
        return None;
    }

    let idx = (rel - 1) as usize;

    (idx < app.filtered_events.len()).then_some(idx)
}

pub const FILTEREVENTS: [&str; 10] = [
    "All",
    "ExecEvent",
    "ExecExit",
    "ExecExitEvent",
    "FileEvent",
    "FileCloseEvent",
    "NetworkEvent",
    "ProcessEvent",
    "PrivilegeEvent",
    "SuspiciousEvent",
];

impl App {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, ev: AppEvent) {
        if self.event_name.is_empty() {
            self.event_name.push_str("All");
        }

        if !ev.matches_filter(&self.event_name) {
            return;
        }

        match ev.severity() {
            Severity::Critical => self.crit_ev_count += 1,
            Severity::High => self.high_ev_count += 1,
            Severity::Medium => self.med_ev_count += 1,
            Severity::Low => self.low_ev_count += 1,
            Severity::Info => self.info_ev_count += 1,
        }

        let ev = UiEvent::new(ev, self.twle_hr_format, self.wallclock_offset_ns);

        if self
            .filter_state
            .selected()
            .is_none_or(|i| ev.severity == SEVERITY_FILTERS[i].0)
        {
            let idx = self.events.len();
            self.events.push(ev);

            if self.search_query.is_empty() || match_query(&self.events[idx], &self.search_query) {
                self.filtered_events.push(idx);
            }
            if self.filtered_events.is_empty() {
                self.selected = 0;
            } else {
                self.selected = self.selected.min(self.filtered_events.len() - 1);
            }
        }
    }

    pub fn search_events(&mut self) {
        self.filtered_events.clear();

        for (i, ev) in self.events.iter().enumerate() {
            if self.search_query.is_empty() || match_query(ev, &self.search_query) {
                self.filtered_events.push(i);
            }
        }

        self.selected = self
            .selected
            .min(self.filtered_events.len().saturating_sub(1));
    }

    fn handle_mouse(&mut self, mouse: MouseEvent) {
        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some(idx) = row_at(self.filter_area, mouse.column, mouse.row) {
                    if self.filter_state.selected() == Some(idx) {
                        self.filter_state.select(None);
                    } else {
                        self.filter_state.select(Some(idx));
                    }
                }
            }

            _ => {}
        }

        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some(idx) = row_at_stream(self, mouse.column, mouse.row) {
                    self.stream_state.select(Some(idx));
                }
            }

            MouseEventKind::ScrollDown => {
                let next = self
                    .stream_state
                    .selected()
                    .unwrap_or(0)
                    .saturating_add(1)
                    .min(self.filtered_events.len() - 1);

                self.stream_state.select(Some(next));
            }

            MouseEventKind::ScrollUp => {
                let next = self.stream_state.selected().unwrap_or(0).saturating_sub(1);

                self.stream_state.select(Some(next));
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

        if self.filter_mode {
            match key.code {
                KeyCode::Char('w') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.event_name.clear();
                }
                KeyCode::Char(c) => {
                    self.event_name.push(c);
                }
                KeyCode::Backspace => {
                    self.event_name.pop();
                }
                KeyCode::Up => {
                    if self.event_idx > 0 {
                        self.event_idx -= 1;
                    }
                }
                KeyCode::Down => {
                    if self.event_idx + 1 < FILTEREVENTS.len() {
                        self.event_idx += 1;
                    }
                }
                KeyCode::Enter => {
                    let fv = FILTEREVENTS.get(self.event_idx).unwrap_or(&"All");
                    self.event_name.clear();
                    self.event_name.push_str(fv);
                    self.filter_mode = false;
                    self.selected_tab = Focus::Stream;
                }
                KeyCode::Esc => {
                    self.filter_mode = false;
                    self.selected_tab = Focus::Stream;
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
                    self.scroll_up();
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected_tab == Focus::Stream {
                    self.scroll_down()
                }
            }
            KeyCode::Char('g') => {
                if self.g_char {
                    self.stream_state.select(Some(0));
                    self.g_char = false;
                } else {
                    self.g_char = true;
                }
            }
            KeyCode::Char('G') => {
                if !self.filtered_events.is_empty() {
                    self.stream_state
                        .select(Some(self.filtered_events.len() - 1));
                }
            }
            KeyCode::Char('q') => self.running = false,
            KeyCode::Char('/') => {
                self.searching = true;
                self.search_query.clear();
            }
            KeyCode::Char('t') => {
                self.twle_hr_format = !self.twle_hr_format;
            }
            KeyCode::Char('f') => {
                self.filter_mode = true;
                self.selected_tab = Focus::Filter;
            }
            KeyCode::Char('p') => self.pause = !self.pause,
            _ => {
                self.g_char = false;
            }
        }
    }

    // pub fn handle_ev_key(&mut self, key: KeyEvent) {
    //     match key.code {
    //         _ => {}
    //     }
    // }

    pub async fn run(
        mut self,
        mut terminal: DefaultTerminal,
        mut rx: Receiver<AppEvent>,
        mut sh_tx: watch::Sender<bool>,
        mut writer_tx: Sender<AppEvent>,
    ) -> color_eyre::Result<()> {
        let mut last_tick = std::time::Instant::now();
        let tick_rate = Duration::from_millis(50);

        let realtime_ns = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_nanos() as u64;

        let mono = clock_gettime(ClockId::CLOCK_MONOTONIC)?;
        let mono_ns = mono.tv_sec() as u64 * 1_000_000_000 + mono.tv_nsec() as u64;

        self.wallclock_offset_ns = realtime_ns - mono_ns;

        while self.running {
            while let Ok(event) = rx.try_recv() {
                if !self.pause {
                    writer_tx.send(event.clone()).await?;
                    self.push(event);
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
        let next = self.stream_state.selected().unwrap_or(0).saturating_sub(1);

        self.stream_state.select(Some(next));
        self.get_selected();
    }

    pub fn scroll_down(&mut self) {
        let len = self.filtered_events.len();

        if len == 0 {
            self.stream_state.select(None);
            self.selected_event = None;
            return;
        }

        let next = self
            .stream_state
            .selected()
            .unwrap_or(0)
            .saturating_add(1)
            .min(len - 1);

        self.stream_state.select(Some(next));
        self.get_selected();
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
}

pub fn match_query(e: &UiEvent, st: &str) -> bool {
    let detail = &e.detail;
    let kind = e.kind;
    if st.bytes().all(|b| b.is_ascii_digit()) {
        if e.event.pid().to_string().contains(st) {
            return true;
        }
    }
    detail.contains(st) || kind.contains(st)
}
