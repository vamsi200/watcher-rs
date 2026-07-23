#![allow(unused)]
use crate::AppEvent;
use crate::Severity;
use crate::helper::format_timestamp_ns;
use crate::parser::detect_input_device_access;
use crate::parser::detect_suspicious_file_access;
use crate::parser::detect_suspicious_network;
use crate::ui::*;
use crate::write::write_to_disk;
// use crate::write::write_to_disk;
use color_eyre::config::FilterCallback;
use crossterm::event::ModifierKeyCode;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use futures::SinkExt;
use futures::channel::mpsc::Sender;
use libc::setspent;
use nix::time::ClockId;
use nix::time::clock_gettime;
use ratatui::{DefaultTerminal, widgets::ScrollbarState};
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use tokio::sync::mpsc::Receiver;
use tokio::sync::watch;

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
        }
    }
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

        let idx = self.events.len();
        let ev = UiEvent::new(ev, self.twle_hr_format, self.wallclock_offset_ns);
        self.events.push(ev);

        let ev = &self.events[idx];

        if self.search_query.is_empty() || match_query(ev, &self.search_query.to_ascii_lowercase())
        {
            self.filtered_events.push(idx);
        }

        if self.filtered_events.is_empty() {
            self.selected = 0;
        } else {
            self.selected = self.selected.min(self.filtered_events.len() - 1);
        }
    }

    pub fn search_events(&mut self) {
        self.filtered_events.clear();

        for (i, ev) in self.events.iter().enumerate() {
            if self.search_query.to_ascii_lowercase().is_empty()
                || match_query(ev, &self.search_query)
            {
                self.filtered_events.push(i);
            }
        }

        self.selected = self
            .selected
            .min(self.filtered_events.len().saturating_sub(1));
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
                    self.selected = 0;
                    self.g_char = false;
                } else {
                    self.g_char = true;
                }
            }
            KeyCode::Char('G') => {
                if !self.filtered_events.is_empty() {
                    self.selected = self.filtered_events.len() - 1;
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

    pub fn handle_ev_key(&mut self, key: KeyEvent) {
        match key.code {
            _ => {}
        }
    }

    pub fn run(
        mut self,
        mut terminal: DefaultTerminal,
        mut rx: Receiver<AppEvent>,
        mut sh_tx: watch::Sender<bool>,
    ) -> color_eyre::Result<()> {
        let mut last_tick = std::time::Instant::now();
        let tick_rate = Duration::from_millis(50);
        // let mut events_map: VecDeque<FileEvent> = VecDeque::new();

        let realtime_ns = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let mono = clock_gettime(ClockId::CLOCK_MONOTONIC).unwrap();
        let mono_ns = mono.tv_sec() as u64 * 1_000_000_000 + mono.tv_nsec() as u64;

        self.wallclock_offset_ns = mono_ns;

        while self.running {
            while let Ok(event) = rx.try_recv() {
                if !self.pause {
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
                if let Event::Key(key) = event::read()? {
                    self.handle_key(key);
                }
            }
        }
        if !self.running {
            sh_tx.send(true);
        }
        Ok(())
    }

    pub fn scroll_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
        self.get_selected();
    }

    pub fn scroll_down(&mut self) {
        if self.selected + 1 < self.filtered_events.len() {
            self.selected += 1;
        }
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
            .get(self.selected)
            .and_then(|&idx| self.events.get(idx))
    }

    pub fn get_selected(&mut self) {
        if let Some(&idx) = self.filtered_events.get(self.selected) {
            self.selected_event = self.events.get(idx).cloned()
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
