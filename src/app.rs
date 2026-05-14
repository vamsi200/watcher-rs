#![allow(unused)]
use crate::AppEvent;
use crate::Severity;
use crate::parser::detect_input_device_access;
use crate::parser::detect_suspicious_file_access;
use crate::parser::detect_suspicious_network;
use crate::ui::*;
use color_eyre::config::FilterCallback;
use crossterm::event::ModifierKeyCode;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use libc::setspent;
use ratatui::{DefaultTerminal, widgets::ScrollbarState};
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;
use tokio::sync::mpsc::UnboundedReceiver;
use watcher_rs_common::ExecEvent;
use watcher_rs_common::FileEvent;

#[derive(Debug)]
pub struct App {
    pub running: bool,
    pub events: Vec<AppEvent>,
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
    pub selected_event: Option<AppEvent>,
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
            events: Vec::new(),
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
            filtered_events: Vec::new(),
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

        if ev.matches_filter(&self.event_name) {
            match ev.severity() {
                Severity::Critical => self.crit_ev_count += 1,
                Severity::High => self.high_ev_count += 1,
                Severity::Medium => self.med_ev_count += 1,
                Severity::Low => self.low_ev_count += 1,
                Severity::Info => self.info_ev_count += 1,
            }

            self.events.push(ev);
            self.filtered_events.push(self.events.len() - 1);
            self.search_events();
        }
    }

    pub fn search_events(&mut self) {
        self.filtered_events = self
            .events
            .iter()
            .enumerate()
            .filter(|(x, s)| match_query(&s, &self.search_query))
            .map(|(x, _)| x)
            .collect();
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
                    self.event_name.push_str(*fv);
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
        mut rx: UnboundedReceiver<AppEvent>,
    ) -> color_eyre::Result<()> {
        let mut last_tick = std::time::Instant::now();
        let tick_rate = Duration::from_millis(50);
        let mut events_map: VecDeque<FileEvent> = VecDeque::new();

        while self.running {
            while let Ok(event) = rx.try_recv() {
                if !self.pause {
                    match &event {
                        AppEvent::Network(ne) => {
                            let s_events = detect_suspicious_network(
                                &ne,
                                &mut self.pid_conn_counts,
                                &mut self.pid_ports_seen,
                            );
                            for event in s_events {
                                self.push(AppEvent::Suspicious(event));
                            }
                        }
                        AppEvent::File(fe) => {
                            events_map.push_back(fe.clone());
                            let f_events = detect_suspicious_file_access(&mut events_map);
                            let i_events = detect_input_device_access(&mut events_map);

                            for event in f_events {
                                self.push(AppEvent::Suspicious(event));
                            }

                            for event in i_events {
                                self.push(AppEvent::Suspicious(event));
                            }
                        }
                        _ => {}
                    };

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

    // pub fn scroll_right(&mut self) {
    //     self.horizontal_scroll = self.vertical_scroll.saturating_add(1);
    //     self.update_scroll_bar_state();
    // }
    //
    // pub fn scroll_left(&mut self) {
    //     self.vertical_scroll = self.vertical_scroll.saturating_sub(1);
    //     self.update_scroll_bar_state();
    // }
    //
    // pub fn update_scroll_bar_state(&mut self) {
    //     self.vertical_scroll_state = self.vertical_scroll_state.position(self.vertical_scroll);
    //     self.horizontal_scroll_state = self
    //         .horizontal_scroll_state
    //         .position(self.horizontal_scroll);
    // }

    pub fn selected_event(&self) -> Option<&AppEvent> {
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

pub fn match_query(e: &AppEvent, st: &str) -> bool {
    let detail = e.detail().to_lowercase();
    let kind = e.kind_label().to_lowercase();
    let pid = e.pid().to_string();
    detail.contains(st) || kind.contains(st) || pid.contains(st)
}
