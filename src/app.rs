#![allow(unused)]
use crate::AppEvent;
use crate::Severity;
use crate::ui::*;
use crossterm::event::ModifierKeyCode;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{DefaultTerminal, widgets::ScrollbarState};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;
use watcher_rs_common::ExecEvent;

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
}

#[derive(Debug, Clone, PartialEq)]
pub enum Focus {
    Sidebar,
    Stream,
    Detail,
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
        }
    }
}

impl App {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, ev: AppEvent) {
        match ev.severity() {
            Severity::Critical => self.crit_ev_count += 1,
            Severity::High => self.high_ev_count += 1,
            Severity::Medium => self.med_ev_count += 1,
            Severity::Low => self.low_ev_count += 1,
            Severity::Info => self.info_ev_count += 1,
        }

        self.events.push(ev);
        self.filtered_events.push(self.events.len() - 1);
    }

    pub fn filter_events(&mut self) {
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
        match key.code {
            KeyCode::Tab => {
                self.selected_tab = match self.selected_tab {
                    Focus::Sidebar => Focus::Stream,
                    Focus::Stream => Focus::Detail,
                    Focus::Detail => Focus::Sidebar,
                }
            }
            KeyCode::Up => {
                if self.selected_tab == Focus::Stream {
                    self.scroll_up();
                }
            }
            KeyCode::Down => {
                if self.selected_tab == Focus::Stream {
                    self.scroll_down()
                }
            }

            KeyCode::Char('q') => self.running = false,
            KeyCode::Char('/') | KeyCode::Char('f') => {
                self.searching = true;
                self.search_query.clear();
            }
            KeyCode::Char('p') => self.pause = !self.pause,
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

        while self.running {
            if !self.pause {
                while let Ok(event) = rx.try_recv() {
                    self.push(event);
                }
            }

            terminal.draw(|frame| {
                render(frame, &mut self);
            });

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
        self.filter_events();
    }
    pub fn search_pop(&mut self) {
        self.search_query.pop();
        self.filter_events();
    }

    pub fn search_clear(&mut self) {
        self.search_query.clear();
        self.filter_events();
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
