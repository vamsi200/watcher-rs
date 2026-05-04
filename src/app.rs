#![allow(unused)]
use crate::AppEvent;
use crate::ui::*;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{DefaultTerminal, widgets::ScrollbarState};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;
use watcher_rs_common::ExecEvent;

#[derive(Debug)]
pub struct App {
    pub running: bool,
    pub events: Option<AppEvent>,
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
    pub seleced_event: usize,
    pub filtered_events: Vec<usize>,
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
            events: None,
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
            seleced_event: 0,
            filtered_events: Vec::new(),
        }
    }
}

impl App {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn run(
        mut self,
        mut terminal: DefaultTerminal,
        mut rx: UnboundedReceiver<AppEvent>,
    ) -> color_eyre::Result<()> {
        while self.running {
            while let Ok(event) = rx.try_recv() {
                self.events = Some(event);
            }

            terminal.draw(|frame| {
                render(frame, &mut self);
            });
            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    match key.code {
                        KeyCode::Tab => {
                            self.selected_tab = match self.selected_tab {
                                Focus::Sidebar => Focus::Stream,
                                Focus::Stream => Focus::Detail,
                                Focus::Detail => Focus::Sidebar,
                            }
                        }

                        KeyCode::Char('q') => self.running = false,
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }

    pub fn scroll_up(&mut self) {
        self.vertical_scroll = self.vertical_scroll.saturating_sub(1);
        self.update_scroll_bar_state();
    }

    pub fn scroll_down(&mut self) {
        self.vertical_scroll = self.vertical_scroll.saturating_add(1);
        self.update_scroll_bar_state();
    }

    pub fn scroll_right(&mut self) {
        self.horizontal_scroll = self.vertical_scroll.saturating_add(1);
        self.update_scroll_bar_state();
    }

    pub fn scroll_left(&mut self) {
        self.vertical_scroll = self.vertical_scroll.saturating_sub(1);
        self.update_scroll_bar_state();
    }

    pub fn update_scroll_bar_state(&mut self) {
        self.vertical_scroll_state = self.vertical_scroll_state.position(self.vertical_scroll);
        self.horizontal_scroll_state = self
            .horizontal_scroll_state
            .position(self.horizontal_scroll);
    }
}
