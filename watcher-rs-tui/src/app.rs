#![allow(unused)]
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::DefaultTerminal;

#[derive(Debug)]
pub struct App {
    running: bool,
}

impl Default for App {
    fn default() -> Self {
        Self { running: true }
    }
}
impl App {
    fn new() -> Self {
        Self::default()
    }
    pub fn run(mut self, mut terminal: DefaultTerminal) -> color_eyre::Result<()> {
        while self.running {
            terminal.draw(|frame| {});
            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    match key.code {
                        KeyCode::Tab => {}
                        _ => {}
                    }
                }
                todo!()
            }
        }
        Ok(())
    }
}
