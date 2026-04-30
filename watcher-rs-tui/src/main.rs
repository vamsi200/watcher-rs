#![allow(unused)]
use color_eyre::Result;
use ratatui::restore;
use watcher_rs_tui::app::{self, App};

fn main() -> Result<()> {
    color_eyre::install()?;
    let terminal = ratatui::init();
    let mut app = App::new();
    app.run(terminal)?;
    restore();
    Ok(())
}
