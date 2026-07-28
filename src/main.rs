#![allow(unused)]
use anyhow::Error;
use bpfx::{
    Bpfx, FileEvent, FileFilter, FileMask, FileTypeFilter, NetworkEvent, NetworkFilter,
    NetworkMask, ProcessEvent, ProcessFilter, ProcessMask,
};
use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen, enable_raw_mode};
use detection::*;
use futures::StreamExt;
use lru::LruCache;
use ratatui::backend::CrosstermBackend;
use ratatui::{Terminal, restore};
use std::{
    collections::{HashMap, HashSet},
    hash::{Hash, Hasher},
    io::stdout,
    net::{Ipv4Addr, Ipv6Addr},
    num::NonZeroUsize,
    ptr::read,
    thread::sleep,
    time::Duration,
};
use tokio::{
    io::unix::AsyncFd,
    signal::ctrl_c,
    sync::{mpsc::Sender, watch},
};
use watcher_rs::*;
use watcher_rs::{
    app::{App, writer_thread},
    helper::format_timestamp_ns,
};

// use watcher_rs_common::*;

use std::{path::PathBuf, sync::LazyLock};

use color_eyre::eyre::{Context, Result};
use directories::ProjectDirs;
use tracing::error;
use tracing_error::ErrorLayer;
use tracing_subscriber::{self, Layer, layer::SubscriberExt, util::SubscriberInitExt};

pub static PROJECT_NAME: LazyLock<String> =
    LazyLock::new(|| env!("CARGO_CRATE_NAME").to_uppercase().to_string());
pub static DATA_FOLDER: LazyLock<Option<PathBuf>> = LazyLock::new(|| {
    std::env::var(format!("{}_DATA", PROJECT_NAME.clone()))
        .ok()
        .map(PathBuf::from)
});
pub static LOG_ENV: LazyLock<String> =
    LazyLock::new(|| format!("{}_LOGLEVEL", PROJECT_NAME.clone()));
pub static LOG_FILE: LazyLock<String> = LazyLock::new(|| format!("{}.log", env!("CARGO_PKG_NAME")));

fn project_directory() -> Option<ProjectDirs> {
    ProjectDirs::from("com", "kdheepak", env!("CARGO_PKG_NAME"))
}

pub fn get_data_dir() -> PathBuf {
    let directory = if let Some(s) = DATA_FOLDER.clone() {
        s
    } else if let Some(proj_dirs) = project_directory() {
        proj_dirs.data_local_dir().to_path_buf()
    } else {
        PathBuf::from(".").join(".data")
    };
    directory
}

pub fn initialize_logging() -> Result<()> {
    let directory = get_data_dir();
    std::fs::create_dir_all(directory.clone())?;
    let log_path = directory.join(LOG_FILE.clone());
    let log_file = std::fs::File::create(log_path)?;
    let log_filter = std::env::var("RUST_LOG")
        .or_else(|_| std::env::var(LOG_ENV.clone()))
        .unwrap_or_else(|_| format!("{}=info", env!("CARGO_CRATE_NAME")));
    let file_subscriber = tracing_subscriber::fmt::layer()
        .with_file(true)
        .with_line_number(true)
        .with_writer(log_file)
        .with_target(false)
        .with_ansi(false)
        .with_filter(tracing_subscriber::filter::EnvFilter::builder().parse_lossy(log_filter));
    tracing_subscriber::registry()
        .with(file_subscriber)
        .with(ErrorLayer::default())
        .init();
    Ok(())
}

/// Similar to the `std::dbg!` macro, but generates `tracing` events rather
/// than printing to stdout.
///
/// By default, the verbosity level for the generated events is `DEBUG`, but
/// this can be customized.
#[macro_export]
macro_rules! trace_dbg {
    (target: $target:expr, level: $level:expr, $ex:expr) => {{
        match $ex {
            value => {
                tracing::event!(target: $target, $level, ?value, stringify!($ex));
                value
            }
        }
    }};
    (level: $level:expr, $ex:expr) => {
        trace_dbg!(target: module_path!(), level: $level, $ex)
    };
    (target: $target:expr, $ex:expr) => {
        trace_dbg!(target: $target, level: tracing::Level::DEBUG, $ex)
    };
    ($ex:expr) => {
        trace_dbg!(level: tracing::Level::DEBUG, $ex)
    };
}

async fn read_events(tx: Sender<AppEvent>, mut sh_rx: watch::Receiver<bool>) -> anyhow::Result<()> {
    let mut bpf = Bpfx::new()?;

    let process_filter = ProcessFilter {
        mask: ProcessMask::ALL,
        ..Default::default()
    };

    let file_filter = FileFilter {
        event_type: FileMask::OPEN,
        ..Default::default()
    };

    let network_filter = NetworkFilter {
        event_mask: NetworkMask::ACCEPT,
        ..Default::default()
    };

    let mut process_events = bpf.subscribe(process_filter)?;
    let mut file_events = bpf.subscribe(file_filter)?;
    let mut network_events = bpf.subscribe(network_filter)?;

    let handle = bpf.run();
    let mut file_event_filter = FileEventFilter::new();

    loop {
        tokio::select! {
            _ = sh_rx.changed() => {
                break;
            }

            Some(event) = process_events.next() => {
                match event {
                    ProcessEvent::Start(e) => {
                        if tx.send(AppEvent::Exec(e)).await.is_err() {
                            return Ok(());
                        }
                    }

                    ProcessEvent::Exit(e) => {
                        if tx.send(AppEvent::ExecExit(e)).await.is_err() {
                            return Ok(());
                        }
                    }

                    _ => {}
                }
            }

            Some(event) = file_events.next() => {

                // if let Some(inode) = event.inode(){
                //     let filter_key = FileKey {
                //         pid: event.process().pid,
                //         tid: event.process().tid,
                //         key: KeyVal::Inode(inode),
                //     };
                //
                //     if file_event_filter.should_drop(&event, filter_key) {
                //         continue;
                //     }
                //
                // } else {
                //     if let Some(path) = event.file_path() {
                //         let filter_key = FileKey {
                //             pid: event.process().pid,
                //             tid: event.process().tid,
                //             key: KeyVal::Path(path.to_owned()),
                //         };
                //
                //         if file_event_filter.should_drop(&event, filter_key) {
                //                 continue;
                //         }
                //     }
                // }

                match event {
                    FileEvent::Open(e) => {
                        let event = classify_file_events(e);
                        // if event.severity == Severity::Low {
                        //     continue;
                        // }

                        // if event.event.file_path == "/etc/passwd" {
                        // tracing::debug!("<< {}", event.event.file_path);
                        // }

                        if tx.send(AppEvent::File(event)).await.is_err() {
                            return Ok(());
                        }
                    }

                    FileEvent::Close(e) => {
                        if tx.send(AppEvent::FileClose(e)).await.is_err() {
                            return Ok(());
                        }
                    }

                    _ => {}
                }
            }

            Some(event) = network_events.next() => {
                match event {
                    NetworkEvent::Accept(e) => {
                        if tx.send(AppEvent::Network(e)).await.is_err() {
                            return Ok(());
                        }
                    }

                    _ => {}
                }
            }

            else => break,
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install().unwrap();
    initialize_logging()?;

    let mut stdout = stdout();
    enable_raw_mode()?;
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture,)?;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<AppEvent>(1000);
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let (writer_tx, mut writer_rx) = tokio::sync::mpsc::channel::<AppEvent>(1000);

    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    let mut app = App::new();

    tokio::spawn(async move {
        if let Err(e) = read_events(tx, shutdown_rx).await {
            eprintln!("{e}");
        }
    });

    tokio::spawn(async move {
        if let Err(e) = writer_thread(writer_rx).await {
            eprintln!("{e}");
        }
    });

    app.run(terminal, rx, shutdown_tx, writer_tx).await?;

    restore();
    Ok(())
}
