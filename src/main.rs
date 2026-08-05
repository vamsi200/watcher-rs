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
use futures::channel::oneshot;
use libc::{setgid, setuid};
use lru::LruCache;
use ratatui::backend::CrosstermBackend;
use ratatui::{Terminal, restore};
use std::fs::{self, File, OpenOptions, create_dir, exists};
use std::io::{BufRead, BufReader, Read};
use std::net::IpAddr;
use std::str::FromStr;
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
use tokio::task::JoinHandle;
use tokio::{
    io::unix::AsyncFd,
    signal::ctrl_c,
    sync::{mpsc::Sender, watch},
};
use watcher_rs::app::UiEvent;
use watcher_rs::gen_db::{drop_privleges, parse_ipsum};
use watcher_rs::*;
use watcher_rs::{
    app::{App, writer_thread},
    helper::format_timestamp_ns,
};

use std::{path::PathBuf, sync::LazyLock};

use color_eyre::eyre::{Context, Result};
use directories::ProjectDirs;
use tracing::error;
use tracing_error::ErrorLayer;
use tracing_subscriber::{self, Layer, layer::SubscriberExt, util::SubscriberInitExt};

struct EventSources<'a> {
    process: PollProcess,
    file: PollFile,
    network: PollNetwork,
    state_path: Option<&'a PathBuf>,
}

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

async fn read_events<'a>(
    tx: Sender<AppEvent>,
    mut sh_rx: watch::Receiver<bool>,
    mut sources: EventSources<'a>,
) -> anyhow::Result<()> {
    let mut file_event_filter = FileEventFilter::new();
    let mut classifier = Classifier::new();

    let file_bytes = if let Some(path) = sources.state_path {
        Some(fs::read(path.join("ipsum.bin"))?)
    } else {
        None
    };

    classifier.ipsum_file_bytes = file_bytes;

    loop {
        tokio::select! {
            _ = sh_rx.changed() => {
                break;
            }

            Some(event) = sources.process.next() => {
                match event {
                    ProcessEvent::Start(e) => {
                        if tx.send(AppEvent::ProcessStart(e)).await.is_err() {
                            return Ok(());
                        }
                    }

                    ProcessEvent::Exit(e) => {
                        if tx.send(AppEvent::ProcessExit(e)).await.is_err() {
                            return Ok(());
                        }
                    }

                    _ => {}
                }
            }

            Some(event) = sources.file.next() => {

                if let Some(inode) = event.inode(){
                    let filter_key = FileKey {
                        pid: event.process().pid,
                        tid: event.process().tid,
                        key: KeyVal::Inode(inode),
                    };

                    if file_event_filter.should_drop(&event, filter_key) {
                        continue;
                    }

                } else {
                    if let Some(path) = event.file_path() {
                        let filter_key = FileKey {
                            pid: event.process().pid,
                            tid: event.process().tid,
                            key: KeyVal::Path(path.to_owned()),
                        };

                        if file_event_filter.should_drop(&event, filter_key) {
                                continue;
                        }
                    }
                }

                match event {
                    FileEvent::Open(e) => {
                        let event = classifier.classify_open(e);

                        if tx.send(AppEvent::FileOpen(event)).await.is_err() {
                            return Ok(());
                        }
                    }

                    FileEvent::Close(e) => {
                        let event = classifier.classify_close(e);

                        if tx.send(AppEvent::FileClose(event)).await.is_err() {
                            return Ok(());
                        }
                    }

                    _ => {}
                }
            }

            Some(event) = sources.network.next() => {
                match event {
                    NetworkEvent::Accept(e) => {
                        let event = classifier.classify_accept(e);

                        if tx.send(AppEvent::NetworkAccept(event)).await.is_err() {
                            return Ok(());
                        }
                    }

                    NetworkEvent::Connect(e) => {
                        let event = classifier.classify_connect(e);
                        if tx.send(AppEvent::NetworkConnect(event)).await.is_err() {
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

    let (tx, mut rx) = tokio::sync::mpsc::channel::<AppEvent>(10000);
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let (writer_tx, mut writer_rx) = tokio::sync::mpsc::channel::<UiEvent>(10000);
    let (batch_ready_tx, mut batch_ready_rx) = tokio::sync::mpsc::channel::<bool>(100);

    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    let mut app = App::new();

    tokio::spawn(async move {
        let mut bpf = Bpfx::new().unwrap();

        let process_filter = ProcessFilter {
            mask: ProcessMask::ALL,
            ..Default::default()
        };

        let file_filter = FileFilter {
            event_type: FileMask::OPEN,
            ..Default::default()
        };

        let network_filter = NetworkFilter {
            event_mask: NetworkMask::ACCEPT | NetworkMask::CONNECT,
            ..Default::default()
        };

        let sources = EventSources {
            process: bpf.subscribe(process_filter).unwrap(),
            file: bpf.subscribe(file_filter).unwrap(),
            network: bpf.subscribe(network_filter).unwrap(),
            state_path: STATE_PATH.as_ref(),
        };

        if let Err(_) = drop_privleges() {
            eprintln!("failed to drop privileges");
        }

        let _runtime = bpf.run();
        if let Err(e) = read_events(tx, shutdown_rx, sources).await {
            eprintln!("{e}");
        }
    });

    tokio::spawn(async move {
        if let Err(e) = writer_thread(writer_rx, batch_ready_tx).await {
            eprintln!("{e}");
        }
    });

    tokio::spawn(async move {
        let _ = tokio::task::spawn_blocking(move || parse_ipsum(STATE_PATH.as_ref())).await;
    });

    app.run(terminal, rx, shutdown_tx, writer_tx, batch_ready_rx)
        .await
        .unwrap();

    restore();
    Ok(())
}
