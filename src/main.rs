use bpfx::{
    Bpfx, BpfxConfig, FileEvent, FileFilter, FileMask, NetworkEvent, NetworkFilter, NetworkMask,
    ProcessEvent, ProcessFilter, ProcessMask,
};
use clap::Subcommand;
use crossterm::event::EnableMouseCapture;
use crossterm::execute;
use crossterm::terminal::{EnterAlternateScreen, enable_raw_mode};
use detection::*;
use futures::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::{Terminal, restore};
use std::collections::HashMap;
use std::fs;
use std::io::stdout;
use std::{path::PathBuf, sync::LazyLock};
use tokio::sync::mpsc::Receiver;
use tokio::sync::{mpsc::Sender, watch};
use watcher_rs::app::{App, writer_thread};
use watcher_rs::app::{ConfigState, UiEvent};
use watcher_rs::gen_db::{drop_privileges, parse_ipsum, regain_privs, update_ipsum_db};
use watcher_rs::write::RuntimeLogConfig;
use watcher_rs::*;

use clap::Parser;
use color_eyre::eyre::Result;
use tracing_error::ErrorLayer;
use tracing_subscriber::{self, Layer, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(name = "watcher-rs", version, about)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Update the ipsum database
    UpdateDb,
}

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
    mut config_watcher_rx: watch::Receiver<bool>,
    config_tx: &Sender<ConfigState>,
) -> color_eyre::eyre::Result<()> {
    let mut file_event_filter = FileEventFilter::new();
    let mut classifier = Classifier::new();

    let file_bytes = if let Some(path) = sources.state_path {
        Some(fs::read(path.join("ipsum.bin"))?)
    } else {
        None
    };

    if let Ok(rule_config) = write_path_config() {
        classifier.ipsum_file_bytes = file_bytes;
        classifier.rules = Some(rule_config.clone());
    }

    classifier.process_map = HashMap::new();

    regain_privs()?;

    loop {
        tokio::select! {
            _ = sh_rx.changed() => {
                break;
            }

            _ = config_watcher_rx.changed() => {
                tracing::info!("reloading config");
                if let Ok(rule_config) = read_path_config() {
                    tracing::info!("got new config");
                    classifier.rules = Some(rule_config);
                    config_tx.send(ConfigState::ConfigReloaded).await?;
                }else{
                    config_tx.send(ConfigState::ConfigReloadFailed).await?;
                }
            }

            Some(event) = sources.process.next() => {
                  if let Some(ref config) = classifier.rules {
                    if let Some(ref config) = config.ignore_pids && config.enabled{
                        if config.pids.iter().any(|s| event.header().pid == *s) {
                            continue;
                        }
                    }

                    if let Some(ref config) = config.ignore_comm_name && config.enabled {
                        if config.names.iter().any(|s| event.header().comm.starts_with(s)) {
                            continue;
                        }

                    }

                    if let Some(ref config) = config.ignore_exe_path && config.enabled {
                        if config.paths.iter().any(|s| read_exe(event.header().pid).starts_with(s)) {
                            continue;
                        }
                    }

                }

                classifier.process_map.insert(event.header().pid, ProcessInfo {
                    uid: event.header().uid,
                    exe: read_exe(event.header().pid),
                    comm: event.header().comm.clone()
                });

                match event {
                    ProcessEvent::Start(e) => {
                        let e = classifier.classify_process_start(e);
                        if tx.send(AppEvent::ProcessStart(e)).await.is_err() {
                            return Ok(());
                        }
                    }

                    ProcessEvent::Fork(e) => {
                        let e = classifier.classify_process_fork(e);
                        if tx.send(AppEvent::ProcessFork(e)).await.is_err() {
                            return Ok(());
                        }
                    }

                    ProcessEvent::Exit(e) => {
                        classifier.process_map.remove(&e.header.pid);
                        let e = classifier.classify_process_exit(e);
                        if tx.send(AppEvent::ProcessExit(e)).await.is_err() {
                            return Ok(());
                        }
                    }

                    _ => {}
                }
            }

            Some(event) = sources.file.next() => {
               if let Some(ref config) = classifier.rules {
                    if let Some(ref config) = config.ignore_pids && config.enabled{
                        if config.pids.iter().any(|s| event.header().pid == *s) {
                            continue;
                        }
                    }

                    if let Some(ref config) = config.ignore_comm_name && config.enabled {
                        if config.names.iter().any(|s| event.header().comm.starts_with(s)) {
                            continue;
                        }

                    }

                    if let Some(ref config) = config.ignore_exe_path && config.enabled {
                        if config.paths.iter().any(|s| read_exe(event.header().pid).starts_with(s)) {
                            continue;
                        }
                    }

                }


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

                 classifier.process_map.insert(event.header().pid, ProcessInfo {
                    uid: event.header().uid,
                    exe: read_exe(event.header().pid),
                    comm: event.header().comm.clone()
                });


                match event {
                    FileEvent::Open(e) => {
                        let event = classifier.classify_open(e);

                        if tx.send(AppEvent::FileOpen(event)).await.is_err() {
                            return Ok(());
                        }
                    }

                    FileEvent::Close(e) => {
                        classifier.process_map.remove(&e.header.pid);
                        let event = classifier.classify_close(e);

                        if tx.send(AppEvent::FileClose(event)).await.is_err() {
                            return Ok(());
                        }
                    }

                    FileEvent::Read(e) => {
                        let event = classifier.classify_read(e);

                        if tx.send(AppEvent::FileRead(event)).await.is_err() {
                            return Ok(());
                        }
                    }

                    FileEvent::Rename(e) => {
                        let event = classifier.classify_rename(e);

                        if tx.send(AppEvent::FileRename(event)).await.is_err() {
                            return Ok(());
                        }
                    }

                    FileEvent::Delete(e) => {
                        let event = classifier.classify_delete(e);

                        if tx.send(AppEvent::FileDelete(event)).await.is_err() {
                            return Ok(());
                        }
                    }

                    FileEvent::Write(e) => {
                        let event = classifier.classify_write(e);

                        if tx.send(AppEvent::FileWrite(event)).await.is_err() {
                            return Ok(());
                        }
                    }


                    _ => {}
                }
            }

            Some(event) = sources.network.next() => {
               if let Some(ref config) = classifier.rules {
                    if let Some(ref config) = config.ignore_pids && config.enabled{
                        if config.pids.iter().any(|s| event.header().pid == *s) {
                            continue;
                        }
                    }

                    if let Some(ref config) = config.ignore_comm_name && config.enabled {
                        if config.names.iter().any(|s| event.header().comm.starts_with(s)) {
                            continue;
                        }

                    }

                     if let Some(ref config) = config.ignore_exe_path && config.enabled {
                        if config.paths.iter().any(|s| read_exe(event.header().pid).starts_with(s)) {
                            continue;
                        }
                    }

                }

                classifier.process_map.insert(event.header().pid, ProcessInfo {
                    uid: event.header().uid,
                    exe: read_exe(event.header().pid),
                    comm: event.header().comm.clone()
                });


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

                     NetworkEvent::Bind(e) => {
                        let event = classifier.classify_bind(e);
                        if tx.send(AppEvent::NetworkBind(event)).await.is_err() {
                            return Ok(());
                        }
                    }

                    NetworkEvent::Close(e) => {
                        classifier.process_map.remove(&e.header.pid);
                        let event = classifier.classify_network_close(e);
                        if tx.send(AppEvent::NetworkClose(event)).await.is_err() {
                            return Ok(());
                        }
                    }

                    NetworkEvent::Listen(e) => {
                        let event = classifier.classify_listen(e);
                        if tx.send(AppEvent::NetworkListen(event)).await.is_err() {
                            return Ok(());
                        }
                    }

                    _ => {}
                }
            }

            else => break,
        }

        if classifier.process_map.len() >= 5000 {
            tracing::info!("clearing process_map");
            classifier.process_map.clear();
        }
    }

    Ok(())
}

async fn start_ui(
    rx: Receiver<AppEvent>,
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
    writer_tx: &tokio::sync::mpsc::Sender<UiEvent>,
    batch_ready_rx: tokio::sync::mpsc::Receiver<bool>,
    config_watcher_tx: watch::Sender<bool>,
    config_rx: Receiver<ConfigState>,
) -> color_eyre::Result<()> {
    let mut stdout = stdout();

    enable_raw_mode()?;
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;

    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    let app = App::new();

    app.run(
        terminal,
        rx,
        shutdown_tx,
        writer_tx,
        batch_ready_rx,
        config_watcher_tx,
        config_rx,
    )
    .await?;

    restore();

    Ok(())
}

async fn start_collectors(
    writer_ready_tx: tokio::sync::oneshot::Sender<()>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    config_watcher_rx: watch::Receiver<bool>,
    tx: tokio::sync::mpsc::Sender<AppEvent>,
    config_tx: Sender<ConfigState>,
) -> color_eyre::Result<()> {
    let config = BpfxConfig {
        channel_capacity: 10000,
    };

    let mut bpf = Bpfx::with_config(config)?;

    let process_filter = ProcessFilter {
        mask: ProcessMask::ALL,
        ..Default::default()
    };

    let file_filter = FileFilter {
        event_type: FileMask::ALL,
        ..Default::default()
    };

    let network_filter = NetworkFilter {
        event_mask: NetworkMask::ALL,
        ..Default::default()
    };

    let sources = EventSources {
        process: bpf.subscribe(process_filter)?,
        file: bpf.subscribe(file_filter)?,
        network: bpf.subscribe(network_filter)?,
        state_path: STATE_PATH.as_ref(),
    };

    drop_privileges()?;

    writer_ready_tx
        .send(())
        .map_err(|_| color_eyre::eyre::eyre!("failed to send ready status"))?;

    init()?;

    let runtime = bpf.run();

    read_events(tx, shutdown_rx, sources, config_watcher_rx, &config_tx).await?;

    drop(runtime);

    Ok(())
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    initialize_logging()?;

    let args = Args::parse();

    match args.command {
        Some(Command::UpdateDb) => {
            update_ipsum_db()?;
            return Ok(());
        }
        None => {}
    }

    let (tx, rx) = tokio::sync::mpsc::channel::<AppEvent>(10_000);

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let (writer_tx, writer_rx) = tokio::sync::mpsc::channel::<UiEvent>(10_000);

    let (batch_ready_tx, batch_ready_rx) = tokio::sync::mpsc::channel::<bool>(100);

    let (writer_ready_tx, writer_ready_rx) = tokio::sync::oneshot::channel::<()>();

    let (config_watcher_tx, config_watcher_rx) = watch::channel::<bool>(false);

    let (config_tx, config_rx) = tokio::sync::mpsc::channel::<ConfigState>(100);

    tokio::spawn(async move {
        if let Err(e) = start_collectors(
            writer_ready_tx,
            shutdown_rx,
            config_watcher_rx,
            tx,
            config_tx,
        )
        .await
        {
            tracing::error!(?e, "collector failed");
        }
    });

    let runtime_log_config = RuntimeLogConfig::from(get_log_config()?);

    tokio::spawn(async move {
        if writer_ready_rx.await.is_err() {
            eprintln!("BPF initialization failed; writer exiting");
            return;
        }

        if let Err(e) = writer_thread(writer_rx, batch_ready_tx, runtime_log_config).await {
            eprintln!("writer failed: {e}");
            return;
        }
    });

    tokio::spawn(async move {
        if let Err(e) = tokio::task::spawn_blocking(|| {
            if parse_ipsum(STATE_PATH.as_ref(), false).is_err() {
                eprintln!("failed to parse ipsum db..")
            }
        })
        .await
        {
            eprintln!("failed to parse ipsum database: {e}");
        }
    });

    start_ui(
        rx,
        &shutdown_tx,
        &writer_tx,
        batch_ready_rx,
        config_watcher_tx,
        config_rx,
    )
    .await?;

    Ok(())
}
