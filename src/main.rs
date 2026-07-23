#![allow(unused)]
use anyhow::Error;
use bpfx::{
    Bpfx, FileEvent, FileFilter, FileMask, FileTypeFilter, NetworkEvent, NetworkFilter,
    NetworkMask, ProcessEvent, ProcessFilter, ProcessMask,
};
use futures::StreamExt;
use ratatui::restore;
use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, Ipv6Addr},
    ptr::read,
    thread::sleep,
    time::Duration,
};
use tokio::{
    io::unix::AsyncFd,
    sync::{mpsc::Sender, watch},
};
use watcher_rs::app::App;
use watcher_rs::*;
use watcher_rs::{
    parser::{self, detect_suspicious_network, get_running_processes}, //track_process_exec},
                                                                      // write::read_from_log,
};
// use watcher_rs_common::*;

async fn read_events(tx: Sender<AppEvent>, mut sh_rx: watch::Receiver<bool>) -> anyhow::Result<()> {
    let mut bpf = Bpfx::new()?;

    let process_filter = ProcessFilter {
        mask: ProcessMask::ALL,
        ..Default::default()
    };

    let file_filter = FileFilter {
        event_type: FileMask::READ | FileMask::OPEN,
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
                match event {
                    FileEvent::Open(e) => {
                        if tx.send(AppEvent::File(e)).await.is_err() {
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
    let (tx, mut rx) = tokio::sync::mpsc::channel::<AppEvent>(1000);
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    color_eyre::install().unwrap();
    let terminal = ratatui::init();
    let mut app = App::new();

    tokio::spawn(async move {
        if let Err(e) = read_events(tx, shutdown_rx).await {
            eprintln!("{e}");
        }
    });

    app.run(terminal, rx, shutdown_tx)?;
    restore();
    Ok(())
}
