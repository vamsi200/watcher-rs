#![allow(unused)]
use anyhow::Error;
use aya::{
    Btf, Ebpf, include_bytes_aligned,
    maps::{Array, MapData, RingBuf},
    programs::{FEntry, TracePoint},
};
use aya_log::EbpfLogger;
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
use tokio::{io::unix::AsyncFd, sync::mpsc::Sender};
use watcher_rs::app::App;
use watcher_rs::*;
use watcher_rs::{
    parser::{self, detect_suspicious_network, get_running_processes}, //track_process_exec},
                                                                      // write::read_from_log,
};
// use watcher_rs_common::*;

async fn read_events(tx: Sender<AppEvent>) -> anyhow::Result<()> {
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

        else => break
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    // let mut filename = [0u8; 256];
    // let s = "test";
    // filename[..s.len()].copy_from_slice(&s.as_bytes());
    //
    // let ev = AppEvent::Exec(ExecEvent {
    //     timestamp: 0,
    //     kind: 12,
    //     pid: 123,
    //     uid: 12,
    //     filename,
    // });
    //
    // let ev2 = AppEvent::Exec(ExecEvent {
    //     timestamp: 123,
    //     kind: 1,
    //     pid: 13,
    //     uid: 2,
    //     filename,
    // });
    //
    // write_to_disk(ev).unwrap();
    // write_to_disk(ev2).unwrap();
    //
    // assert_eq!(true, read_from_log(size_of::<ExecEvent>()).is_ok());

    // env_logger::init();
    // let mut bpf = Ebpf::load(include_bytes_aligned!(
    //     "../watcher-rs-ebpf/target/bpfel-unknown-none/release/watcher-rs-ebpf"
    // ))?;
    // EbpfLogger::init(&mut bpf)?;
    //
    // let btf = Btf::from_sys_fs()?;
    // let prog: &mut TracePoint = bpf.program_mut("sys_enter_execve").unwrap().try_into()?;
    // prog.load()?;
    // prog.attach("syscalls", "sys_enter_execve")?;
    //
    // // FIX: openat and filp_close are creating a lot of noice.
    // let prog: &mut TracePoint = bpf.program_mut("sys_enter_openat").unwrap().try_into()?;
    // prog.load()?;
    // prog.attach("syscalls", "sys_enter_openat")?;
    //
    // let prog: &mut TracePoint = bpf.program_mut("sched_process_exit").unwrap().try_into()?;
    // prog.load()?;
    // prog.attach("sched", "sched_process_exit")?;
    //
    // let prog: &mut TracePoint = bpf.program_mut("sys_enter_connect").unwrap().try_into()?;
    // prog.load()?;
    // prog.attach("syscalls", "sys_enter_connect")?;
    //
    // // let prog: &mut FEntry = bpf.program_mut("filp_close").unwrap().try_into()?;
    // // prog.load("filp_close", &btf)?;
    // // prog.attach()?;
    //
    // let mut ring_buf = RingBuf::try_from(bpf.take_map("EVENTS").unwrap())?;
    // let dropped_ev_map = bpf.take_map("DROPPED").unwrap();
    //
    // const AF_INET: u16 = 2;
    // const AF_INET6: u16 = 10;
    // // let mut pid_conn_counts: HashMap<u32, (usize, u64)> = HashMap::new();
    // // let mut pid_ports_seen: HashMap<u32, HashSet<u16>> = HashMap::new();
    // let mut seen_pid: HashSet<u32> = HashSet::new();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<AppEvent>(10_000);
    color_eyre::install().unwrap();
    let terminal = ratatui::init();
    let mut app = App::new();

    tokio::spawn(async move {
        if let Err(e) = read_events(tx).await {
            eprintln!("{e}");
        }
    });

    app.run(terminal, rx)?;
    restore();
    Ok(())
}
