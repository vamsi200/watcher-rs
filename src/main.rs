#![allow(unused)]
use anyhow::Error;
use aya::{
    Btf, Ebpf, include_bytes_aligned,
    maps::{Array, MapData, RingBuf},
    programs::{FEntry, TracePoint},
};
use aya_log::EbpfLogger;
use ratatui::restore;
use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, Ipv6Addr},
    ptr::read,
    thread::sleep,
    time::Duration,
};
use tokio::{io::unix::AsyncFd, sync::mpsc::UnboundedSender};
use watcher_rs::app::App;
use watcher_rs::parser::{
    self, Event, detect_suspicious_network, get_running_processes, ret_event, track_process_exec,
};
use watcher_rs::*;
use watcher_rs_common::*;

async fn read_events(buf: RingBuf<MapData>, tx: UnboundedSender<AppEvent>) -> anyhow::Result<()> {
    let mut asyncfd = AsyncFd::new(buf)?;
    loop {
        let mut guard = asyncfd.readable_mut().await?;
        let ring_buf = guard.get_inner_mut();

        while let Some(data) = ring_buf.next() {
            let ptr = data.as_ptr();
            let header = unsafe { read(ptr as *const EventHeader) };

            let event = match header.kind {
                0 => AppEvent::Exec(unsafe { read(ptr as *const ExecEvent) }),
                1 => AppEvent::ExecExit(unsafe { read(ptr as *const ProcessExitEvent) }),
                2 => AppEvent::File(unsafe { read(ptr as *const FileEvent) }),
                3 => AppEvent::FileClose(unsafe { read(ptr as *const FileCloseEvent) }),
                4 => AppEvent::Network(unsafe { read(ptr as *const NetworkEvent) }),
                k => return Ok(()),
            };

            if tx.send(event).is_err() {
                return Ok(());
            }
        }
        guard.clear_ready();
    }

    Ok(())
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    env_logger::init();
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../watcher-rs-ebpf/target/bpfel-unknown-none/release/watcher-rs-ebpf"
    ))?;
    EbpfLogger::init(&mut bpf)?;

    let btf = Btf::from_sys_fs()?;
    let prog: &mut TracePoint = bpf.program_mut("sys_enter_execve").unwrap().try_into()?;
    prog.load()?;
    prog.attach("syscalls", "sys_enter_execve")?;

    // let prog: &mut TracePoint = bpf.program_mut("sys_enter_openat").unwrap().try_into()?;
    // prog.load()?;
    // prog.attach("syscalls", "sys_enter_openat")?;

    let prog: &mut TracePoint = bpf.program_mut("sched_process_exit").unwrap().try_into()?;
    prog.load()?;
    prog.attach("sched", "sched_process_exit")?;

    let prog: &mut TracePoint = bpf.program_mut("sys_enter_connect").unwrap().try_into()?;
    prog.load()?;
    prog.attach("syscalls", "sys_enter_connect")?;

    // let prog: &mut FEntry = bpf.program_mut("filp_close").unwrap().try_into()?;
    // prog.load("filp_close", &btf)?;
    // prog.attach()?;

    let mut ring_buf = RingBuf::try_from(bpf.take_map("EVENTS").unwrap())?;
    let dropped_ev_map = bpf.take_map("DROPPED").unwrap();

    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 10;
    // let mut pid_conn_counts: HashMap<u32, (usize, u64)> = HashMap::new();
    // let mut pid_ports_seen: HashMap<u32, HashSet<u16>> = HashMap::new();
    let mut seen_pid: HashSet<u32> = HashSet::new();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<AppEvent>();

    tokio::spawn(async move {
        if let Err(e) = read_events(ring_buf, tx).await {
            eprintln!("err: {e}");
        }
    });

    color_eyre::install()?;
    let terminal = ratatui::init();
    let mut app = App::new();
    app.run(terminal, rx)?;
    restore();

    Ok(())
}
