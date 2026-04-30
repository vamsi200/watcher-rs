#![allow(unused)]
use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, Ipv6Addr},
    ptr::read,
    thread::sleep,
    time::Duration,
};

use anyhow::Error;
use aya::{
    Btf, Ebpf, include_bytes_aligned,
    maps::{Array, RingBuf},
    programs::{FEntry, TracePoint},
};
use aya_log::EbpfLogger;
use tokio::io::unix::AsyncFd;
use watcher_rs::parser::{
    self, Event, detect_suspicious_network, get_running_processes, ret_event, track_process_exec,
};
use watcher_rs_common::{ExecEvent, FileEvent, NetworkEvent, SockAddrIn};

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../watcher-rs-ebpf/target/bpfel-unknown-none/release/watcher-rs-ebpf"
    ))?;
    EbpfLogger::init(&mut bpf)?;

    let btf = Btf::from_sys_fs()?;
    let prog: &mut TracePoint = bpf.program_mut("sys_enter_execve").unwrap().try_into()?;
    prog.load()?;
    prog.attach("syscalls", "sys_enter_execve")?;

    let prog: &mut TracePoint = bpf.program_mut("sys_enter_openat").unwrap().try_into()?;
    prog.load()?;
    prog.attach("syscalls", "sys_enter_openat")?;

    let prog: &mut TracePoint = bpf.program_mut("sched_process_exit").unwrap().try_into()?;
    prog.load()?;
    prog.attach("sched", "sched_process_exit")?;

    let prog: &mut TracePoint = bpf.program_mut("sys_enter_connect").unwrap().try_into()?;
    prog.load()?;
    prog.attach("syscalls", "sys_enter_connect")?;

    let prog: &mut FEntry = bpf.program_mut("filp_close").unwrap().try_into()?;
    prog.load("filp_close", &btf)?;
    prog.attach()?;

    let mut ring_buf_map = bpf.take_map("EVENTS").unwrap();
    let dropped_ev_map = bpf.take_map("DROPPED").unwrap();

    let mut ring_buf = RingBuf::try_from(&mut ring_buf_map)?;
    let mut dropped_ev = Array::try_from(dropped_ev_map)?;

    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 10;
    // let mut pid_conn_counts: HashMap<u32, (usize, u64)> = HashMap::new();
    // let mut pid_ports_seen: HashMap<u32, HashSet<u16>> = HashMap::new();
    let mut seen_pid: HashSet<u32> = HashSet::new();
    loop {
        while let Some(event) = ret_event(&mut ring_buf) {
            match event {
                Event::ProcessExec(e) => {
                    if seen_pid.insert(e.pid) {
                        println!("exec: pid={}", e.pid);
                    }
                }
                Event::ProcessExit(e) => {
                    seen_pid.remove(&e.pid);
                    println!("exit: pid={}", e.pid);
                }
                Event::FileOpen(e) => {
                    if seen_pid.insert(e.pid) {
                        println!("open: pid={}", e.pid);
                    }
                }
                Event::FileClose(e) => {
                    if seen_pid.insert(e.pid) {
                        println!("close: pid={}", e.pid);
                    }
                }
                Event::Network(e) => {
                    if seen_pid.insert(e.pid) {
                        println!("net: pid={}", e.pid);
                    }
                }
                Event::Unknown(k) => panic!("unknown kind={}", k),
            }
        }

        let dropped = dropped_ev.get(&0, 0).unwrap_or(0);
        if dropped > 0 {
            eprintln!("some events dropped brah: {}", dropped);
            dropped_ev.set(0, &0, 0)?;
        }
        sleep(Duration::from_millis(100));
    }
    Ok(())
}
