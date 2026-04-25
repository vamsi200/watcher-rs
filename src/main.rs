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
    maps::RingBuf,
    programs::{FEntry, TracePoint},
};
use aya_log::EbpfLogger;
use watcher_rs::parser::{
    self, ProcessInfo, detect_suspicious_network, get_running_processes, track_process_exec,
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
    let prog: &mut TracePoint = bpf
        .program_mut("sys_enter_connect")
        .expect("failed to load file_open")
        .try_into()?;

    prog.load()?;

    prog.attach("syscalls", "sys_enter_connect")?;
    let mut ring_buf = RingBuf::try_from(bpf.map_mut("EVENTS").unwrap())?;
    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 10;
    let mut pid_conn_counts: HashMap<u32, (usize, u64)> = HashMap::new();
    let mut pid_ports_seen: HashMap<u32, HashSet<u16>> = HashMap::new();

    loop {
        if let Some(data) = ring_buf.next() {
            let event = unsafe { read(data.as_ptr() as *const NetworkEvent) };

            let se = detect_suspicious_network(&event, &mut pid_conn_counts, &mut pid_ports_seen);
            println!("{se:#?}");
            // match event.family {
            //     2 => {
            //         let ip = Ipv4Addr::from([
            //             event.addr[0],
            //             event.addr[1],
            //             event.addr[2],
            //             event.addr[3],
            //         ]);
            //         println!("Ip: {}; port: {}", ip, event.port);
            //     }
            //     10 => {
            //         let ip = Ipv6Addr::from(event.addr);
            //         println!("Ip: {}; port: {}", ip, event.port);
            //     }
            //     _ => {}
            // }

            // let process_info = ProcessInfo::get_process_info_from_pid(event.pid);
            // if !set.insert(event.pid) {
            //     println!("{process_info:#?}");
            //     println!("FileName: {}", str::from_utf8(&event.filename)?);
            // }
        } else {
            sleep(Duration::from_secs(1));
        }
    }
    // loop {
    //     if let Some(p) = track_process_exec(&mut ring_buf)? {
    //         println!("event: {p:#?}");
    //     }
    //     sleep(Duration::from_secs(1));
    // }

    Ok(())
}
