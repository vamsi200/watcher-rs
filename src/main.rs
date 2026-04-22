#![allow(unused)]
use std::{ptr::read, thread::sleep, time::Duration};

use anyhow::Error;
use aya::{
    Btf, Ebpf, include_bytes_aligned,
    maps::RingBuf,
    programs::{FEntry, TracePoint},
};
use aya_log::EbpfLogger;
use watcher_rs::parser::{self, get_running_processes, track_process_exec};
use watcher_rs_common::ExecEvent;

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../watcher-rs-ebpf/target/bpfel-unknown-none/release/watcher-rs-ebpf"
    ))?;
    EbpfLogger::init(&mut bpf)?;

    let btf = Btf::from_sys_fs()?;
    let prog: &mut TracePoint = bpf
        .program_mut("sys_enter_execve")
        .expect("failed to load file_open")
        .try_into()?;

    prog.load()?;

    prog.attach("syscalls", "sys_enter_execve")?;

    let mut ring_buf = RingBuf::try_from(bpf.map_mut("EVENTS").unwrap())?;

    loop {
        if let Some(data) = ring_buf.next() {
            let event = unsafe { read(data.as_ptr() as *const ExecEvent) };
            let file_name = str::from_utf8(&event.filename)?;
            println!("{}:{}", event.pid, file_name);
        } else {
            sleep(Duration::from_secs(1));
        }
    }
    Ok(())
}
