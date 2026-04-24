#![allow(unused)]
use anyhow::Result;
use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Read},
    path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use std::{ptr::read, thread::sleep};

use anyhow::Error;
use aya::{
    Btf, Ebpf, include_bytes_aligned,
    maps::{MapData, RingBuf},
    programs::{FEntry, TracePoint},
};
use aya_log::EbpfLogger;
use watcher_rs_common::ExecEvent;

// like a snapshot
#[derive(Debug)]
pub struct ProcessInfo {
    pid: u32,
    ppid: u32,
    name: String,
    cmdline: String,
}

impl ProcessInfo {
    pub fn get_process_info_from_pid(i_pid: u32) -> Self {
        let mut cmdline = String::new();
        let mut ppid = 0u32;
        let mut pid = 0u32;
        let mut name = String::new();

        if let Ok(file) = File::open(format!("/proc/{}/status", i_pid)) {
            let mut reader = BufReader::new(file);
            for line in reader.lines() {
                let line = line.unwrap_or_default();
                let split: Vec<&str> = line.trim().split(":").collect();
                if split.len() >= 2 {
                    match split[0] {
                        "Pid" => pid = split[1].trim().parse().unwrap_or_default(),
                        "PPid" => ppid = split[1].trim().parse().unwrap_or_default(),
                        "Name" => name.push_str(split[1].trim()),
                        _ => {}
                    }
                }
            }
        }

        if let Ok(mut file) = File::open(format!("/proc/{}/cmdline", pid)) {
            file.read_to_string(&mut cmdline).unwrap_or_default();
            cmdline = cmdline.replace('\0', "");
        }
        Self {
            pid,
            ppid,
            name,
            cmdline,
        }
    }
}

#[derive(Debug)]
pub struct ProcessEvent {
    info: ProcessInfo,
    uid: u32,
    timestamp: u64,
}

pub struct ProcessExitEvent {
    pid: u32,
    timestamp: u64,
}

struct FileEvent {
    pid: u32,
    path: String,
    flags: String,
    timestamp: u64,
}

struct NetworkEvent {
    pid: u32,
    dest_ip: String,
    dest_port: u16,
    protocol: String,
    timestamp: u64,
}

struct PrivilegeEvent {
    pid: u32,
    uid: u32,
    binary: String,
    is_setuid: bool,
    timestamp: u64,
}

struct SuspiciousEvent {
    pid: u32,
    reason: String,
    severity: Severity,
    timestamp: u64,
}

enum Severity {
    Low,
    Medium,
    High,
}

pub fn get_running_processes() -> Result<Vec<ProcessInfo>> {
    let read_dir = fs::read_dir("/proc/")?;
    let mut process_info: Vec<ProcessInfo> = Vec::new();

    for entry in read_dir {
        let entry = entry?;

        if entry.file_type()?.is_dir() {
            if let Some(pid_str) = entry.file_name().to_str() {
                if pid_str.chars().all(|c| c.is_ascii_digit()) {
                    let info = ProcessInfo::get_process_info_from_pid(pid_str.parse()?);
                    process_info.push(info);
                }
            }
        }
    }

    Ok(process_info)
}

pub fn track_process_exec(ring_buf: &mut RingBuf<&mut MapData>) -> Result<Option<ProcessEvent>> {
    let mut p_event: Option<ProcessEvent> = None;

    if let Some(data) = ring_buf.next() {
        let event = unsafe { read(data.as_ptr() as *const ExecEvent) };
        let proc_info = ProcessInfo::get_process_info_from_pid(event.pid);

        let mut uid = 0u32;
        if let Ok(mut file) = File::open(format!("/proc/{}/status", event.pid)) {
            let reader = BufReader::new(file);

            for line in reader.lines() {
                let line = line?;
                let split: Vec<&str> = line.trim().split(":").collect();
                match split[0] {
                    "Uid" => {
                        if let Some(s) = split[1].split_whitespace().nth(1) {
                            uid = s.parse()?;
                        }
                    }
                    _ => {}
                }
            }
        }

        p_event = Some(ProcessEvent {
            info: proc_info,
            uid: uid,
            timestamp: event.timestamp,
        })
    }

    Ok(p_event)
}

fn track_process_exit() -> Vec<ProcessExitEvent> {
    todo!()
}

// have to capture exit as well
fn track_file_open() -> Vec<FileEvent> {
    todo!()
}

fn track_network_connect() -> Vec<NetworkEvent> {
    todo!()
}

//???
fn detect_privileged_exec() -> Vec<PrivilegeEvent> {
    todo!()
}

fn detect_suspicious_file_access(events: &[FileEvent]) -> Vec<SuspiciousEvent> {
    todo!()
}

fn detect_suspicious_network(events: &[NetworkEvent]) -> Vec<SuspiciousEvent> {
    todo!()
}

fn detect_input_device_access(events: &[FileEvent]) -> Vec<SuspiciousEvent> {
    todo!()
}
