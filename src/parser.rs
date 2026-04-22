#![allow(unused)]
use anyhow::Result;
use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Read},
    path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

// like a snapshot
#[derive(Debug)]
pub struct ProcessInfo {
    pid: u32,
    ppid: u32,
    name: String,
    cmdline: String,
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
                    let mut cmdline = String::new();
                    if let Ok(mut file) = File::open(format!("/proc/{}/cmdline", pid_str)) {
                        file.read_to_string(&mut cmdline)?;
                        cmdline = cmdline.replace('\0', " ");
                    }

                    if let Ok(file) = File::open(format!("/proc/{}/status", pid_str)) {
                        let reader = BufReader::new(file);

                        let mut name = String::new();
                        let mut pid = 0u32;
                        let mut ppid = 0u32;

                        for line in reader.lines() {
                            let line = line?;
                            let split: Vec<&str> = line.split(':').collect();

                            if split.len() >= 2 {
                                match split[0] {
                                    "Name" => name = split[1].trim().to_string(),
                                    "Pid" => pid = split[1].trim().parse()?,
                                    "PPid" => ppid = split[1].trim().parse()?,
                                    _ => {}
                                }
                            }
                        }

                        process_info.push(ProcessInfo {
                            pid,
                            ppid,
                            name,
                            cmdline,
                        });
                    }
                }
            }
        }
    }

    Ok(process_info)
}

pub fn track_process_exec() -> Result<Vec<ProcessEvent>> {
    let proc_info = get_running_processes()?;
    let mut proc_ev: Vec<ProcessEvent> = Vec::new();

    for process in proc_info {
        let mut uid = 0u32;
        if let Ok(mut file) = File::open(format!("/proc/{}/status", process.pid)) {
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
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        proc_ev.push(ProcessEvent {
            info: process,
            uid: uid,
            timestamp,
        });
    }
    println!("{proc_ev:#?}");
    Ok(proc_ev)
}

fn track_process_exit() -> Vec<ProcessExitEvent> {
    todo!()
}

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
