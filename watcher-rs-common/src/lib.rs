#![allow(unused)]
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;

use crate::helper::{bytes_to_str, flags_to_op, parse_addr};
pub mod helper;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub cmdline: String,
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

#[derive(Debug, Clone)]
pub struct ProcessEvent {
    pub info: ProcessInfo,
    pub uid: u32,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct PrivilegeEvent {
    pub pid: u32,
    pub uid: u32,
    pub binary: PathBuf,
    pub is_setuid: bool,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct SuspiciousEvent {
    pub pid: u32,
    pub file: String,
    pub reason: String,
    pub severity: Severity,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}
impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW ",
            Severity::Medium => "MED ",
            Severity::High => "HIGH",
            Severity::Critical => "CRIT",
        }
    }
}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ExecEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub timestamp: u64,
    pub filename: [u8; 256],
}

#[repr(u32)]
#[derive(Debug)]
pub enum EventType {
    ExecEvent = 0,
    ExecExit = 1,
    FileOpen = 2,
    FileClose = 3,
    Network = 4,
}

#[repr(C)]
pub struct EventHeader {
    pub kind: u32,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FileEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub dir_fd: i32,
    pub filename: [u8; 256],
    pub mode: i32,
    pub flags: i32,
    pub timestamp: u64,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct SockAddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: [u8; 4],
    pub _pad: [u8; 8],
}

#[repr(C)]
pub struct SockaddrIn6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: [u8; 16],
    pub sin6_scope_id: u32,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct NetworkEvent {
    pub kind: u32,
    pub pid: u32,
    pub sockfd: i32,
    pub family: u16,
    pub port: u16,
    pub addr: [u8; 16],
    pub timestamp: u64,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct ProcessExitEvent {
    pub kind: u32,
    pub pid: u32,
    pub timestamp: u64,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FileCloseEvent {
    pub kind: u32,
    pub file_name: [u8; 256],
    pub pid: u32,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub enum AppEvent {
    Exec(ExecEvent),
    ExecExit(ProcessExitEvent),
    File(FileEvent),
    FileClose(FileCloseEvent),
    Network(NetworkEvent),
    Process(ProcessEvent),
    Privilege(PrivilegeEvent),
    Suspicious(SuspiciousEvent),
}

impl AppEvent {
    pub fn timestamp(&self) -> u64 {
        match self {
            AppEvent::Exec(e) => e.timestamp,
            AppEvent::ExecExit(e) => e.timestamp,
            AppEvent::File(e) => e.timestamp,
            AppEvent::FileClose(e) => e.timestamp,
            AppEvent::Network(e) => e.timestamp,
            AppEvent::Process(e) => e.timestamp,
            AppEvent::Privilege(e) => e.timestamp,
            AppEvent::Suspicious(e) => e.timestamp,
        }
    }

    pub fn pid(&self) -> u32 {
        match self {
            AppEvent::Exec(e) => e.pid,
            AppEvent::ExecExit(e) => e.pid,
            AppEvent::File(e) => e.pid,
            AppEvent::FileClose(e) => e.pid,
            AppEvent::Network(e) => e.pid,
            AppEvent::Process(e) => e.info.pid,
            AppEvent::Privilege(e) => e.pid,
            AppEvent::Suspicious(e) => e.pid,
        }
    }

    pub fn kind_label(&self) -> &'static str {
        match self {
            AppEvent::Exec(_) => "ExecEvent ",
            AppEvent::ExecExit(_) => "ExecExit  ",
            AppEvent::File(_) => "FileEvent ",
            AppEvent::FileClose(_) => "FileClose ",
            AppEvent::Network(_) => "NetEvent  ",
            AppEvent::Process(_) => "ProcEvent ",
            AppEvent::Privilege(_) => "PrivEvent ",
            AppEvent::Suspicious(_) => "Suspicious",
        }
    }

    // just for testing..
    pub fn severity(&self) -> Severity {
        match self {
            AppEvent::Suspicious(e) => e.severity.clone(),
            AppEvent::Privilege(e) => {
                if e.is_setuid {
                    Severity::High
                } else {
                    Severity::Medium
                }
            }
            AppEvent::File(e) => Severity::Low,
            AppEvent::Network(e) => {
                if e.port > 30000 {
                    Severity::Medium
                } else {
                    Severity::Low
                }
            }
            AppEvent::Exec(_) => Severity::Low,
            AppEvent::ExecExit(_) => Severity::Info,
            AppEvent::FileClose(_) => Severity::Info,
            AppEvent::Process(_) => Severity::Info,
        }
    }

    pub fn detail(&self) -> String {
        match self {
            AppEvent::Exec(e) => {
                format!("exec {}", bytes_to_str(&e.filename))
            }
            AppEvent::ExecExit(e) => {
                format!("pid {} exited", e.pid)
            }
            AppEvent::File(e) => {
                let op = flags_to_op(e.flags);
                let name = bytes_to_str(&e.filename);
                format!("{op} {name}  mode={:o}", e.mode)
            }
            AppEvent::FileClose(e) => {
                format!("close {}", bytes_to_str(&e.file_name))
            }
            AppEvent::Network(e) => {
                let addr = parse_addr(e.family, &e.addr);
                format!("→ {addr}  fd={}", e.sockfd)
            }
            AppEvent::Process(e) => {
                format!("{} (ppid={})  {}", e.info.name, e.info.ppid, e.info.cmdline)
            }
            AppEvent::Privilege(e) => {
                let flag = if e.is_setuid { "setuid" } else { "setgid" };
                format!("{flag} exec {}", e.binary.display())
            }
            AppEvent::Suspicious(e) => {
                format!("[{}] {}", e.file, e.reason)
            }
        }
    }
}
