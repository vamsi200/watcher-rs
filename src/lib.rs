pub mod app;
pub mod detection;
pub mod helper;
pub mod parser;
pub mod ui;
pub mod write;

use crate::helper::*;
use bpfx::file::{FileCloseEvent, FileOpenEvent};
use bpfx::network::AcceptEvent;
use bpfx::process::{ProcessExitEvent, ProcessStartEvent};
use std::fs::File;
use std::io::Read;
use std::io::{BufRead, BufReader};

#[derive(
    Debug, Clone, PartialEq, PartialOrd, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
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
            let reader = BufReader::new(file);
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

#[derive(
    Debug, Clone, PartialEq, PartialOrd, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct ProcessEvent {
    pub info: ProcessInfo,
    pub uid: u32,
    pub timestamp: u64,
}

#[derive(
    Debug, Clone, PartialEq, PartialOrd, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct PrivilegeEvent {
    pub pid: u32,
    pub uid: u32,
    pub binary: String,
    pub is_setuid: bool,
    pub timestamp: u64,
}

#[derive(
    Debug, Clone, PartialEq, PartialOrd, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct SuspiciousEvent {
    pub pid: u32,
    pub file: String,
    pub reason: String,
    pub severity: Severity,
    pub timestamp: u64,
}

#[derive(
    Debug, Clone, PartialEq, PartialOrd, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
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

#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub enum AppEvent {
    Exec(ProcessStartEvent),
    ExecExit(ProcessExitEvent),
    File(FileOpenEvent),
    FileClose(FileCloseEvent),
    Network(AcceptEvent),
    // Process(ProcessEvent),
    Privilege(PrivilegeEvent),
    Suspicious(SuspiciousEvent),
}

impl AppEvent {
    pub fn matches_filter(&self, filter: &str) -> bool {
        match filter {
            "All" => true,
            "ExecEvent" => matches!(self, AppEvent::Exec(_)),
            "ExecExitEvent" => matches!(self, AppEvent::ExecExit(_)),
            "FileEvent" => matches!(self, AppEvent::File(_)),
            "FileCloseEvent" => matches!(self, AppEvent::FileClose(_)),
            "NetworkEvent" => matches!(self, AppEvent::Network(_)),
            // "ProcessEvent" => matches!(self, AppEvent::Process(_)),
            "PrivilegeEvent" => matches!(self, AppEvent::Privilege(_)),
            "SuspiciousEvent" => matches!(self, AppEvent::Suspicious(_)),
            _ => false,
        }
    }

    pub fn timestamp(&self) -> u64 {
        match self {
            AppEvent::Exec(e) => e.header.timestamp_ns,
            AppEvent::ExecExit(e) => e.header.timestamp_ns,
            AppEvent::File(e) => e.header.timestamp_ns,
            AppEvent::FileClose(e) => e.header.timestamp_ns,
            AppEvent::Network(e) => e.header.timestamp_ns,
            // AppEvent::Process(e) => e.timestamp,
            AppEvent::Privilege(e) => e.timestamp,
            AppEvent::Suspicious(e) => e.timestamp,
        }
    }

    pub fn pid(&self) -> u32 {
        match self {
            AppEvent::Exec(e) => e.header.pid,
            AppEvent::ExecExit(e) => e.header.pid,
            AppEvent::File(e) => e.header.pid,
            AppEvent::FileClose(e) => e.header.pid,
            AppEvent::Network(e) => e.header.pid,
            // AppEvent::Process(e) => e.info.pid,
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
            // AppEvent::Process(_) => "ProcEvent ",
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
            AppEvent::File(_) => Severity::Low,
            AppEvent::Network(e) => {
                if e.endpoints.local_port > 30000 {
                    // TODO: recheck this
                    Severity::Medium
                } else {
                    Severity::Low
                }
            }
            AppEvent::Exec(_) => Severity::Low,
            AppEvent::ExecExit(_) => Severity::Info,
            AppEvent::FileClose(_) => Severity::Info,
            // AppEvent::Process(_) => Severity::Info,
        }
    }

    pub fn detail(&self) -> String {
        match self {
            AppEvent::Exec(e) => {
                format!("exec {}", &e.filename)
            }
            AppEvent::ExecExit(e) => {
                format!("pid {} exited", e.header.pid)
            }
            AppEvent::File(e) => {
                let op = &e.flags;
                let name = &e.filename;
                format!("{op} {name}  mode={:?}", &e.file_type)
            }
            AppEvent::FileClose(e) => {
                format!("close {}", &e.header.comm)
            }
            AppEvent::Network(e) => {
                let addr = e.endpoints.remote_ip.to_string(); // TODO: recheck this

                format!("→ {addr}")
            }
            // AppEvent::Process(e) => {
            //     format!("{} (ppid={})  {}", e.info.name, e.info.ppid, e.info.cmdline)
            // }
            AppEvent::Privilege(e) => {
                let flag = if e.is_setuid { "setuid" } else { "setgid" };
                format!("{flag} exec {}", e.binary)
            }
            AppEvent::Suspicious(e) => {
                format!("[{}] {}", e.file, e.reason)
            }
        }
    }
}
