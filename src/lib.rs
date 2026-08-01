pub mod app;
pub mod detection;
pub mod helper;
pub mod parser;
pub mod ui;
pub mod write;

pub use bpfx::{file::*, network::*, process::*};
use std::fs::read_link;
use std::path::PathBuf;

use crate::app::FILTEREVENTS;
use crate::detection::Classified;

#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct ProcessInfo {
    pub uid: u32,
    pub exe: PathBuf,
    pub comm: String,
}

pub fn get_exe(pid: u32) -> PathBuf {
    read_link(format!("/proc/{}/exe", pid)).unwrap_or_default()
}

// #[derive(
//     Debug, Clone, PartialEq, PartialOrd, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
// )]
// pub struct ProcessEvent {
//     pub info: ProcessInfo,
//     pub uid: u32,
//     pub timestamp: u64,
// }

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
    Debug,
    Clone,
    PartialEq,
    PartialOrd,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Copy,
    Eq,
    Ord,
    Hash,
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

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub enum EventType {
    ExecStart,
    ExecExit,
    FileOpen,
    FileClose,
    AcceptEvent,
}

#[derive(
    Debug, Clone, PartialEq, PartialOrd, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub enum AppEvent {
    Exec(ProcessStartEvent),
    ExecExit(ProcessExitEvent),
    File(Classified<FileOpenEvent>),
    FileClose(Classified<FileCloseEvent>),
    Network(AcceptEvent),
    // Process(ProcessEvent),
}

impl AppEvent {
    pub fn event_type(&mut self) -> EventType {
        match self {
            AppEvent::Exec(_) => EventType::ExecStart,
            AppEvent::ExecExit(_) => EventType::ExecExit,
            AppEvent::File(_) => EventType::FileOpen,
            AppEvent::FileClose(_) => EventType::FileClose,
            AppEvent::Network(_) => EventType::AcceptEvent,
        }
    }
    pub fn matches_filter(&self, filter_idx: usize) -> (bool, &'static str) {
        let val = FILTEREVENTS[filter_idx];
        match val {
            "All" => (true, "All"),
            "ExecStart" => (matches!(self, AppEvent::Exec(_)), "ExecStart"),
            "ExecExit" => (matches!(self, AppEvent::ExecExit(_)), "ExecExit"),
            "FileOpen" => (matches!(self, AppEvent::File(_)), "FileOpen"),
            "FileClose" => (matches!(self, AppEvent::FileClose(_)), "FileClose"),
            "Network" => (matches!(self, AppEvent::Network(_)), "Network"),
            // "ProcessEvent" => matches!(self, AppEvent::Process(_)),
            _ => (false, "None"),
        }
    }

    pub fn timestamp(&self) -> u64 {
        match self {
            AppEvent::Exec(e) => e.header.timestamp_ns,
            AppEvent::ExecExit(e) => e.header.timestamp_ns,
            AppEvent::File(e) => e.event.header.timestamp_ns,
            AppEvent::FileClose(e) => e.event.header.timestamp_ns,
            AppEvent::Network(e) => e.header.timestamp_ns,
            // AppEvent::Process(e) => e.timestamp,
        }
    }

    pub fn pid(&self) -> u32 {
        match self {
            AppEvent::Exec(e) => e.header.pid,
            AppEvent::ExecExit(e) => e.header.pid,
            AppEvent::File(e) => e.event.header.pid,
            AppEvent::FileClose(e) => e.event.header.pid,
            AppEvent::Network(e) => e.header.pid,
            // AppEvent::Process(e) => e.info.pid,
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
        }
    }

    // just for testing..
    pub fn severity(&self) -> Severity {
        match self {
            AppEvent::File(e) => e.severity,
            AppEvent::Network(e) => {
                if e.endpoints.local_port > 30000 {
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
            AppEvent::File(e) => e.event.file_path.clone(),
            AppEvent::FileClose(e) => {
                format!("close {}", &e.event.header.comm)
            }
            AppEvent::Network(e) => {
                let addr = e.endpoints.remote_ip.to_string(); // TODO: recheck this

                format!("→ {addr}")
            } // AppEvent::Process(e) => {
              //     format!("{} (ppid={})  {}", e.info.name, e.info.ppid, e.info.cmdline)
              // }
        }
    }
}
