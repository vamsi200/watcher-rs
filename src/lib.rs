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
    ProcessStart,
    ProcessExit,
    FileOpen,
    FileClose,
    AcceptEvent,
}

#[derive(
    Debug, Clone, PartialEq, PartialOrd, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub enum AppEvent {
    ProcessStart(ProcessStartEvent),
    ProcessExit(ProcessExitEvent),
    FileOpen(Classified<FileOpenEvent>),
    FileClose(Classified<FileCloseEvent>),
    NetworkAccept(AcceptEvent),
}

impl AppEvent {
    pub fn event_type(&mut self) -> EventType {
        match self {
            AppEvent::ProcessStart(_) => EventType::ProcessStart,
            AppEvent::ProcessExit(_) => EventType::ProcessExit,
            AppEvent::FileOpen(_) => EventType::FileOpen,
            AppEvent::FileClose(_) => EventType::FileClose,
            AppEvent::NetworkAccept(_) => EventType::AcceptEvent,
        }
    }
    pub fn matches_filter(&self, filter_idx: usize) -> (bool, &'static str) {
        let val = FILTEREVENTS[filter_idx];
        match val {
            "All" => (true, "All"),
            "FileOpen" => (matches!(self, AppEvent::FileOpen(_)), "FileOpen"),
            "FileClose" => (matches!(self, AppEvent::FileClose(_)), "FileClose"),
            "NetworkAccept" => (matches!(self, AppEvent::NetworkAccept(_)), "NetworkAccept"),
            "ProcessStart" => (matches!(self, AppEvent::ProcessStart(_)), "ProcessStart"),
            "ProcessExit" => (matches!(self, AppEvent::ProcessExit(_)), "ProcessExit"),
            _ => (false, "None"),
        }
    }

    pub fn timestamp(&self) -> u64 {
        match self {
            AppEvent::ProcessStart(e) => e.header.timestamp_ns,
            AppEvent::ProcessExit(e) => e.header.timestamp_ns,
            AppEvent::FileOpen(e) => e.event.header.timestamp_ns,
            AppEvent::FileClose(e) => e.event.header.timestamp_ns,
            AppEvent::NetworkAccept(e) => e.header.timestamp_ns,
        }
    }

    pub fn pid(&self) -> u32 {
        match self {
            AppEvent::ProcessStart(e) => e.header.pid,
            AppEvent::ProcessExit(e) => e.header.pid,
            AppEvent::FileOpen(e) => e.event.header.pid,
            AppEvent::FileClose(e) => e.event.header.pid,
            AppEvent::NetworkAccept(e) => e.header.pid,
        }
    }

    pub fn kind_label(&self) -> &'static str {
        match self {
            AppEvent::ProcessStart(_) => "ProcessStart ",
            AppEvent::ProcessExit(_) => "ProcessExit  ",
            AppEvent::FileOpen(_) => "FileOpen ",
            AppEvent::FileClose(_) => "FileClose ",
            AppEvent::NetworkAccept(_) => "NetworkAccept  ",
        }
    }

    // just for testing..
    pub fn severity(&self) -> Severity {
        match self {
            AppEvent::FileOpen(e) => e.severity,
            AppEvent::NetworkAccept(e) => {
                if e.endpoints.local_port > 30000 {
                    Severity::Medium
                } else {
                    Severity::Low
                }
            }
            AppEvent::ProcessStart(_) => Severity::Low,
            AppEvent::ProcessExit(_) => Severity::Info,
            AppEvent::FileClose(_) => Severity::Info,
        }
    }

    pub fn detail(&self) -> String {
        match self {
            AppEvent::ProcessStart(e) => {
                format!("exec {}", &e.filename)
            }
            AppEvent::ProcessExit(e) => {
                format!("pid {} exited", e.header.pid)
            }
            AppEvent::FileOpen(e) => e.event.file_path.clone(),
            AppEvent::FileClose(e) => {
                format!("close {}", &e.event.header.comm)
            }
            AppEvent::NetworkAccept(e) => {
                let addr = e.endpoints.remote_ip.to_string();
                format!("→  {addr}")
            }
        }
    }
}
