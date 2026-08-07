pub mod app;
pub mod detection;
pub mod gen_db;
pub mod helper;
pub mod parser;
pub mod ui;
pub mod write;

use anyhow::Result;
pub use bpfx::{file::*, network::*, process::*};
use directories::ProjectDirs;
use std::fs::{OpenOptions, create_dir, exists, read_link};
use std::path::PathBuf;
use std::sync::LazyLock;

use crate::app::FILTEREVENTS;
use crate::detection::Classified;
use crate::write::{index_path, log_path};

pub static STATE_PATH: LazyLock<Option<PathBuf>> = LazyLock::new(|| get_state_dir().unwrap());

pub fn project_directory() -> Option<ProjectDirs> {
    ProjectDirs::from("com", "", env!("CARGO_PKG_NAME"))
}

pub fn get_state_dir() -> Result<Option<PathBuf>> {
    let mut state_dir_path: Option<PathBuf> = None;
    if let Some(prj_dir) = project_directory() {
        if let Some(state_dir) = prj_dir.state_dir() {
            if !exists(state_dir)? {
                create_dir(state_dir)?;
            }
            state_dir_path = Some(state_dir.to_path_buf())
        }
    }

    Ok(state_dir_path)
}

pub fn init() -> color_eyre::Result<()> {
    tracing::info!("truncating log and index file");
    let _ = OpenOptions::new()
        .truncate(true)
        .write(true)
        .create(true)
        .open(log_path().unwrap());
    let _ = OpenOptions::new()
        .truncate(true)
        .write(true)
        .create(true)
        .open(index_path().unwrap());

    Ok(())
}

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
    ConnectEvent,
}

#[derive(
    Debug, Clone, PartialEq, PartialOrd, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub enum AppEvent {
    ProcessStart(Classified<ProcessStartEvent>),
    ProcessExit(Classified<ProcessExitEvent>),
    FileOpen(Classified<FileOpenEvent>),
    FileClose(Classified<FileCloseEvent>),
    NetworkAccept(Classified<AcceptEvent>),
    NetworkConnect(Classified<ConnectEvent>),
}

impl AppEvent {
    pub fn event_type(&mut self) -> EventType {
        match self {
            AppEvent::ProcessStart(_) => EventType::ProcessStart,
            AppEvent::ProcessExit(_) => EventType::ProcessExit,
            AppEvent::FileOpen(_) => EventType::FileOpen,
            AppEvent::FileClose(_) => EventType::FileClose,
            AppEvent::NetworkAccept(_) => EventType::AcceptEvent,
            AppEvent::NetworkConnect(_) => EventType::ConnectEvent,
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
            "NetworkConnect" => (
                matches!(self, AppEvent::NetworkConnect(_)),
                "NetworkConnect",
            ),
            _ => (false, "None"),
        }
    }

    pub fn timestamp(&self) -> u64 {
        match self {
            AppEvent::ProcessStart(e) => e.event.header.timestamp_ns,
            AppEvent::ProcessExit(e) => e.event.header.timestamp_ns,
            AppEvent::FileOpen(e) => e.event.header.timestamp_ns,
            AppEvent::FileClose(e) => e.event.header.timestamp_ns,
            AppEvent::NetworkAccept(e) => e.event.header.timestamp_ns,
            AppEvent::NetworkConnect(e) => e.event.header.timestamp_ns,
        }
    }

    pub fn pid(&self) -> u32 {
        match self {
            AppEvent::ProcessStart(e) => e.event.header.pid,
            AppEvent::ProcessExit(e) => e.event.header.pid,
            AppEvent::FileOpen(e) => e.event.header.pid,
            AppEvent::FileClose(e) => e.event.header.pid,
            AppEvent::NetworkAccept(e) => e.event.header.pid,
            AppEvent::NetworkConnect(e) => e.event.header.pid,
        }
    }

    pub fn kind_label(&self) -> &'static str {
        match self {
            AppEvent::ProcessStart(_) => "ProcessStart ",
            AppEvent::ProcessExit(_) => "ProcessExit  ",
            AppEvent::FileOpen(_) => "FileOpen ",
            AppEvent::FileClose(_) => "FileClose ",
            AppEvent::NetworkAccept(_) => "NetworkAccept  ",
            AppEvent::NetworkConnect(_) => "NetworkConnect  ",
        }
    }

    // just for testing..
    pub fn severity(&self) -> Severity {
        match self {
            AppEvent::FileOpen(e) => e.severity,
            AppEvent::NetworkAccept(e) => e.severity,
            AppEvent::ProcessStart(_) => Severity::Low,
            AppEvent::ProcessExit(_) => Severity::Info,
            AppEvent::FileClose(_) => Severity::Info,
            AppEvent::NetworkConnect(e) => e.severity,
        }
    }

    pub fn detail(&self) -> String {
        match self {
            AppEvent::ProcessStart(e) => {
                format!("exec {}", &e.event.filename)
            }
            AppEvent::ProcessExit(e) => {
                format!("pid {} exited", e.event.header.pid)
            }
            AppEvent::FileOpen(e) => e.event.file_path.clone(),
            AppEvent::FileClose(e) => {
                format!("close {}", &e.event.header.comm)
            }
            AppEvent::NetworkAccept(e) => {
                let addr = e.event.endpoints.remote_ip.to_string();
                format!("→  {addr}")
            }
            AppEvent::NetworkConnect(e) => {
                let addr = e.event.endpoints.remote_ip.to_string();
                format!("→  {addr}")
            }
        }
    }
}
