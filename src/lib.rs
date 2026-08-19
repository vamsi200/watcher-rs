pub mod app;
pub mod detection;
pub mod gen_db;
pub mod helper;
pub mod ui;
pub mod write;

pub use bpfx::{file::*, network::*, process::*};
use libc::{getpwuid, uid_t};
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::fs::{self, File, OpenOptions, create_dir, exists};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::LazyLock;

use crate::app::FILTEREVENTS;
use crate::detection::{
    Classified, PATH_SEVERITY, Rules, SUSPICIOUS_EXEC_PATHS, SUSPICIOUS_PORTS, SensitivePathConfig,
    SuspiciousExecPathConfig, SuspiciousPortsConfig,
};
use crate::write::{LogConfig, index_path};

pub static STATE_PATH: LazyLock<PathBuf> = LazyLock::new(|| match get_state_dir() {
    Ok(path) => path,
    Err(e) => {
        eprintln!("failed to get state directory: {e}");
        std::process::exit(1);
    }
});

pub static CONFIG_DIR_PATH: LazyLock<PathBuf> = LazyLock::new(|| match get_config_dir() {
    Ok(path) => path,
    Err(e) => {
        eprintln!("failed to get config directory: {e}");
        std::process::exit(1);
    }
});

pub fn get_log_config() -> color_eyre::eyre::Result<LogConfig> {
    let mut file = open_config_file()?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)?;

    tracing::info!("loading config.");
    let log_config = match toml::from_str::<Config>(&buf) {
        Ok(config) => config.log_config,
        Err(_) => {
            let config = Config::default();
            write_init_config(&config, &mut file)?;
            config.log_config
        }
    };

    if !log_config.max_segment_size_mib.is_finite() || log_config.max_segment_size_mib <= 0.0 {
        return Err(color_eyre::eyre::eyre!(
            "max_segment_size_mib must be a finite value greater than 0"
        ));
    }

    if !log_config.max_storage_size_gib.is_finite() || log_config.max_storage_size_gib <= 0.0 {
        return Err(color_eyre::eyre::eyre!(
            "max_storage_size_gib must be a finite value greater than 0"
        ));
    }

    Ok(log_config)
}

pub fn open_config_file() -> color_eyre::Result<File> {
    let config_path = CONFIG_DIR_PATH.join("config.toml");

    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .open(config_path)?)
}

pub fn open_rules_file() -> color_eyre::Result<File> {
    let rules_path = CONFIG_DIR_PATH.join("rules.toml");

    Ok(OpenOptions::new().read(true).write(true).open(rules_path)?)
}

pub static RULE_CONFIG: LazyLock<Rules> = LazyLock::new(|| match write_path_config() {
    Ok(config) => config,
    Err(e) => {
        eprintln!("failed to load rule configuration: {e}");
        std::process::exit(1);
    }
});

pub fn read_path_config() -> color_eyre::eyre::Result<Rules> {
    let config_path = CONFIG_DIR_PATH.clone();

    let mut file = OpenOptions::new()
        .read(true)
        .open(config_path.join("rules.toml"))?;

    let mut buf = String::new();
    file.read_to_string(&mut buf)?;

    let rule_config = toml::from_str::<Rules>(&buf)
        .map_err(|e| color_eyre::eyre::eyre!("invalid rules.toml: {e}"))?;

    Ok(rule_config)
}

pub fn write_path_config() -> color_eyre::eyre::Result<Rules> {
    let mut file = open_rules_file()?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)?;

    let mut sensitivie_paths = std::collections::BTreeMap::new();
    let mut sus_exec_paths = BTreeMap::new();
    let mut sus_ports = BTreeMap::new();

    for (path, severity) in PATH_SEVERITY {
        sensitivie_paths
            .entry(*severity)
            .or_insert_with(Vec::new)
            .push((*path).to_string());
    }

    for (path, severity) in SUSPICIOUS_EXEC_PATHS {
        sus_exec_paths
            .entry(*severity)
            .or_insert_with(Vec::new)
            .push((*path).to_string());
    }

    for (pids, severity) in SUSPICIOUS_PORTS {
        sus_ports
            .entry(*severity)
            .or_insert_with(Vec::new)
            .push(*pids);
    }

    let sp_config = SensitivePathConfig {
        enabled: true,
        paths: sensitivie_paths,
    };

    let sus_exec_config = SuspiciousExecPathConfig {
        enabled: true,
        paths: sus_exec_paths,
    };

    let sus_port_config = SuspiciousPortsConfig {
        enabled: true,
        ports: sus_ports,
    };

    let config = Rules {
        sensitive_path: Some(sp_config),
        suspicious_exec_path: Some(sus_exec_config),
        suspicious_ports: Some(sus_port_config),
        ignore_pids: None,
        ignore_comm_name: None,
        ignore_exe_path: None,
    };

    let toml = toml::to_string_pretty(&config)?;
    let rule_config = if buf.trim().is_empty() {
        file.seek(SeekFrom::Start(0))?;
        file.set_len(0)?;
        file.write_all(toml.as_bytes())?;

        config
    } else {
        toml::from_str::<Rules>(&buf)
            .map_err(|e| color_eyre::eyre::eyre!("invalid rules.toml: {e}"))?
    };

    Ok(rule_config)
}

fn get_config_dir() -> color_eyre::eyre::Result<PathBuf> {
    let home = user_home_dir()?;

    let config_dir = home.join(".config").join(env!("CARGO_PKG_NAME"));
    if !exists(&config_dir)? {
        create_dir(&config_dir)?;
    }

    let config_dir_path = config_dir.to_path_buf();

    Ok(config_dir_path)
}

fn user_home_dir() -> color_eyre::Result<PathBuf> {
    let uid: uid_t = std::env::var("SUDO_UID")
        .ok()
        .and_then(|uid| uid.parse().ok())
        .unwrap_or_else(|| unsafe { libc::getuid() });

    let passwd = unsafe { getpwuid(uid) };

    if passwd.is_null() {
        return Err(color_eyre::eyre::eyre!(
            "Failed to resolve home directory for UID {uid}"
        ));
    }

    let home = unsafe { CStr::from_ptr((*passwd).pw_dir) };

    Ok(PathBuf::from(home.to_str()?))
}

pub fn get_state_dir() -> color_eyre::eyre::Result<PathBuf> {
    let home = user_home_dir()?;

    let state_dir = home.join(".local/state").join(env!("CARGO_PKG_NAME"));

    if !exists(&state_dir)? {
        create_dir(&state_dir)?;
    }

    Ok(state_dir)
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Config {
    pub log_config: LogConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log_config: LogConfig {
                max_segment_size_mib: 1.0,
                max_storage_size_gib: 0.5,
            },
        }
    }
}

pub fn write_init_config(config: &Config, file: &mut File) -> color_eyre::eyre::Result<()> {
    let toml = toml::to_string_pretty(&config)?;
    file.write_all(toml.as_bytes())?;

    Ok(())
}

pub fn init() -> color_eyre::eyre::Result<()> {
    tracing::info!("truncating log and index file");
    let state_path = STATE_PATH.clone();

    for entry in fs::read_dir(state_path)? {
        let entry = entry?;
        let path = entry.path();

        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("events.bin."))
        {
            fs::remove_file(path)?;
        }
    }

    let _ = OpenOptions::new()
        .truncate(true)
        .write(true)
        .create(true)
        .open(index_path()?);

    Ok(())
}

#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct ProcessInfo {
    pub uid: u32,
    pub exe: PathBuf,
    pub comm: String,
}

pub fn read_exe(pid: u32) -> PathBuf {
    std::fs::read_link(format!("/proc/{pid}/exe")).unwrap_or_default()
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
    serde::Deserialize,
    serde::Serialize,
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
            Severity::Info => "INFO ",
            Severity::Low => "LOW ",
            Severity::Medium => "MED ",
            Severity::High => "HIGH ",
            Severity::Critical => "CRIT ",
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub enum EventType {
    ProcessStart,
    ProcessExit,
    ProcessFork,
    FileOpen,
    FileClose,
    FileDelete,
    FileRead,
    FileRename,
    FileWrite,
    NetworkAccept,
    NetworkConnect,
    NetworkBind,
    NetworkClose,
    NetworkListen,
}

#[derive(
    Debug, Clone, PartialEq, PartialOrd, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub enum AppEvent {
    ProcessStart(Classified<ProcessStartEvent>),
    ProcessExit(Classified<ProcessExitEvent>),
    ProcessFork(Classified<ProcessForkEvent>),
    FileOpen(Classified<FileOpenEvent>),
    FileClose(Classified<FileCloseEvent>),
    FileDelete(Classified<FileDeleteEvent>),
    FileRead(Classified<FileReadEvent>),
    FileRename(Classified<FileRenameEvent>),
    FileWrite(Classified<FileWriteEvent>),
    NetworkAccept(Classified<AcceptEvent>),
    NetworkConnect(Classified<ConnectEvent>),
    NetworkBind(Classified<BindEvent>),
    NetworkClose(Classified<CloseEvent>),
    NetworkListen(Classified<ListenEvent>),
}

impl AppEvent {
    pub fn rule_name(&self) -> &[String] {
        match self {
            AppEvent::ProcessStart(e) => e.matched_rules.as_slice(),
            AppEvent::ProcessExit(e) => e.matched_rules.as_slice(),
            AppEvent::ProcessFork(e) => e.matched_rules.as_slice(),
            AppEvent::FileOpen(e) => e.matched_rules.as_slice(),
            AppEvent::FileClose(e) => e.matched_rules.as_slice(),
            AppEvent::FileDelete(e) => e.matched_rules.as_slice(),
            AppEvent::FileRead(e) => e.matched_rules.as_slice(),
            AppEvent::FileRename(e) => e.matched_rules.as_slice(),
            AppEvent::FileWrite(e) => e.matched_rules.as_slice(),
            AppEvent::NetworkAccept(e) => e.matched_rules.as_slice(),
            AppEvent::NetworkConnect(e) => e.matched_rules.as_slice(),
            AppEvent::NetworkBind(e) => e.matched_rules.as_slice(),
            AppEvent::NetworkClose(e) => e.matched_rules.as_slice(),
            AppEvent::NetworkListen(e) => e.matched_rules.as_slice(),
        }
    }

    pub fn event_type(&mut self) -> EventType {
        match self {
            AppEvent::ProcessStart(_) => EventType::ProcessStart,
            AppEvent::ProcessExit(_) => EventType::ProcessExit,
            AppEvent::ProcessFork(_) => EventType::ProcessFork,
            AppEvent::FileOpen(_) => EventType::FileOpen,
            AppEvent::FileClose(_) => EventType::FileClose,
            AppEvent::FileDelete(_) => EventType::FileClose,
            AppEvent::FileRead(_) => EventType::FileClose,
            AppEvent::FileRename(_) => EventType::FileClose,
            AppEvent::FileWrite(_) => EventType::FileWrite,
            AppEvent::NetworkAccept(_) => EventType::NetworkAccept,
            AppEvent::NetworkConnect(_) => EventType::NetworkConnect,
            AppEvent::NetworkBind(_) => EventType::NetworkBind,
            AppEvent::NetworkClose(_) => EventType::NetworkClose,
            AppEvent::NetworkListen(_) => EventType::NetworkListen,
        }
    }

    pub fn matches_filter(&self, filter_idx: usize) -> bool {
        let val = FILTEREVENTS[filter_idx];
        match val {
            "FileOpen" => matches!(self, AppEvent::FileOpen(_)),
            "FileClose" => matches!(self, AppEvent::FileClose(_)),
            "FileDelete" => matches!(self, AppEvent::FileDelete(_)),
            "FileRename" => matches!(self, AppEvent::FileRename(_)),
            "FileRead" => matches!(self, AppEvent::FileRead(_)),
            "FileWrite" => matches!(self, AppEvent::FileWrite(_)),

            "ProcessStart" => matches!(self, AppEvent::ProcessStart(_)),
            "ProcessExit" => matches!(self, AppEvent::ProcessExit(_)),
            "ProcessFork" => matches!(self, AppEvent::ProcessFork(_)),

            "NetworkAccept" => matches!(self, AppEvent::NetworkAccept(_)),
            "NetworkConnect" => matches!(self, AppEvent::NetworkConnect(_)),
            "NetworkBind" => matches!(self, AppEvent::NetworkBind(_)),
            "NetworkListen" => matches!(self, AppEvent::NetworkListen(_)),
            "NetworkClose" => matches!(self, AppEvent::NetworkClose(_)),

            _ => false,
        }
    }

    pub fn timestamp(&self) -> u64 {
        match self {
            AppEvent::ProcessStart(e) => e.event.header.timestamp_ns,
            AppEvent::ProcessExit(e) => e.event.header.timestamp_ns,
            AppEvent::ProcessFork(e) => e.event.parent.timestamp_ns,
            AppEvent::FileOpen(e) => e.event.header.timestamp_ns,
            AppEvent::FileClose(e) => e.event.header.timestamp_ns,
            AppEvent::FileDelete(e) => e.event.header.timestamp_ns,
            AppEvent::FileRead(e) => e.event.header.timestamp_ns,
            AppEvent::FileRename(e) => e.event.header.timestamp_ns,
            AppEvent::FileWrite(e) => e.event.header.timestamp_ns,
            AppEvent::NetworkAccept(e) => e.event.header.timestamp_ns,
            AppEvent::NetworkConnect(e) => e.event.header.timestamp_ns,
            AppEvent::NetworkBind(e) => e.event.header.timestamp_ns,
            AppEvent::NetworkClose(e) => e.event.header.timestamp_ns,
            AppEvent::NetworkListen(e) => e.event.header.timestamp_ns,
        }
    }

    pub fn pid(&self) -> u32 {
        match self {
            AppEvent::ProcessStart(e) => e.event.header.pid,
            AppEvent::ProcessExit(e) => e.event.header.pid,
            AppEvent::ProcessFork(e) => e.event.parent.pid,
            AppEvent::FileOpen(e) => e.event.header.pid,
            AppEvent::FileClose(e) => e.event.header.pid,
            AppEvent::FileDelete(e) => e.event.header.pid,
            AppEvent::FileRead(e) => e.event.header.pid,
            AppEvent::FileRename(e) => e.event.header.pid,
            AppEvent::FileWrite(e) => e.event.header.pid,

            AppEvent::NetworkAccept(e) => e.event.header.pid,
            AppEvent::NetworkConnect(e) => e.event.header.pid,
            AppEvent::NetworkBind(e) => e.event.header.pid,
            AppEvent::NetworkClose(e) => e.event.header.pid,
            AppEvent::NetworkListen(e) => e.event.header.pid,
        }
    }

    pub fn kind_label(&self) -> &'static str {
        match self {
            AppEvent::ProcessStart(_) => "ProcessStart ",
            AppEvent::ProcessExit(_) => "ProcessExit  ",
            AppEvent::ProcessFork(_) => "ProcessFork  ",
            AppEvent::FileOpen(_) => "FileOpen ",
            AppEvent::FileClose(_) => "FileClose ",
            AppEvent::FileDelete(_) => "FileDelete ",
            AppEvent::FileRead(_) => "FileRead ",
            AppEvent::FileRename(_) => "FileRename ",
            AppEvent::FileWrite(_) => "FileWrite ",

            AppEvent::NetworkAccept(_) => "NetworkAccept  ",
            AppEvent::NetworkConnect(_) => "NetworkConnect  ",
            AppEvent::NetworkBind(_) => "NetworkBind  ",
            AppEvent::NetworkClose(_) => "NetworkClose  ",
            AppEvent::NetworkListen(_) => "NetworkListen  ",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            AppEvent::FileOpen(e) => e.severity,
            AppEvent::FileClose(e) => e.severity,
            AppEvent::FileDelete(e) => e.severity,
            AppEvent::FileRead(e) => e.severity,
            AppEvent::FileRename(e) => e.severity,
            AppEvent::FileWrite(e) => e.severity,

            AppEvent::ProcessStart(e) => e.severity,
            AppEvent::ProcessExit(e) => e.severity,
            AppEvent::ProcessFork(e) => e.severity,

            AppEvent::NetworkAccept(e) => e.severity,
            AppEvent::NetworkConnect(e) => e.severity,
            AppEvent::NetworkBind(e) => e.severity,
            AppEvent::NetworkClose(e) => e.severity,
            AppEvent::NetworkListen(e) => e.severity,
        }
    }

    pub fn detail(&self) -> String {
        match self {
            AppEvent::ProcessStart(e) => {
                format!("exec: {}", e.event.filename)
            }
            AppEvent::ProcessExit(e) => {
                format!("exit: pid {}", e.event.header.pid)
            }
            AppEvent::ProcessFork(e) => {
                format!("fork: {} -> {}", e.event.parent.pid, e.event.child_pid)
            }

            AppEvent::FileOpen(e) => {
                format!("open: {}", e.event.file_path)
            }
            AppEvent::FileClose(e) => {
                format!("close: {}", e.event.header.comm)
            }
            AppEvent::FileDelete(e) => {
                format!("delete: {}", e.event.filename)
            }
            AppEvent::FileRead(e) => {
                format!("read: {}", e.event.file_path)
            }
            AppEvent::FileRename(e) => {
                format!(
                    "rename: {} -> {}",
                    e.event.old_filename, e.event.new_filename
                )
            }
            AppEvent::FileWrite(e) => {
                format!("write: {}", e.event.file_path)
            }

            AppEvent::NetworkAccept(e) => {
                format!("accept: {}", e.event.endpoints.remote_ip)
            }
            AppEvent::NetworkConnect(e) => {
                format!("connect: {}", e.event.endpoints.remote_ip)
            }
            AppEvent::NetworkBind(e) => {
                format!("bind: {}", e.event.endpoints.remote_ip)
            }
            AppEvent::NetworkClose(e) => {
                format!("close: {}", e.event.endpoints.remote_ip)
            }
            AppEvent::NetworkListen(e) => {
                format!("listen: {}", e.event.endpoints.remote_ip)
            }
        }
    }
}
