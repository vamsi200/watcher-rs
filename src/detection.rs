#![allow(unused)]
use crate::helper::{bytes_to_str, check_path, is_root_only_path, parse_addr};
use crate::*;
use crate::{PrivilegeEvent, Severity, helper::is_sensitive_path};
use bpfx::EventHeader;
use bpfx::{FileEvent, process::ProcessStartEvent};
use futures::lock::Mutex;
use libc::O_TRUNC;
use lru::LruCache;
use std::collections::{HashMap, HashSet, VecDeque};
use std::num::NonZeroUsize;
use std::os::unix::fs::PermissionsExt;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use std::{
    fs::{self, File},
    path::{self, PathBuf},
};

pub struct FileEventFilter {
    filter: LruCache<FileKey, Aggregate>,
}

impl FileEventFilter {
    pub fn new() -> Self {
        let lru_cache: LruCache<FileKey, Aggregate> =
            LruCache::new(NonZeroUsize::new(4096).unwrap());

        Self { filter: lru_cache }
    }

    pub fn should_drop(&mut self, event: &FileEvent, file_key: FileKey) -> bool {
        if std::process::id() == event.process().pid {
            return true;
        }

        let now = Instant::now();
        match self.filter.get_mut(&file_key) {
            Some(val) => {
                if val.last_seen.elapsed() < Duration::from_secs(1) {
                    val.count += 1;
                    val.last_seen = now;
                    return true;
                }
                val.last_seen = now;
                val.count += 1;
                return false;
            }

            None => {
                self.filter.put(
                    file_key,
                    Aggregate {
                        last_seen: now,
                        count: 1,
                    },
                );
                return false;
            }
        }

        // if event.file_path().is_some_and(|x| check_path(x)) {
        //     return false;
        // }
        //
        false
    }
}

#[derive(Hash, PartialEq, PartialOrd, Ord, Eq)]
pub enum KeyVal {
    Path(String),
    Inode(u64),
}

#[derive(Hash, PartialEq, PartialOrd, Ord, Eq)]
pub struct FileKey {
    pub pid: u32,
    pub tid: u32,
    pub key: KeyVal,
}

pub struct Aggregate {
    last_seen: Instant,
    count: u64,
}

const HIGH_FREQ_THRESHOLD: usize = 50;
const MED_FREQ_THRESHOLD: usize = 20;
const HIGH_CONN_THRESHOLD: usize = 100;
const MED_CONN_THRESHOLD: usize = 40;
const TIME_WINDOW_NS: u64 = 1_000_000_000;

const SENSITIVE_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/root/",
    "/.ssh/",
    "/proc/",
    "/sys/kernel/",
    "/boot/",
];

pub const PATH_SEVERITY: &[(&str, Severity)] = &[
    // Critical
    ("/etc/shadow", Severity::Critical),
    ("/etc/gshadow", Severity::Critical),
    ("/etc/sudoers", Severity::Critical),
    ("/etc/sudoers.d/", Severity::Critical),
    ("/etc/ssh/sshd_config", Severity::Critical),
    ("/etc/ld.so.preload", Severity::Critical),
    ("/etc/crontab", Severity::Critical),
    ("/etc/systemd/system/", Severity::Critical),
    ("/etc/systemd/user/", Severity::Critical),
    ("/boot/", Severity::Critical),
    ("/boot/efi/", Severity::Critical),
    ("/root/.ssh/", Severity::Critical),
    ("/root/.gnupg/", Severity::Critical),
    // High
    ("/etc/passwd", Severity::High),
    ("/etc/group", Severity::High),
    ("/etc/hosts", Severity::High),
    ("/etc/resolv.conf", Severity::High),
    ("/etc/fstab", Severity::High),
    ("/etc/pam.d/", Severity::High),
    ("/etc/profile", Severity::High),
    ("/etc/profile.d/", Severity::High),
    ("/etc/environment", Severity::High),
    ("/etc/bash.bashrc", Severity::High),
    ("/etc/zsh/", Severity::High),
    ("/usr/bin/", Severity::High),
    ("/usr/sbin/", Severity::High),
    ("/bin/", Severity::High),
    ("/sbin/", Severity::High),
    ("/lib/", Severity::High),
    ("/lib64/", Severity::High),
    ("/usr/lib/", Severity::High),
    ("/usr/lib64/", Severity::High),
    ("/var/spool/cron/", Severity::High),
    ("/var/lib/systemd/", Severity::High),
    // Medium
    ("/home/", Severity::Medium),
    ("/root/", Severity::Medium),
    ("/.ssh/", Severity::Medium),
    ("/.gnupg/", Severity::Medium),
    ("/.config/autostart/", Severity::Medium),
    ("/tmp/", Severity::Medium),
    ("/var/tmp/", Severity::Medium),
    ("/dev/shm/", Severity::Medium),
    ("/run/user/", Severity::Medium),
    ("/opt/", Severity::Medium),
    ("/srv/", Severity::Medium),
    // Low
    ("/proc/", Severity::Low),
    ("/sys/", Severity::Low),
    ("/dev/", Severity::Low),
    ("/run/", Severity::Low),
    ("/var/cache/", Severity::Low),
    ("/var/log/", Severity::Low),
    ("/var/lib/", Severity::Low),
];

const SUSPICIOUS_FLAGS: &[(i32, &str)] = &[
    (libc::O_WRONLY | libc::O_TRUNC, "truncating sensitive file"),
    (libc::O_RDWR | libc::O_CREAT, "creating file with RW access"),
    (libc::O_WRONLY | libc::O_APPEND, "appending to file"),
];

const SUSPICIOUS_PORTS: &[(u16, &str, Severity)] = &[
    (22, "ssh", Severity::High),
    (4444, "Metasploit default listener", Severity::High),
    (1337, "Common backdoor port", Severity::High),
    (31337, "Elite/Back Orifice backdoor", Severity::High),
    (9001, "Tor relay port", Severity::Medium),
    (9050, "Tor SOCKS proxy port", Severity::Medium),
    (6667, "IRC (common C2 channel)", Severity::Medium),
    (23, "Telnet - unencrypted remote access", Severity::Medium),
    (512, "rexec - unauthenticated exec", Severity::High),
    (513, "rlogin - unauthenticated login", Severity::High),
];

const INPUT_DEVICE_PATHS: &[(&str, &str, Severity)] = &[
    (
        "/dev/input/",
        "Raw input device access (possible keylogger)",
        Severity::High,
    ),
    ("/dev/tty", "TTY device access", Severity::Medium),
    ("/dev/pts/", "Pseudo-terminal access", Severity::Medium),
    ("/dev/hidraw", "Raw HID device access", Severity::High),
    (
        "/dev/uinput",
        "uinput device (can inject input events)",
        Severity::High,
    ),
    (
        "/dev/input/mice",
        "Mouse aggregator device",
        Severity::Medium,
    ),
    ("/dev/input/mouse", "Raw mouse device", Severity::Medium),
    (
        "/dev/input/event",
        "Raw keyboard/input event device",
        Severity::High,
    ),
];

const SUSPICIOUS_INPUT_FLAGS: &[(i32, &str)] = &[
    (
        libc::O_WRONLY,
        "Write access to input device (input injection)",
    ),
    (libc::O_RDWR, "Read-write access to input device"),
];

const HIGH_READ_THRESHOLD: usize = 200;
const MED_READ_THRESHOLD: usize = 80;

pub struct RuleContext<'a> {
    pub process_cache: &'a HashMap<u32, ProcessInfo>,
}

#[derive(
    Debug, Clone, PartialEq, PartialOrd, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct Classified<T> {
    pub event: T,
    pub severity: Severity,
    pub matched_rules: Vec<String>,
}

type ClassifiedFileOpenEvent = Classified<FileOpenEvent>;
type ClassifiedFileCloseEvent = Classified<FileCloseEvent>;
type ClassifiedProcessStartEvent = Classified<ProcessStartEvent>;

//TODO: Refactor later to just match enum
pub trait Rule: Send + Sync {
    fn name(&self) -> &'static str;
    fn check_open(&self, event: &FileOpenEvent, ctx: &RuleContext) -> Option<Severity>;
    fn check_close(&self, event: &FileCloseEvent, ctx: &RuleContext) -> Option<Severity>;
    fn check_process_start(&self, event: &ProcessStartEvent, ctx: &RuleContext)
    -> Option<Severity>;
    fn check_process_exit(&self, event: &ProcessExitEvent, ctx: &RuleContext) -> Option<Severity>;
}

pub struct RuleEngine {
    pub rules: Vec<Box<dyn Rule>>,
}

impl RuleEngine {
    pub fn classify_open(
        &self,
        event: FileOpenEvent,
        ctx: RuleContext,
    ) -> Classified<FileOpenEvent> {
        let mut severity = Severity::Low;
        let mut matched_rules = Vec::new();

        for rule in &self.rules {
            if let Some(sev) = rule.check_open(&event, &ctx) {
                severity = severity.max(sev);
                matched_rules.push(rule.name().to_owned());
            }
        }

        Classified {
            event,
            severity,
            matched_rules,
        }
    }

    pub fn classify_close(
        &self,
        event: FileCloseEvent,
        ctx: RuleContext,
    ) -> Classified<FileCloseEvent> {
        let mut severity = Severity::Low;
        let mut matched_rules = Vec::new();

        for rule in &self.rules {
            if let Some(sev) = rule.check_close(&event, &ctx) {
                severity = severity.max(sev);
                matched_rules.push(rule.name().to_owned());
            }
        }

        Classified {
            event,
            severity,
            matched_rules,
        }
    }

    pub fn classify_process_start(
        &self,
        event: ProcessStartEvent,
        ctx: RuleContext,
    ) -> Classified<ProcessStartEvent> {
        let mut severity = Severity::Low;
        let mut matched_rules = Vec::new();

        for rule in &self.rules {
            if let Some(sev) = rule.check_process_start(&event, &ctx) {
                severity = severity.max(sev);
                matched_rules.push(rule.name().to_owned());
            }
        }

        Classified {
            event,
            severity,
            matched_rules,
        }
    }
}

trait FileEventCommon {
    fn header(&self) -> &EventHeader;
    fn file_path(&self) -> &str;
    fn file_type(&self) -> &FileType;
    fn inode(&self) -> u64;
    fn retval(&self) -> i32;
    fn flags(&self) -> u32;
    fn flags_str(&self) -> String;
    fn is_write(&self) -> bool;
}

impl FileEventCommon for FileOpenEvent {
    fn header(&self) -> &EventHeader {
        &self.header
    }

    fn file_path(&self) -> &str {
        &self.file_path
    }

    fn file_type(&self) -> &FileType {
        &self.file_type
    }

    fn inode(&self) -> u64 {
        self.inode
    }

    fn retval(&self) -> i32 {
        self.retval
    }

    fn flags(&self) -> u32 {
        self.flags
    }

    fn flags_str(&self) -> String {
        self.flags()
    }

    fn is_write(&self) -> bool {
        self.is_write()
    }
}

impl FileEventCommon for FileCloseEvent {
    fn header(&self) -> &EventHeader {
        &self.header
    }

    fn file_path(&self) -> &str {
        &self.file_path
    }

    fn file_type(&self) -> &FileType {
        &self.file_type
    }

    fn inode(&self) -> u64 {
        self.inode
    }

    fn retval(&self) -> i32 {
        self.retval
    }

    fn flags(&self) -> u32 {
        self.flags
    }

    fn flags_str(&self) -> String {
        self.flags()
    }

    fn is_write(&self) -> bool {
        self.is_write()
    }
}

pub struct SensitivePathRule;

impl SensitivePathRule {
    fn check<T>(&self, event: &T, ctx: &RuleContext) -> Option<Severity>
    where
        T: FileEventCommon,
    {
        PATH_SEVERITY
            .iter()
            .filter_map(|(name, sev)| {
                if event.file_path().starts_with(name) {
                    Some(sev)
                } else {
                    None
                }
            })
            .next()
            .copied()
    }
}

impl Rule for SensitivePathRule {
    fn name(&self) -> &'static str {
        "SensitivePath"
    }

    fn check_open(&self, event: &FileOpenEvent, ctx: &RuleContext) -> Option<Severity> {
        self.check(event, ctx)
    }

    fn check_close(&self, event: &FileCloseEvent, ctx: &RuleContext) -> Option<Severity> {
        self.check(event, ctx)
    }

    fn check_process_start(
        &self,
        event: &ProcessStartEvent,
        ctx: &RuleContext,
    ) -> Option<Severity> {
        None
    }

    fn check_process_exit(&self, event: &ProcessExitEvent, ctx: &RuleContext) -> Option<Severity> {
        None
    }
}

pub struct FlagRule;

impl FlagRule {
    fn check<T>(&self, event: &T, ctx: &RuleContext) -> Option<Severity>
    where
        T: FileEventCommon,
    {
        match event.flags_str().as_str() {
            "RDONLY" => Some(Severity::Low),
            "WRONLY" => Some(Severity::Medium),
            "RDWR" => Some(Severity::Medium),
            "CREAT" => Some(Severity::Medium),
            "TRUNC" => Some(Severity::High),
            _ => Some(Severity::Info),
        }
    }
}

impl Rule for FlagRule {
    fn name(&self) -> &'static str {
        "SensitiveFlag"
    }

    fn check_open(&self, event: &FileOpenEvent, ctx: &RuleContext) -> Option<Severity> {
        self.check(event, ctx)
    }

    fn check_close(&self, event: &FileCloseEvent, ctx: &RuleContext) -> Option<Severity> {
        self.check(event, ctx)
    }

    fn check_process_exit(&self, event: &ProcessExitEvent, ctx: &RuleContext) -> Option<Severity> {
        None
    }

    fn check_process_start(
        &self,
        event: &ProcessStartEvent,
        ctx: &RuleContext,
    ) -> Option<Severity> {
        None
    }
}

pub struct RootWriteRule;

impl RootWriteRule {
    fn check<T>(&self, event: &T, _: &RuleContext) -> Option<Severity>
    where
        T: FileEventCommon,
    {
        if event.header().uid == 0 && event.is_write() {
            Some(Severity::High)
        } else {
            None
        }
    }
}

impl Rule for RootWriteRule {
    fn name(&self) -> &'static str {
        "RootWrite"
    }

    fn check_open(&self, event: &FileOpenEvent, ctx: &RuleContext) -> Option<Severity> {
        self.check(event, ctx)
    }

    fn check_close(&self, event: &FileCloseEvent, ctx: &RuleContext) -> Option<Severity> {
        self.check(event, ctx)
    }

    fn check_process_start(
        &self,
        event: &ProcessStartEvent,
        ctx: &RuleContext,
    ) -> Option<Severity> {
        None
    }

    fn check_process_exit(&self, event: &ProcessExitEvent, ctx: &RuleContext) -> Option<Severity> {
        None
    }
}

pub struct TempExecutableRule;

impl TempExecutableRule {
    fn check<T>(&self, event: &T, ctx: &RuleContext) -> Option<Severity>
    where
        T: FileEventCommon,
    {
        let Some(proc) = ctx.process_cache.get(&event.header().pid) else {
            return None;
        };

        if proc.exe.starts_with("/tmp") || proc.exe.starts_with("/dev/shm") {
            Some(Severity::High)
        } else {
            Some(Severity::Low)
        }
    }
}

impl Rule for TempExecutableRule {
    fn name(&self) -> &'static str {
        "TempExecutable"
    }

    fn check_open(&self, event: &FileOpenEvent, ctx: &RuleContext) -> Option<Severity> {
        self.check(event, ctx)
    }

    fn check_close(&self, event: &FileCloseEvent, ctx: &RuleContext) -> Option<Severity> {
        self.check(event, ctx)
    }

    fn check_process_start(
        &self,
        event: &ProcessStartEvent,
        ctx: &RuleContext,
    ) -> Option<Severity> {
        None
    }

    fn check_process_exit(&self, event: &ProcessExitEvent, ctx: &RuleContext) -> Option<Severity> {
        None
    }
}

pub struct FileClassifier {
    pub process_map: HashMap<u32, ProcessInfo>,
    pub engine: RuleEngine,
}

impl FileClassifier {
    pub fn new() -> Self {
        Self {
            process_map: HashMap::new(),
            engine: RuleEngine {
                rules: vec![
                    Box::new(TempExecutableRule),
                    Box::new(RootWriteRule),
                    Box::new(SensitivePathRule),
                    Box::new(FlagRule),
                ],
            },
        }
    }

    pub fn classify_open(&self, event: FileOpenEvent) -> Classified<FileOpenEvent> {
        let ctx = RuleContext {
            process_cache: &self.process_map,
        };

        self.engine.classify_open(event, ctx)
    }

    pub fn classify_close(&self, event: FileCloseEvent) -> Classified<FileCloseEvent> {
        let ctx = RuleContext {
            process_cache: &self.process_map,
        };

        self.engine.classify_close(event, ctx)
    }
}

// TODO: Test and refine the approach
pub fn detect_suspicious_network(
    event: &AcceptEvent,
    pid_conn_counts: &mut HashMap<u32, (usize, u64)>,
    pid_ports_seen: &mut HashMap<u32, HashSet<u16>>,
) -> Vec<SuspiciousEvent> {
    let mut suspicious = Vec::new();

    let addr = event.endpoints.remote_ip.to_string();
    // if event.family != 2 && event.family != 10 {
    //     suspicious.push(SuspiciousEvent {
    //         pid: event.pid,
    //         file: addr.clone(),
    //         reason: format!(
    //             "Unusual socket family {} (not AF_INET/AF_INET6)",
    //             event.family
    //         ),
    //         severity: Severity::Medium,
    //         timestamp: event.timestamp,
    //     });
    // }

    while let Some(&(_, description, ref sev)) = SUSPICIOUS_PORTS
        .iter()
        .find(|&&(p, _, _)| p == event.endpoints.remote_port)
    {
        suspicious.push(SuspiciousEvent {
            pid: event.header.pid,
            file: addr.clone(),
            reason: format!(
                "Connection to suspicious port {}: {}",
                event.endpoints.remote_port, description
            ),
            severity: match sev {
                Severity::Critical => Severity::Critical,
                Severity::High => Severity::High,
                Severity::Medium => Severity::Medium,
                Severity::Low => Severity::Low,
                Severity::Info => Severity::Info,
            },
            timestamp: event.header.timestamp_ns,
        });
    }

    if event.endpoints.remote_port > 0 && event.endpoints.remote_port < 1024 {
        suspicious.push(SuspiciousEvent {
            pid: event.header.pid,
            file: addr.clone(),
            reason: format!(
                "Connection to privileged port {}",
                event.endpoints.remote_port
            ),
            severity: Severity::Low,
            timestamp: event.header.timestamp_ns,
        });
    }

    let conn_entry = pid_conn_counts
        .entry(event.header.pid)
        .or_insert((0, event.header.timestamp_ns));

    if event.header.timestamp_ns - conn_entry.1 <= TIME_WINDOW_NS {
        conn_entry.0 += 1;
    } else {
        *conn_entry = (1, event.header.timestamp_ns);
    }

    let conn_count = conn_entry.0;
    if conn_count == HIGH_CONN_THRESHOLD {
        suspicious.push(SuspiciousEvent {
            pid: event.header.pid,
            file: addr.clone(),
            reason: format!(
                "High-frequency connections: {} in 1s (possible DDoS/scanner)",
                conn_count
            ),
            severity: Severity::High,
            timestamp: event.header.timestamp_ns,
        });
    } else if conn_count == MED_CONN_THRESHOLD {
        suspicious.push(SuspiciousEvent {
            pid: event.header.pid,
            file: addr.clone(),
            reason: format!("Elevated connection rate: {} in 1s", conn_count),
            severity: Severity::Medium,
            timestamp: event.header.timestamp_ns,
        });
    }

    let ports_seen = pid_ports_seen.entry(event.header.pid).or_default();
    ports_seen.insert(event.endpoints.remote_port);

    if ports_seen.len() == 20 {
        suspicious.push(SuspiciousEvent {
            pid: event.header.pid,
            file: addr.clone(),
            reason: format!(
                "Possible port scan: {} unique ports contacted",
                ports_seen.len()
            ),
            severity: Severity::High,
            timestamp: event.header.timestamp_ns,
        });
    }

    // if event.sockfd < 0 {
    //     suspicious.push(SuspiciousEvent {
    //         pid: event.pid,
    //         file: addr.clone(),
    //         reason: format!("Invalid sockfd {} in network event", event.sockfd),
    //         severity: Severity::Low,
    //         timestamp: event.timestamp,
    //     });
    // }

    suspicious.dedup_by(|a, b| {
        a.pid == b.pid && a.reason == b.reason && a.timestamp.abs_diff(b.timestamp) < TIME_WINDOW_NS
    });

    suspicious
}

pub fn detect_input_device_access(events: &mut VecDeque<FileOpenEvent>) -> Vec<SuspiciousEvent> {
    let mut suspicious = Vec::new();
    let mut pid_access_counts: HashMap<u32, (usize, u64)> = HashMap::new();
    let mut pid_devices_seen: HashMap<u32, HashSet<String>> = HashMap::new();

    while let Some(event) = events.pop_front() {
        let filename = event.file_name().to_string();

        let device_match = INPUT_DEVICE_PATHS
            .iter()
            .find(|&&(path, _, _)| filename.starts_with(path));

        let Some(&(_, description, ref sev)) = device_match else {
            continue;
        };

        suspicious.push(SuspiciousEvent {
            pid: event.header.pid,
            file: filename.to_string(),
            reason: description.to_string(),
            severity: sev.to_owned(),
            timestamp: event.header.timestamp_ns,
        });

        if event.header.uid != 0 {
            suspicious.push(SuspiciousEvent {
                pid: event.header.pid,
                file: filename.to_string(),
                reason: format!(
                    "Non-root UID {} reading raw input device - possible keylogger",
                    event.header.uid
                ),
                severity: Severity::High,
                timestamp: event.header.timestamp_ns,
            });
        }

        for &(flag, reason) in SUSPICIOUS_INPUT_FLAGS {
            if event.flags as i32 & flag == flag {
                //TODO: fix this
                suspicious.push(SuspiciousEvent {
                    pid: event.header.pid,
                    file: filename.to_string(),
                    reason: format!("{} on '{}'", reason, filename),
                    severity: Severity::High,
                    timestamp: event.header.timestamp_ns,
                });
                break;
            }
        }

        if u32::from(event.file_type.clone()) & 0o4000 != 0 {
            suspicious.push(SuspiciousEvent {
                pid: event.header.pid,
                file: filename.to_string(),
                reason: format!("SUID bit set on input device access '{}'", filename),
                severity: Severity::High,
                timestamp: event.header.timestamp_ns,
            });
        }
        if u32::from(event.file_type) & 0o2000 != 0 {
            suspicious.push(SuspiciousEvent {
                pid: event.header.pid,
                file: filename.to_string(),
                reason: format!("SGID bit set on input device access '{}'", filename),
                severity: Severity::Medium,
                timestamp: event.header.timestamp_ns,
            });
        }

        let entry = pid_access_counts
            .entry(event.header.pid)
            .or_insert((0, event.header.timestamp_ns));

        if event.header.timestamp_ns - entry.1 <= TIME_WINDOW_NS {
            entry.0 += 1;
        } else {
            *entry = (1, event.header.timestamp_ns);
        }

        let count = entry.0;
        if count == HIGH_READ_THRESHOLD {
            suspicious.push(SuspiciousEvent {
                pid: event.header.pid,
                file: filename.to_string(),
                reason: format!(
                    "High-frequency input device polling: {} reads/s - likely a keylogger",
                    count
                ),
                severity: Severity::High,
                timestamp: event.header.timestamp_ns,
            });
        } else if count == MED_READ_THRESHOLD {
            suspicious.push(SuspiciousEvent {
                pid: event.header.pid,
                file: filename.to_string(),
                reason: format!("Elevated input device polling: {} reads/s", count),
                severity: Severity::Medium,
                timestamp: event.header.timestamp_ns,
            });
        }

        let devices = pid_devices_seen.entry(event.header.pid).or_default();
        devices.insert(filename.to_string());

        if devices.len() == 5 {
            suspicious.push(SuspiciousEvent {
                pid: event.header.pid,
                file: filename.to_string(),
                reason: format!(
                    "PID {} accessing {} distinct input devices - scraping all inputs",
                    event.header.pid,
                    devices.len()
                ),
                severity: Severity::High,
                timestamp: event.header.timestamp_ns,
            });
        }

        // if event.dir_fd != libc::AT_FDCWD && event.dir_fd < 0 {
        //     suspicious.push(SuspiciousEvent {
        //         pid: event.header.pid,
        //         file: filename.to_string(),
        //         reason: format!(
        //             "Invalid dir_fd {} used to open input device '{}'",
        //             event.dir_fd, filename
        //         ),
        //         severity: Severity::Low,
        //         timestamp: event.header.timestamp_ns,
        //     });
        // }
    }

    suspicious.dedup_by(|a, b| {
        a.pid == b.pid && a.reason == b.reason && a.timestamp.abs_diff(b.timestamp) < TIME_WINDOW_NS
    });

    suspicious
}
