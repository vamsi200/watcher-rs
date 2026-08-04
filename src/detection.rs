#![allow(unused)]
use crate::gen_db::{ArchivedIpsumDb, IpsumDb};
use crate::helper::{bytes_to_str, check_path, is_root_only_path, parse_addr};
use crate::*;
use crate::{PrivilegeEvent, Severity, helper::is_sensitive_path};
use bpfx::EventHeader;
use bpfx::{FileEvent, process::ProcessStartEvent};
use futures::lock::Mutex;
use libc::O_TRUNC;
use lru::LruCache;
use rkyv::rancor::Error;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Read;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::os::unix::fs::PermissionsExt;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use std::{
    fs::{self, File},
    path::{self, PathBuf},
};

macro_rules! match_event {
    ($($variant:ident), + $(,)?) => {
        fn check(&self, event: Event, ctx: &RuleContext) -> Option<Severity> {
            match event {
                $(
                    Event::$variant(e) => self.check(e, ctx),
                )+
                _ => None,
            }
        }
    };
}

macro_rules! classify {
    ($fn_name:ident, $variant:ident, $event_ty:ty) => {
        pub fn $fn_name(&self, event: $event_ty, ctx: RuleContext) -> Classified<$event_ty> {
            let mut severity = Severity::Low;
            let mut matched_rules = Vec::new();

            for rule in &self.rules {
                if let Some(sev) = rule.check(Event::$variant(&event), &ctx) {
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
    };
}

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
    pub ipsum_bytes: Option<&'a [u8]>,
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

pub enum Event<'a> {
    FileOpen(&'a FileOpenEvent),
    FileClose(&'a FileCloseEvent),
    ProcessStart(&'a ProcessStartEvent),
    ProcessExit(&'a ProcessExitEvent),
    Accept(&'a AcceptEvent),
    Connect(&'a ConnectEvent),
}

pub trait Rule: Send + Sync {
    fn name(&self) -> &'static str;
    fn check(&self, event: Event, ctx: &RuleContext) -> Option<Severity>;
}

pub struct RuleEngine {
    pub rules: Vec<Box<dyn Rule>>,
}

impl RuleEngine {
    classify!(classify_open, FileOpen, FileOpenEvent);
    classify!(classify_close, FileClose, FileCloseEvent);
    classify!(classify_process_start, ProcessStart, ProcessStartEvent);
    classify!(classify_accept, Accept, AcceptEvent);
    classify!(classify_connect, Connect, ConnectEvent);
}

trait FileEventCommon {
    fn header(&self) -> &EventHeader;
    fn file_path(&self) -> &str;
    fn file_type(&self) -> &FileType;
    fn inode(&self) -> u64;
    fn retval(&self) -> i32;
    fn flags_u32(&self) -> u32;
    fn flags_string(&self) -> String;
    fn write(&self) -> bool;
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

    fn flags_u32(&self) -> u32 {
        self.flags_raw()
    }

    fn flags_string(&self) -> String {
        self.flags()
    }

    fn write(&self) -> bool {
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

    fn flags_u32(&self) -> u32 {
        self.flags
    }

    fn flags_string(&self) -> String {
        self.flags()
    }

    fn write(&self) -> bool {
        self.is_write()
    }
}

pub struct SensitivePathRule;

impl SensitivePathRule {
    fn check<T>(&self, event: &T, _: &RuleContext) -> Option<Severity>
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

    match_event!(FileOpen, FileClose);
}

pub struct FlagRule;

impl FlagRule {
    fn check<T>(&self, event: &T, _: &RuleContext) -> Option<Severity>
    where
        T: FileEventCommon,
    {
        match event.flags_string().as_str() {
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

    match_event!(FileOpen, FileClose);
}

pub struct RootWriteRule;

impl RootWriteRule {
    fn check<T>(&self, event: &T, _: &RuleContext) -> Option<Severity>
    where
        T: FileEventCommon,
    {
        if event.header().uid == 0 && event.write() {
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

    match_event!(FileOpen, FileClose);
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

    match_event!(FileOpen, FileClose);
}

pub struct Classifier {
    pub ipsum_file_bytes: Vec<u8>,
    pub process_map: HashMap<u32, ProcessInfo>, //TODO: unimplemented!()
    pub engine: RuleEngine,
}

impl Classifier {
    pub fn new() -> Self {
        Self {
            ipsum_file_bytes: Vec::new(),
            process_map: HashMap::new(),
            engine: RuleEngine {
                rules: vec![
                    Box::new(TempExecutableRule),
                    Box::new(RootWriteRule),
                    Box::new(SensitivePathRule),
                    Box::new(FlagRule),
                    Box::new(SuspiciousPortRule),
                    Box::new(SuspiciousIpRule),
                ],
            },
        }
    }

    pub fn classify_open(&self, event: FileOpenEvent) -> Classified<FileOpenEvent> {
        let ctx = RuleContext {
            process_cache: &self.process_map,
            ipsum_bytes: None,
        };

        self.engine.classify_open(event, ctx)
    }

    pub fn classify_close(&self, event: FileCloseEvent) -> Classified<FileCloseEvent> {
        let ctx = RuleContext {
            process_cache: &self.process_map,
            ipsum_bytes: None,
        };

        self.engine.classify_close(event, ctx)
    }

    pub fn classify_accept(&self, event: AcceptEvent) -> Classified<AcceptEvent> {
        let ctx = RuleContext {
            process_cache: &self.process_map,
            ipsum_bytes: Some(&self.ipsum_file_bytes),
        };

        self.engine.classify_accept(event, ctx)
    }

    pub fn classify_connect(&self, event: ConnectEvent) -> Classified<ConnectEvent> {
        let ctx = RuleContext {
            process_cache: &self.process_map,
            ipsum_bytes: Some(&self.ipsum_file_bytes),
        };

        self.engine.classify_connect(event, ctx)
    }
}

trait NetworkCommon {
    fn endpoints(&self) -> &SocketEndpoints;
}

impl NetworkCommon for AcceptEvent {
    fn endpoints(&self) -> &SocketEndpoints {
        &self.endpoints
    }
}

impl NetworkCommon for ConnectEvent {
    fn endpoints(&self) -> &SocketEndpoints {
        &self.endpoints
    }
}

pub struct SuspiciousPortRule;

impl SuspiciousPortRule {
    fn check<T>(&self, event: &T, _: &RuleContext) -> Option<Severity>
    where
        T: NetworkCommon,
    {
        SUSPICIOUS_PORTS
            .iter()
            .filter_map(|(port, name, sev)| {
                if port == &event.endpoints().remote_port || port == &event.endpoints().local_port {
                    Some(sev)
                } else {
                    None
                }
            })
            .next()
            .copied()
    }
}

impl Rule for SuspiciousPortRule {
    fn name(&self) -> &'static str {
        "SuspiciousPort"
    }

    match_event!(Accept, Connect);
}

pub struct SuspiciousIpRule;

impl SuspiciousIpRule {
    fn check<'a, T>(&self, event: &T, file_bytes: &'a [u8]) -> Option<Severity>
    where
        T: NetworkCommon,
    {
        let mut severity: Option<Severity> = None;
        if let Ok(archived) = rkyv::access::<ArchivedIpsumDb, Error>(file_bytes) {
            match event.endpoints().remote_ip {
                IpAddr::V4(ip) => {
                    let key = u32::from(ip);
                    match archived.v4.binary_search_by_key(&key, |val| val.ip.into()) {
                        Ok(idx) => {
                            let score = archived.v4[idx].score;
                            let sev = match score {
                                1 => Severity::Medium,
                                2 => Severity::Medium,
                                3 => Severity::Medium,
                                4 => Severity::High,
                                _ => Severity::Critical,
                            };
                            severity = Some(sev);
                        }
                        Err(_) => {
                            tracing::info!("Found none..");
                            severity = None;
                        }
                    }
                }

                IpAddr::V6(ip) => {
                    let key = u128::from(ip);
                    match archived.v6.binary_search_by_key(&key, |val| val.ip.into()) {
                        Ok(idx) => {
                            let score = archived.v6[idx].score;
                            let sev = match score {
                                1 => Severity::Medium,
                                2 => Severity::Medium,
                                3 => Severity::Medium,
                                4 => Severity::High,
                                _ => Severity::Critical,
                            };

                            severity = Some(sev);
                        }
                        Err(_) => {
                            tracing::info!("Found none..");
                            severity = None;
                        }
                    }
                }
            }
        }

        severity
    }
}

impl Rule for SuspiciousIpRule {
    fn name(&self) -> &'static str {
        "SuspiciousIp"
    }

    fn check(&self, event: Event, ctx: &RuleContext) -> Option<Severity> {
        if let Some(file_bytes) = ctx.ipsum_bytes {
            match event {
                Event::Accept(e) => self.check(e, file_bytes),
                Event::Connect(e) => self.check(e, file_bytes),
                _ => None,
            }
        } else {
            None
        }
    }
}
