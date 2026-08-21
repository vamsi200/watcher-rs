#![allow(unused)]
use crate::Severity;
use crate::gen_db::ArchivedIpsumDb;
use crate::*;
use bpfx::EventHeader;
use bpfx::{FileEvent, process::ProcessStartEvent};
use lru::LruCache;
use rkyv::rancor::Error;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

macro_rules! impl_file_header {
    () => {
        fn header(&self) -> &EventHeader {
            &self.header
        }
    };
}

macro_rules! impl_file_path {
    () => {
        fn file_path(&self) -> &str {
            &self.file_path
        }
    };
}

macro_rules! impl_file_type {
    () => {
        fn file_type(&self) -> &FileType {
            &self.file_type
        }
    };
}

macro_rules! impl_file_inode {
    () => {
        fn inode(&self) -> u64 {
            self.inode
        }
    };
}

macro_rules! impl_file_retval {
    () => {
        fn retval(&self) -> i32 {
            self.retval
        }
    };
}

macro_rules! impl_file_retval_read {
    () => {
        fn retval(&self) -> i32 {
            self.retval as i32
        }
    };
}

macro_rules! impl_file_flags {
    () => {
        fn flags_u32(&self) -> u32 {
            self.flags
        }
    };
}

macro_rules! impl_file_flags_string {
    () => {
        fn flags_string(&self) -> String {
            self.flags()
        }
    };
}

macro_rules! impl_file_write {
    () => {
        fn write(&self) -> bool {
            self.is_write()
        }
    };
}

macro_rules! root_impl {
    ($type: ident) => {
        fn check<T>(&self, event: &T, _: &RuleContext) -> Option<Severity>
        where
            T: $type,
        {
            if event.header().uid == 0 {
                Some(Severity::Low)
            } else {
                None
            }
        }
    };
}

macro_rules! generic_file_impl {
    ($type:ident, $retval_impl:ident) => {
        impl HasHeader for $type {
            impl_file_header!();
        }

        impl HasFilePath for $type {
            impl_file_path!();
        }

        impl HasFileType for $type {
            impl_file_type!();
        }

        impl HasInode for $type {
            impl_file_inode!();
        }

        impl HasRetval for $type {
            $retval_impl!();
        }

        impl HasFlags for $type {
            impl_file_flags!();
            impl_file_flags_string!();
        }

        impl HasWrite for $type {
            impl_file_write!();
        }
    };
}

macro_rules! impl_network_common {
    () => {
        fn endpoints(&self) -> &SocketEndpoints {
            &self.endpoints
        }

        fn header(&self) -> &EventHeader {
            &self.header
        }
    };
}

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

macro_rules! classify_classifier {
    ($fn_name:ident, $event:ty) => {
        pub fn $fn_name(&self, event: $event) -> Classified<$event> {
            let ctx = RuleContext {
                process_cache: &self.process_map,
                ipsum_bytes: self.ipsum_file_bytes.as_deref(),
                rules_config: self.rules.as_ref(),
            };

            self.engine.$fn_name(event, ctx)
        }
    };
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct Rules {
    pub sensitive_path: Option<SensitivePathConfig>,
    pub suspicious_exec_path: Option<SuspiciousExecPathConfig>,
    pub suspicious_ports: Option<SuspiciousPortsConfig>,
    pub ignore_pids: Option<IgnorePidsConfig>,
    pub ignore_comm_name: Option<IgnoreCommName>,
    pub ignore_exe_path: Option<IgnoreExePath>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct IgnoreExePath {
    pub enabled: bool,
    pub paths: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct IgnoreCommName {
    pub enabled: bool,
    pub names: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct IgnorePidsConfig {
    pub enabled: bool,
    pub pids: Vec<u32>,
}

pub struct FileEventFilter {
    filter: LruCache<FileKey, Aggregate>,
}

impl Default for FileEventFilter {
    fn default() -> Self {
        Self::new()
    }
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

        match self.filter.get_mut(&file_key) {
            Some(val) => {
                if val.last_seen.elapsed() < Duration::from_secs(1) {
                    val.count += 1;
                    return true;
                }

                val.last_seen = Instant::now();
                val.count += 1;
                false
            }

            None => {
                self.filter.put(
                    file_key,
                    Aggregate {
                        last_seen: Instant::now(),
                        count: 1,
                    },
                );

                false
            }
        }
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
    pub event_type: FileEventKey,
}

pub struct Aggregate {
    last_seen: Instant,
    count: u64,
}

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

pub const SUSPICIOUS_PORTS: &[(u16, Severity)] = &[
    (23, Severity::Medium),
    (512, Severity::High),
    (513, Severity::High),
    (514, Severity::High),
    (4444, Severity::High),
    (5554, Severity::High),
    (12345, Severity::High),
    (27374, Severity::High),
    (31337, Severity::High),
    (54321, Severity::High),
    (6660, Severity::Medium),
    (6661, Severity::Medium),
    (6662, Severity::Medium),
    (6663, Severity::Medium),
    (6664, Severity::Medium),
    (6665, Severity::Medium),
    (6666, Severity::Medium),
    (6667, Severity::Medium),
    (6668, Severity::Medium),
    (6669, Severity::Medium),
    (6697, Severity::Medium),
    (1080, Severity::Medium),
    (9001, Severity::Medium),
    (9030, Severity::Medium),
    (9050, Severity::Medium),
    (9051, Severity::High),
    (9150, Severity::Medium),
];

const INPUT_DEVICE_PATHS: &[(&str, Severity)] = &[
    ("/dev/input/", Severity::High),
    ("/dev/tty", Severity::Medium),
    ("/dev/pts/", Severity::Medium),
    ("/dev/hidraw", Severity::High),
    ("/dev/uinput", Severity::High),
    ("/dev/input/mice", Severity::Medium),
    ("/dev/input/mouse", Severity::Medium),
    ("/dev/input/event", Severity::High),
];

pub struct SuspiciousInputDeviceAccessRule;

impl SuspiciousInputDeviceAccessRule {
    fn check<T>(&self, event: &T, _: &RuleContext) -> Option<Severity>
    where
        T: HasFilePath,
    {
        INPUT_DEVICE_PATHS
            .iter()
            .filter_map(|(input, sev)| {
                if event.file_path().starts_with(*input) {
                    Some(*sev)
                } else {
                    None
                }
            })
            .next()
    }
}

impl Rule for SuspiciousInputDeviceAccessRule {
    fn name(&self) -> &'static str {
        "SuspiciousInputDeviceAccessRule"
    }
    match_event!(FileOpen, FileClose, FileRead, FileWrite);
}

pub struct RuleContext<'a> {
    pub process_cache: &'a HashMap<u32, ProcessInfo>,
    pub ipsum_bytes: Option<&'a [u8]>,
    pub rules_config: Option<&'a Rules>,
}

#[derive(
    Debug, Clone, PartialEq, PartialOrd, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct Classified<T> {
    pub event: T,
    pub severity: Severity,
    pub matched_rules: Vec<String>,
}

pub enum Event<'a> {
    FileOpen(&'a FileOpenEvent),
    FileClose(&'a FileCloseEvent),
    FileRead(&'a FileReadEvent),
    FileRename(&'a FileRenameEvent),
    FileWrite(&'a FileWriteEvent),
    FileDelete(&'a FileDeleteEvent),
    ProcessStart(&'a ProcessStartEvent),
    ProcessExit(&'a ProcessExitEvent),
    ProcessFork(&'a ProcessForkEvent),
    NetworkAccept(&'a AcceptEvent),
    NetworkConnect(&'a ConnectEvent),
    NetworkBind(&'a BindEvent),
    NetworkListen(&'a ListenEvent),
    NetworkClose(&'a CloseEvent),
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
    classify!(classify_read, FileRead, FileReadEvent);
    classify!(classify_rename, FileRename, FileRenameEvent);
    classify!(classify_write, FileWrite, FileWriteEvent);
    classify!(classify_delete, FileDelete, FileDeleteEvent);

    classify!(classify_process_start, ProcessStart, ProcessStartEvent);
    classify!(classify_process_exit, ProcessExit, ProcessExitEvent);
    classify!(classify_process_fork, ProcessFork, ProcessForkEvent);

    classify!(classify_accept, NetworkAccept, AcceptEvent);
    classify!(classify_connect, NetworkConnect, ConnectEvent);
    classify!(classify_bind, NetworkBind, BindEvent);
    classify!(classify_listen, NetworkListen, ListenEvent);
    classify!(classify_network_close, NetworkClose, CloseEvent);
}

trait HasHeader {
    fn header(&self) -> &EventHeader;
}

trait HasFilePath {
    fn file_path(&self) -> &str;
}

trait HasFileType {
    fn file_type(&self) -> &FileType;
}

trait HasInode {
    fn inode(&self) -> u64;
}

trait HasRetval {
    fn retval(&self) -> i32;
}

trait HasFlags {
    fn flags_u32(&self) -> u32;

    fn flags_string(&self) -> String {
        self.flags_u32().to_string()
    }
}

trait HasWrite {
    fn write(&self) -> bool;
}

generic_file_impl!(FileOpenEvent, impl_file_retval);
generic_file_impl!(FileCloseEvent, impl_file_retval);

impl HasHeader for FileRenameEvent {
    impl_file_header!();
}

impl HasFileType for FileRenameEvent {
    impl_file_type!();
}

impl HasFlags for FileRenameEvent {
    impl_file_flags!();
}

impl HasRetval for FileRenameEvent {
    impl_file_retval!();
}

impl HasHeader for FileDeleteEvent {
    impl_file_header!();
}

impl HasFileType for FileDeleteEvent {
    impl_file_type!();
}

impl HasRetval for FileDeleteEvent {
    impl_file_retval!();
}

generic_file_impl!(FileReadEvent, impl_file_retval_read);
generic_file_impl!(FileWriteEvent, impl_file_retval_read);

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SensitivePathConfig {
    pub enabled: bool,
    pub paths: BTreeMap<Severity, Vec<String>>,
}

impl SensitivePathConfig {
    fn check<T>(&self, event: &T, ctx: &RuleContext) -> Option<Severity>
    where
        T: HasFilePath,
    {
        let config = ctx
            .rules_config
            .and_then(|rules| rules.sensitive_path.as_ref())?;

        if config.enabled {
            config.paths.iter().find_map(|(severity, paths)| {
                paths
                    .iter()
                    .any(|path| event.file_path().starts_with(path))
                    .then_some(*severity)
            })
        } else {
            None
        }
    }
}

impl Rule for SensitivePathConfig {
    fn name(&self) -> &'static str {
        "SensitivePath"
    }

    match_event!(FileOpen, FileClose);
}

pub struct FlagRule;

impl FlagRule {
    fn check<T>(&self, event: &T, _: &RuleContext) -> Option<Severity>
    where
        T: HasFlags,
    {
        match event.flags_string().as_str() {
            "RDONLY" => Some(Severity::Low),
            "WRONLY" => Some(Severity::Medium),
            "RDWR" => Some(Severity::Medium),
            "CREAT" => Some(Severity::Medium),
            "TRUNC" => Some(Severity::High),
            _ => None,
        }
    }
}

impl Rule for FlagRule {
    fn name(&self) -> &'static str {
        "SensitiveFlag"
    }

    match_event!(FileOpen, FileClose, FileRead, FileWrite, FileRename);
}

pub struct RootWriteRule;

impl RootWriteRule {
    fn check<T>(&self, event: &T, _: &RuleContext) -> Option<Severity>
    where
        T: HasHeader + HasWrite,
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
        T: HasHeader,
    {
        let Some(proc) = ctx.process_cache.get(&event.header().pid) else {
            return None;
        };

        if proc.exe.starts_with("/tmp") || proc.exe.starts_with("/dev/shm") {
            Some(Severity::High)
        } else {
            None
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
    pub ipsum_file_bytes: Option<Vec<u8>>,
    pub process_map: HashMap<u32, ProcessInfo>,
    pub engine: RuleEngine,
    pub rules: Option<Rules>,
}

impl Default for Classifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Classifier {
    pub fn new() -> Self {
        Self {
            ipsum_file_bytes: None,
            process_map: HashMap::new(),
            engine: RuleEngine {
                rules: vec![
                    Box::new(TempExecutableRule),
                    Box::new(RootWriteRule),
                    Box::new(SensitivePathConfig {
                        enabled: true,
                        paths: BTreeMap::new(),
                    }),
                    Box::new(FlagRule),
                    Box::new(SuspiciousPortsConfig {
                        enabled: true,
                        ports: BTreeMap::new(),
                    }),
                    Box::new(SuspiciousIpRule),
                    Box::new(IpClassificationRule),
                    Box::new(RunAsRootRule),
                    Box::new(BindConnRules),
                    Box::new(RunAsRootProcessRule),
                    Box::new(SuspiciousExecPathConfig {
                        enabled: true,
                        paths: BTreeMap::new(),
                    }),
                    Box::new(SuspiciousInputDeviceAccessRule),
                ],
            },
            rules: None,
        }
    }

    classify_classifier!(classify_open, FileOpenEvent);
    classify_classifier!(classify_close, FileCloseEvent);
    classify_classifier!(classify_read, FileReadEvent);
    classify_classifier!(classify_rename, FileRenameEvent);
    classify_classifier!(classify_write, FileWriteEvent);
    classify_classifier!(classify_delete, FileDeleteEvent);

    classify_classifier!(classify_accept, AcceptEvent);
    classify_classifier!(classify_connect, ConnectEvent);
    classify_classifier!(classify_bind, BindEvent);
    classify_classifier!(classify_listen, ListenEvent);
    classify_classifier!(classify_network_close, CloseEvent);

    classify_classifier!(classify_process_start, ProcessStartEvent);
    classify_classifier!(classify_process_exit, ProcessExitEvent);
    classify_classifier!(classify_process_fork, ProcessForkEvent);
}

trait NetworkCommon {
    fn endpoints(&self) -> &SocketEndpoints;
    fn header(&self) -> &EventHeader;
}

impl NetworkCommon for AcceptEvent {
    impl_network_common!();
}

impl NetworkCommon for ConnectEvent {
    impl_network_common!();
}

impl NetworkCommon for BindEvent {
    impl_network_common!();
}

impl NetworkCommon for ListenEvent {
    impl_network_common!();
}

impl NetworkCommon for CloseEvent {
    impl_network_common!();
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SuspiciousPortsConfig {
    pub enabled: bool,
    pub ports: BTreeMap<Severity, Vec<u16>>,
}

impl SuspiciousPortsConfig {
    fn check<T>(&self, event: &T, ctx: &RuleContext) -> Option<Severity>
    where
        T: NetworkCommon,
    {
        let config = ctx.rules_config.and_then(|s| s.suspicious_ports.as_ref())?;

        if config.enabled {
            config.ports.iter().find_map(|(severity, pids)| {
                pids.iter()
                    .any(|x| {
                        *x == event.endpoints().remote_port || *x == event.endpoints().local_port
                    })
                    .then_some(*severity)
            })
        } else {
            None
        }
    }
}

impl Rule for SuspiciousPortsConfig {
    fn name(&self) -> &'static str {
        "SuspiciousPort"
    }

    match_event!(NetworkAccept, NetworkConnect);
}

pub struct SuspiciousIpRule;

impl SuspiciousIpRule {
    fn check<T>(&self, event: &T, file_bytes: &[u8]) -> Option<Severity>
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
                Event::NetworkAccept(e) => self.check(e, file_bytes),
                Event::NetworkConnect(e) => self.check(e, file_bytes),
                Event::NetworkBind(e) => self.check(e, file_bytes),
                Event::NetworkListen(e) => self.check(e, file_bytes),
                Event::NetworkClose(e) => self.check(e, file_bytes),
                _ => None,
            }
        } else {
            None
        }
    }
}

pub enum IpKind {
    Loopback,
    Private,
    LinkLocal,
    Multicast,
    Broadcast,
    Unspecified,
    Documentation,
    Public,
}

pub fn classify(ip: IpAddr) -> IpKind {
    match ip {
        IpAddr::V4(ip) => {
            if ip.is_loopback() {
                IpKind::Loopback
            } else if ip.is_private() {
                IpKind::Private
            } else if ip.is_link_local() {
                IpKind::LinkLocal
            } else if ip.is_multicast() {
                IpKind::Multicast
            } else if ip.is_broadcast() {
                IpKind::Broadcast
            } else if ip.is_unspecified() {
                IpKind::Unspecified
            } else if ip.is_documentation() {
                IpKind::Documentation
            } else {
                IpKind::Public
            }
        }
        IpAddr::V6(ip) => {
            if ip.is_loopback() {
                IpKind::Loopback
            } else if ip.is_unique_local() {
                IpKind::Private
            } else if ip.is_unicast_link_local() {
                IpKind::LinkLocal
            } else if ip.is_multicast() {
                IpKind::Multicast
            } else if ip.is_unspecified() {
                IpKind::Unspecified
            } else {
                IpKind::Public
            }
        }
    }
}

pub struct IpClassificationRule;

impl IpClassificationRule {
    fn check<T>(&self, event: &T, _: &RuleContext) -> Option<Severity>
    where
        T: NetworkCommon,
    {
        match classify(event.endpoints().remote_ip) {
            IpKind::Public => Some(Severity::Low),
            IpKind::Private | IpKind::Loopback => Some(Severity::Info),
            _ => None,
        }
    }
}

impl Rule for IpClassificationRule {
    fn name(&self) -> &'static str {
        "IpClassification"
    }

    match_event!(NetworkBind, NetworkListen, NetworkConnect, NetworkAccept);
}

pub struct RunAsRootRule;

impl RunAsRootRule {
    root_impl!(NetworkCommon);
}

impl Rule for RunAsRootRule {
    fn name(&self) -> &'static str {
        "RunAsRoot"
    }

    match_event!(NetworkListen, NetworkConnect);
}

pub struct BindConnRules;

impl BindConnRules {
    fn check(&self, event: &BindEvent, _: &RuleContext) -> Option<Severity> {
        if event.endpoints.local_ip.is_unspecified() || event.endpoints().local_port < 1024 {
            Some(Severity::Low)
        } else {
            None
        }
    }
}

impl Rule for BindConnRules {
    fn name(&self) -> &'static str {
        "GenericBindRule"
    }

    match_event!(NetworkBind);
}

trait ProcessCommon {
    fn header(&self) -> &EventHeader;
}

impl ProcessCommon for ProcessStartEvent {
    fn header(&self) -> &EventHeader {
        &self.header
    }
}

impl ProcessCommon for ProcessExitEvent {
    fn header(&self) -> &EventHeader {
        &self.header
    }
}

impl ProcessCommon for ProcessForkEvent {
    fn header(&self) -> &EventHeader {
        &self.parent
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SuspiciousExecPathConfig {
    pub enabled: bool,
    pub paths: BTreeMap<Severity, Vec<String>>,
}

pub const SUSPICIOUS_EXEC_PATHS: &[(&str, Severity)] = &[
    ("/tmp", Severity::Medium),
    ("/var/tmp", Severity::Medium),
    ("/dev/shm", Severity::Medium),
    ("/run/user", Severity::Low),
    ("/var/run", Severity::Low),
];

impl SuspiciousExecPathConfig {
    fn check<T>(&self, event: &T, ctx: &RuleContext) -> Option<Severity>
    where
        T: ProcessCommon,
    {
        let config = ctx
            .rules_config
            .and_then(|s| s.suspicious_exec_path.as_ref())?;

        if config.enabled {
            config.paths.iter().find_map(|(severity, paths)| {
                paths
                    .iter()
                    .any(|path| read_exe(event.header().pid).starts_with(path))
                    .then_some(*severity)
            })
        } else {
            None
        }
    }
}

impl Rule for SuspiciousExecPathConfig {
    fn name(&self) -> &'static str {
        "SuspiciousExecPath"
    }

    match_event!(ProcessStart, ProcessExit, ProcessFork);
}
pub struct RunAsRootProcessRule;

impl RunAsRootProcessRule {
    root_impl!(ProcessCommon);
}

impl Rule for RunAsRootProcessRule {
    fn name(&self) -> &'static str {
        "ProcessRunningAsRoot"
    }

    match_event!(ProcessStart, ProcessExit, ProcessFork);
}
