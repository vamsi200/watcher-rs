#![allow(unused)]
use crate::helper::{is_root_only_path, parse_addr, parse_filename};
use anyhow::Error;
use anyhow::Result;
use aya::{
    Btf, Ebpf, include_bytes_aligned,
    maps::{MapData, RingBuf},
    programs::{FEntry, TracePoint},
};
use aya_log::EbpfLogger;
use std::collections::{HashMap, HashSet};
use std::{
    ffi::CStr,
    fs::{self, File},
    io::{BufRead, BufReader, Read},
    os::unix::fs::PermissionsExt,
    path::{self, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use std::{ptr::read, thread::sleep};
use watcher_rs_common::EventHeader;
use watcher_rs_common::ExecEvent;
use watcher_rs_common::FileCloseEvent;
use watcher_rs_common::FileEvent;
use watcher_rs_common::NetworkEvent;
use watcher_rs_common::ProcessExitEvent;

// like a snapshot
#[derive(Debug)]
pub struct ProcessInfo {
    pid: u32,
    ppid: u32,
    name: String,
    cmdline: String,
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

#[derive(Debug)]
pub struct ProcessEvent {
    info: ProcessInfo,
    uid: u32,
    timestamp: u64,
}

struct PrivilegeEvent {
    pid: u32,
    uid: u32,
    binary: PathBuf,
    is_setuid: bool,
    timestamp: u64,
}

#[derive(Debug)]
pub struct SuspiciousEvent {
    pid: u32,
    file: String,
    reason: String,
    severity: Severity,
    timestamp: u64,
}

#[derive(Debug)]
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
                    let info = ProcessInfo::get_process_info_from_pid(pid_str.parse()?);
                    process_info.push(info);
                }
            }
        }
    }

    Ok(process_info)
}

pub fn track_process_exec(ring_buf: &mut RingBuf<&mut MapData>) -> Result<Option<ProcessEvent>> {
    let mut p_event: Option<ProcessEvent> = None;

    if let Some(data) = ring_buf.next() {
        let event = unsafe { read(data.as_ptr() as *const ExecEvent) };
        let proc_info = ProcessInfo::get_process_info_from_pid(event.pid);

        let mut uid = 0u32;
        if let Ok(mut file) = File::open(format!("/proc/{}/status", event.pid)) {
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

        p_event = Some(ProcessEvent {
            info: proc_info,
            uid: uid,
            timestamp: event.timestamp,
        })
    }

    Ok(p_event)
}

#[derive(Debug)]
pub enum Event {
    ProcessExec(ExecEvent),
    ProcessExit(ProcessExitEvent),
    FileOpen(FileEvent),
    FileClose(FileCloseEvent),
    Network(NetworkEvent),
    Unknown(u32),
}

pub fn ret_event(ring_buf: &mut RingBuf<&mut MapData>) -> Option<Event> {
    let data = ring_buf.next()?;
    let ptr = data.as_ptr();

    let header = unsafe { read(ptr as *const EventHeader) };

    let event = match header.kind {
        0 => Event::ProcessExec(unsafe { read(ptr as *const ExecEvent) }),
        1 => Event::ProcessExit(unsafe { read(ptr as *const ProcessExitEvent) }),
        2 => Event::FileOpen(unsafe { read(ptr as *const FileEvent) }),
        3 => Event::FileClose(unsafe { read(ptr as *const FileCloseEvent) }),
        4 => Event::Network(unsafe { read(ptr as *const NetworkEvent) }),
        k => Event::Unknown(k),
    };

    Some(event)
}

// TODO: Test and refine the approach
fn detect_privileged_exec(events: &[ExecEvent]) -> Vec<PrivilegeEvent> {
    let mut p_events = Vec::new();
    for ev in events {
        let file_name = std::fs::read_link(format!("/proc/{}/exe", ev.pid))
            .unwrap_or_else(|_| PathBuf::from("unknown")); // find some other way to find the
        // binary

        let is_setuid = match std::fs::metadata(&file_name) {
            Ok(meta) => (meta.permissions().mode() & 0o4000) != 0,
            Err(_) => false,
        };

        if is_setuid || ev.uid == 0 {
            p_events.push(PrivilegeEvent {
                pid: ev.pid,
                uid: ev.uid,
                binary: file_name,
                is_setuid,
                timestamp: ev.timestamp,
            });
        }
    }
    p_events
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

const SUSPICIOUS_FLAGS: &[(i32, &str)] = &[
    (libc::O_WRONLY | libc::O_TRUNC, "truncating sensitive file"),
    (libc::O_RDWR | libc::O_CREAT, "creating file with RW access"),
    (libc::O_WRONLY | libc::O_APPEND, "appending to file"),
];

// are ya sure??
const SUSPICIOUS_PORTS: &[(u16, &str, Severity)] = &[
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

// TODO: Test and refine the approach
pub fn detect_suspicious_file_access(events: &[FileEvent]) -> Vec<SuspiciousEvent> {
    let mut suspicious = Vec::new();
    let mut pid_access_counts: HashMap<u32, (usize, u64)> = HashMap::new();

    for event in events {
        let filename = parse_filename(&event.filename);

        if let Some(matched_path) = SENSITIVE_PATHS.iter().find(|&&p| filename.starts_with(p)) {
            let severity = if matches!(*matched_path, "/etc/shadow" | "/.ssh/" | "/etc/sudoers") {
                Severity::High
            } else {
                Severity::Medium
            };

            suspicious.push(SuspiciousEvent {
                pid: event.pid,
                reason: format!("Access to sensitive path: {}", filename),
                file: filename.clone(),
                severity,
                timestamp: event.timestamp,
            });
        }

        if event.uid != 0 && is_root_only_path(&filename) {
            suspicious.push(SuspiciousEvent {
                pid: event.pid,
                reason: format!(
                    "Non-root UID {} accessing privileged path: {}",
                    event.uid, filename
                ),
                file: filename.clone(),
                severity: Severity::High,
                timestamp: event.timestamp,
            });
        }

        for &(flag_combo, description) in SUSPICIOUS_FLAGS {
            if event.flags & flag_combo == flag_combo {
                suspicious.push(SuspiciousEvent {
                    pid: event.pid,
                    reason: format!("Suspicious open flags on '{}': {}", filename, description),
                    file: filename.clone(),
                    severity: Severity::Medium,
                    timestamp: event.timestamp,
                });
                break;
            }
        }

        let entry = pid_access_counts
            .entry(event.pid)
            .or_insert((0, event.timestamp));

        if event.timestamp - entry.1 <= TIME_WINDOW_NS {
            entry.0 += 1;
        } else {
            *entry = (1, event.timestamp);
        }

        let access_count = entry.0;
        if access_count == HIGH_FREQ_THRESHOLD {
            suspicious.push(SuspiciousEvent {
                pid: event.pid,
                reason: format!(
                    "High-frequency file access: {} accesses in 1s window",
                    access_count
                ),
                file: filename.clone(),
                severity: Severity::High,
                timestamp: event.timestamp,
            });
        } else if access_count == MED_FREQ_THRESHOLD {
            suspicious.push(SuspiciousEvent {
                pid: event.pid,
                reason: format!(
                    "Elevated file access rate: {} accesses in 1s window",
                    access_count
                ),
                file: filename.clone(),
                severity: Severity::Medium,
                timestamp: event.timestamp,
            });
        }

        if event.dir_fd != libc::AT_FDCWD && event.dir_fd < 0 {
            suspicious.push(SuspiciousEvent {
                pid: event.pid,
                reason: format!("Invalid dir_fd {} used in openat syscall", event.dir_fd),
                file: filename,
                severity: Severity::Low,
                timestamp: event.timestamp,
            });
        }
    }

    suspicious.dedup_by(|a, b| {
        a.pid == b.pid && a.reason == b.reason && a.timestamp.abs_diff(b.timestamp) < TIME_WINDOW_NS
    });

    suspicious
}

// TODO: Test and refine the approach
pub fn detect_suspicious_network(
    event: &NetworkEvent,
    pid_conn_counts: &mut HashMap<u32, (usize, u64)>,
    pid_ports_seen: &mut HashMap<u32, HashSet<u16>>,
) -> Vec<SuspiciousEvent> {
    let mut suspicious = Vec::new();

    let addr = parse_addr(event.family, &event.addr);
    if event.family != 2 && event.family != 10 {
        suspicious.push(SuspiciousEvent {
            pid: event.pid,
            file: addr.clone(),
            reason: format!(
                "Unusual socket family {} (not AF_INET/AF_INET6)",
                event.family
            ),
            severity: Severity::Medium,
            timestamp: event.timestamp,
        });
    }

    if let Some(&(_, description, ref sev)) =
        SUSPICIOUS_PORTS.iter().find(|&&(p, _, _)| p == event.port)
    {
        suspicious.push(SuspiciousEvent {
            pid: event.pid,
            file: addr.clone(),
            reason: format!(
                "Connection to suspicious port {}: {}",
                event.port, description
            ),
            severity: match sev {
                Severity::High => Severity::High,
                Severity::Medium => Severity::Medium,
                Severity::Low => Severity::Low,
            },
            timestamp: event.timestamp,
        });
    }

    if event.port > 0 && event.port < 1024 {
        suspicious.push(SuspiciousEvent {
            pid: event.pid,
            file: addr.clone(),
            reason: format!("Connection to privileged port {}", event.port),
            severity: Severity::Low,
            timestamp: event.timestamp,
        });
    }

    let conn_entry = pid_conn_counts
        .entry(event.pid)
        .or_insert((0, event.timestamp));

    if event.timestamp - conn_entry.1 <= TIME_WINDOW_NS {
        conn_entry.0 += 1;
    } else {
        *conn_entry = (1, event.timestamp);
    }

    let conn_count = conn_entry.0;
    if conn_count == HIGH_CONN_THRESHOLD {
        suspicious.push(SuspiciousEvent {
            pid: event.pid,
            file: addr.clone(),
            reason: format!(
                "High-frequency connections: {} in 1s (possible DDoS/scanner)",
                conn_count
            ),
            severity: Severity::High,
            timestamp: event.timestamp,
        });
    } else if conn_count == MED_CONN_THRESHOLD {
        suspicious.push(SuspiciousEvent {
            pid: event.pid,
            file: addr.clone(),
            reason: format!("Elevated connection rate: {} in 1s", conn_count),
            severity: Severity::Medium,
            timestamp: event.timestamp,
        });
    }

    let ports_seen = pid_ports_seen.entry(event.pid).or_default();
    ports_seen.insert(event.port);

    if ports_seen.len() == 20 {
        suspicious.push(SuspiciousEvent {
            pid: event.pid,
            file: addr.clone(),
            reason: format!(
                "Possible port scan: {} unique ports contacted",
                ports_seen.len()
            ),
            severity: Severity::High,
            timestamp: event.timestamp,
        });
    }

    if event.sockfd < 0 {
        suspicious.push(SuspiciousEvent {
            pid: event.pid,
            file: addr.clone(),
            reason: format!("Invalid sockfd {} in network event", event.sockfd),
            severity: Severity::Low,
            timestamp: event.timestamp,
        });
    }

    suspicious.dedup_by(|a, b| {
        a.pid == b.pid && a.reason == b.reason && a.timestamp.abs_diff(b.timestamp) < TIME_WINDOW_NS
    });

    suspicious
}

pub fn detect_input_device_access(events: &[FileEvent]) -> Vec<SuspiciousEvent> {
    let mut suspicious = Vec::new();
    let mut pid_access_counts: HashMap<u32, (usize, u64)> = HashMap::new();
    let mut pid_devices_seen: HashMap<u32, HashSet<String>> = HashMap::new();

    for event in events {
        let filename = parse_filename(&event.filename);

        let device_match = INPUT_DEVICE_PATHS
            .iter()
            .find(|&&(path, _, _)| filename.starts_with(path));

        let Some(&(_, description, ref sev)) = device_match else {
            continue;
        };

        suspicious.push(SuspiciousEvent {
            pid: event.pid,
            file: filename.clone(),
            reason: description.to_string(),
            severity: match sev {
                Severity::High => Severity::High,
                Severity::Medium => Severity::Medium,
                Severity::Low => Severity::Low,
            },
            timestamp: event.timestamp,
        });

        if event.uid != 0 {
            suspicious.push(SuspiciousEvent {
                pid: event.pid,
                file: filename.clone(),
                reason: format!(
                    "Non-root UID {} reading raw input device - possible keylogger",
                    event.uid
                ),
                severity: Severity::High,
                timestamp: event.timestamp,
            });
        }

        for &(flag, reason) in SUSPICIOUS_INPUT_FLAGS {
            if event.flags & flag == flag {
                suspicious.push(SuspiciousEvent {
                    pid: event.pid,
                    file: filename.clone(),
                    reason: format!("{} on '{}'", reason, filename),
                    severity: Severity::High,
                    timestamp: event.timestamp,
                });
                break;
            }
        }

        if event.mode & 0o4000 != 0 {
            suspicious.push(SuspiciousEvent {
                pid: event.pid,
                file: filename.clone(),
                reason: format!("SUID bit set on input device access '{}'", filename),
                severity: Severity::High,
                timestamp: event.timestamp,
            });
        }
        if event.mode & 0o2000 != 0 {
            suspicious.push(SuspiciousEvent {
                pid: event.pid,
                file: filename.clone(),
                reason: format!("SGID bit set on input device access '{}'", filename),
                severity: Severity::Medium,
                timestamp: event.timestamp,
            });
        }

        let entry = pid_access_counts
            .entry(event.pid)
            .or_insert((0, event.timestamp));

        if event.timestamp - entry.1 <= TIME_WINDOW_NS {
            entry.0 += 1;
        } else {
            *entry = (1, event.timestamp);
        }

        let count = entry.0;
        if count == HIGH_READ_THRESHOLD {
            suspicious.push(SuspiciousEvent {
                pid: event.pid,
                file: filename.clone(),
                reason: format!(
                    "High-frequency input device polling: {} reads/s - likely a keylogger",
                    count
                ),
                severity: Severity::High,
                timestamp: event.timestamp,
            });
        } else if count == MED_READ_THRESHOLD {
            suspicious.push(SuspiciousEvent {
                pid: event.pid,
                file: filename.clone(),
                reason: format!("Elevated input device polling: {} reads/s", count),
                severity: Severity::Medium,
                timestamp: event.timestamp,
            });
        }

        let devices = pid_devices_seen.entry(event.pid).or_default();
        devices.insert(filename.clone());

        if devices.len() == 5 {
            suspicious.push(SuspiciousEvent {
                pid: event.pid,
                file: filename.clone(),
                reason: format!(
                    "PID {} accessing {} distinct input devices - scraping all inputs",
                    event.pid,
                    devices.len()
                ),
                severity: Severity::High,
                timestamp: event.timestamp,
            });
        }

        if event.dir_fd != libc::AT_FDCWD && event.dir_fd < 0 {
            suspicious.push(SuspiciousEvent {
                pid: event.pid,
                file: filename.clone(),
                reason: format!(
                    "Invalid dir_fd {} used to open input device '{}'",
                    event.dir_fd, filename
                ),
                severity: Severity::Low,
                timestamp: event.timestamp,
            });
        }
    }

    suspicious.dedup_by(|a, b| {
        a.pid == b.pid && a.reason == b.reason && a.timestamp.abs_diff(b.timestamp) < TIME_WINDOW_NS
    });

    suspicious
}
