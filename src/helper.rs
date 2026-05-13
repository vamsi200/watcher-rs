#![allow(unused)]
use std::fs::File;
use std::io::Read;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Local};
use nix::time::{ClockId, clock_gettime};

pub fn parse_addr(family: u16, addr: &[u8; 16]) -> String {
    match family {
        2 => format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]),
        10 => format!(
            "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:\
             {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            addr[0],
            addr[1],
            addr[2],
            addr[3],
            addr[4],
            addr[5],
            addr[6],
            addr[7],
            addr[8],
            addr[9],
            addr[10],
            addr[11],
            addr[12],
            addr[13],
            addr[14],
            addr[15]
        ),
        _ => format!("{:?}", &addr[..]),
    }
}

pub fn extract_ipv4_bytes(family: u16, addr: &[u8; 16]) -> Option<&[u8]> {
    if family == 2 { Some(&addr[..4]) } else { None }
}

pub fn bytes_to_str(raw: &[u8; 256]) -> String {
    // improve this later
    let end = raw.iter().position(|&b| b == 0).unwrap_or(256);
    String::from_utf8_lossy(&raw[..end]).to_string()
}

pub fn flags_to_op(flags: i32) -> &'static str {
    // O_WRONLY=1 O_RDWR=2
    match flags & 0x3 {
        1 => "W",
        2 => "RW",
        _ => "R",
    }
}

pub fn format_timestamp_ns(ns: u64, use_24hr: bool) -> String {
    let realtime_ns = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let mono = clock_gettime(ClockId::CLOCK_MONOTONIC).unwrap();
    let mono_ns = mono.tv_sec() as u64 * 1_000_000_000 + mono.tv_nsec() as u64;
    let wallclock_ns = realtime_ns - mono_ns + ns;
    let secs = (wallclock_ns / 1_000_000_000) as i64;
    let nanos = (wallclock_ns % 1_000_000_000) as u32;

    let dt = DateTime::from_timestamp(secs, nanos)
        .unwrap()
        .with_timezone(&Local);

    if use_24hr {
        dt.format("%H:%M:%S%.3f").to_string()
    } else {
        dt.format("%I:%M:%S%.3f %p").to_string()
    }
}

pub fn is_sensitive_path(path: &str) -> bool {
    const SENSITIVE: &[&str] = &[
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/crontab",
        "/etc/cron",
        "/root/",
        "/proc/",
        "/sys/",
        "/.ssh/",
    ];
    SENSITIVE.iter().any(|s| path.starts_with(s))
}

pub fn is_root_only_path(filename: &str) -> bool {
    const ROOT_ONLY: &[&str] = &[
        "/etc/shadow",
        "/etc/sudoers",
        "/root/",
        "/boot/",
        "/sys/kernel/security/",
        "/proc/kcore",
    ];
    ROOT_ONLY.iter().any(|&p| filename.starts_with(p))
}

pub fn parse_uptime() -> String {
    let mut file = File::open("/proc/uptime").unwrap();
    let mut buf = String::new();
    file.read_to_string(&mut buf).unwrap();
    let uptime_secs = buf
        .split('.')
        .next()
        .expect("Failed to parse uptime")
        .parse::<u64>()
        .unwrap();

    let hours = uptime_secs / 3600;
    let minutes = uptime_secs % 3600 / 60;
    let secs = uptime_secs % 60;
    let out_string = format!("{hours}:{minutes}:{secs}");
    out_string
}
