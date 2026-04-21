#![allow(unused)]

pub struct ProcessInfo {
    pid: u32,
    ppid: u32,
    name: String,
    cmdline: String,
}

pub struct ProcessEvent {
    pid: u32,
    ppid: u32,
    name: String,
    cmdline: String,
    uid: u32,
    timestamp: u64,
}

struct FileEvent {
    pid: u32,
    path: String,
    flags: String,
    timestamp: u64,
}

pub struct ProcessExitEvent {
    pid: u32,
    timestamp: u64,
}

struct NetworkEvent {
    pid: u32,
    dest_ip: String,
    dest_port: u16,
    protocol: String,
    timestamp: u64,
}

struct PrivilegeEvent {
    pid: u32,
    uid: u32,
    binary: String,
    is_setuid: bool,
    timestamp: u64,
}

struct SuspiciousEvent {
    pid: u32,
    reason: String,
    severity: Severity,
    timestamp: u64,
}

enum Severity {
    Low,
    Medium,
    High,
}

fn get_running_processes() -> Vec<ProcessInfo> {
    todo!();
}

fn track_prkocess_exec() -> Vec<ProcessEvent> {
    todo!()
}

fn track_process_exit() -> Vec<ProcessExitEvent> {
    todo!()
}

fn track_file_open() -> Vec<FileEvent> {
    todo!()
}

fn track_network_connect() -> Vec<NetworkEvent> {
    todo!()
}

//???
fn detect_privileged_exec() -> Vec<PrivilegeEvent> {
    todo!()
}

fn detect_suspicious_file_access(events: &[FileEvent]) -> Vec<SuspiciousEvent> {
    todo!()
}

fn detect_suspicious_network(events: &[NetworkEvent]) -> Vec<SuspiciousEvent> {
    todo!()
}

fn detect_input_device_access(events: &[FileEvent]) -> Vec<SuspiciousEvent> {
    todo!()
}
