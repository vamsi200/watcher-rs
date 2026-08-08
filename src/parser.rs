#![allow(unused)]
use crate::helper::{bytes_to_str, is_root_only_path, parse_addr};
use crate::*;
use bpfx::NetworkEvent;
use std::collections::{HashMap, HashSet, VecDeque};
use std::{
    ffi::CStr,
    fs::{self, File},
    io::{BufRead, BufReader, Read},
    os::unix::fs::PermissionsExt,
    path::{self, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use std::{ptr::read, thread::sleep};

// pub fn get_running_processes() -> Result<Vec<ProcessInfo>> {
//     let read_dir = fs::read_dir("/proc/")?;
//     let mut process_info: Vec<ProcessInfo> = Vec::new();
//
//     for entry in read_dir {
//         let entry = entry?;
//
//         if entry.file_type()?.is_dir() {
//             if let Some(pid_str) = entry.file_name().to_str() {
//                 if pid_str.chars().all(|c| c.is_ascii_digit()) {
//                     let info = ProcessInfo::get_process_info_from_pid(pid_str.parse()?);
//                     process_info.push(info);
//                 }
//             }
//         }
//     }
//
//     Ok(process_info)
// }

//TODO:
// pub fn track_process_exec(ring_buf: &mut RingBuf<&mut MapData>) -> Result<Option<ProcessEvent>> {
//     let mut p_event: Option<ProcessEvent> = None;
//
//     if let Some(data) = ring_buf.next() {
//         let event = unsafe { read(data.as_ptr() as *const ExecEvent) };
//         let proc_info = ProcessInfo::get_process_info_from_pid(event.pid);
//
//         let mut uid = 0u32;
//         if let Ok(mut file) = File::open(format!("/proc/{}/status", event.pid)) {
//             let reader = BufReader::new(file);
//
//             for line in reader.lines() {
//                 let line = line?;
//                 let split: Vec<&str> = line.trim().split(":").collect();
//                 match split[0] {
//                     "Uid" => {
//                         if let Some(s) = split[1].split_whitespace().nth(1) {
//                             uid = s.parse()?;
//                         }
//                     }
//                     _ => {}
//                 }
//             }
//         }
//
//         p_event = Some(ProcessEvent {
//             info: proc_info,
//             uid: uid,
//             timestamp: event.timestamp,
//         })
//     }
//
//     Ok(p_event)
// }

// #[derive(Debug)]
// pub enum Event {
//     ProcessExec(ExecEvent),
//     ProcessExit(ProcessExitEvent),
//     FileOpen(FileEvent),
//     FileClose(FileCloseEvent),
//     Network(NetworkEvent),
//     Unknown(u32),
// }
//
// pub fn ret_event(ring_buf: &mut RingBuf<&mut MapData>) -> Option<AppEvent> {
//     let data = ring_buf.next()?;
//     let ptr = data.as_ptr();
//
//     let header = unsafe { read(ptr as *const EventHeader) };
//
//     let event = match header.kind {
//         0 => AppEvent::Exec(unsafe { read(ptr as *const ExecEvent) }),
//         1 => AppEvent::ExecExit(unsafe { read(ptr as *const ProcessExitEvent) }),
//         2 => AppEvent::File(unsafe { read(ptr as *const FileEvent) }),
//         3 => AppEvent::FileClose(unsafe { read(ptr as *const FileCloseEvent) }),
//         4 => AppEvent::Network(unsafe { read(ptr as *const NetworkEvent) }),
//         k => return None,
//     };
//
//     Some(event)
// }
