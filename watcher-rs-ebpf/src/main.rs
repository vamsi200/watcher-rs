#![no_main]
#![no_std]
#![allow(unused)]
#![allow(non_camel_case_types)]

mod bindings;
use crate::bindings::{dentry, file, path};
use aya_ebpf::EbpfContext;
use aya_ebpf::bindings::bpf_core_relo_kind::BPF_CORE_FIELD_BYTE_OFFSET;
use aya_ebpf::cty::c_char;
use aya_ebpf::helpers::r#gen::{
    bpf_d_path, bpf_ktime_get_ns, bpf_probe_read_kernel_str, bpf_probe_read_str,
    bpf_probe_read_user_str,
};
use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel,
    bpf_probe_read_user,
};
use aya_ebpf::macros::{lsm, tracepoint};
use aya_ebpf::maps::{Array, RingBuf};
use aya_ebpf::programs::{FEntryContext, LsmContext, TracePointContext};
use aya_ebpf::programs::{fentry, tracepoint};
use aya_ebpf_macros::{fentry, map};
use aya_log_ebpf::info;
use core::ffi::c_int;
use core::panic::PanicInfo;
use core::ptr::null;
use watcher_rs_common::*;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

#[map]
static DROPPED: Array<u32> = Array::with_max_entries(1, 0);

#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> i32 {
    match unsafe { try_sys_enter_execve(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

pub fn try_sys_enter_execve(ctx: TracePointContext) -> Result<i32, i32> {
    unsafe {
        let mut entry = match EVENTS.reserve::<ExecEvent>(0) {
            Some(e) => e,
            None => return Ok(0),
        };

        let filename_ptr: u64 = match ctx.read_at(16) {
            Ok(v) => v,
            Err(_) => {
                entry.discard(0);
                return Ok(0);
            }
        };

        let mut filename = [0u8; 256];
        bpf_probe_read_user_str(
            filename.as_mut_ptr() as *mut _,
            filename.len() as u32,
            filename_ptr as *const _,
        );

        let tgid = bpf_get_current_pid_tgid();
        let pid = (tgid >> 32) as u32;
        let uid_gid = bpf_get_current_uid_gid();
        let uid = uid_gid as u32;
        let ts = bpf_ktime_get_ns();

        entry.write(ExecEvent {
            kind: EventType::ExecEvent as u32,
            pid,
            uid,
            timestamp: ts,
            filename,
        });

        entry.submit(0);
    }
    Ok(0)
}

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> i32 {
    match unsafe { try_sys_enter_openat(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

pub fn try_sys_enter_openat(ctx: TracePointContext) -> Result<i32, i32> {
    unsafe {
        let mut entry = match EVENTS.reserve::<FileEvent>(0) {
            Some(e) => e,
            None => {
                if let Some(val) = DROPPED.get_ptr_mut(0) {
                    *val += 1;
                }
                return Ok(0);
            }
        };

        let dir_fd: i32 = match ctx.read_at(16) {
            Ok(p) => p,
            Err(_) => {
                entry.discard(0);
                return Ok(0);
            }
        };

        let filename_ptr: u64 = match ctx.read_at(24) {
            Ok(fp) => fp,
            Err(_) => {
                entry.discard(0);
                return Ok(0);
            }
        };

        let flags: i32 = match ctx.read_at(32) {
            Ok(fl) => fl,
            Err(_) => {
                entry.discard(0);
                return Ok(0);
            }
        };

        let mode: i32 = match ctx.read_at(40) {
            Ok(m) => m,
            Err(_) => {
                entry.discard(0);
                return Ok(0);
            }
        };

        let mut filename = [0u8; 256];

        bpf_probe_read_user_str(
            filename.as_mut_ptr() as *mut _,
            filename.len() as u32,
            filename_ptr as *const _,
        );

        let tgid = bpf_get_current_pid_tgid();
        let pid = (tgid >> 32) as u32;
        let gid = bpf_get_current_uid_gid();
        let uid = gid as u32;
        let timestamp = bpf_ktime_get_ns();

        entry.write(FileEvent {
            kind: EventType::FileOpen as u32,
            pid,
            uid,
            dir_fd,
            filename,
            mode,
            flags,
            timestamp,
        });
        entry.submit(0);
    }
    Ok(0)
}

#[tracepoint]
pub fn sys_enter_connect(ctx: TracePointContext) -> i32 {
    match unsafe { try_sys_enter_connect(ctx) } {
        Ok(v) => v,
        Err(e) => 0,
    }
}

pub fn try_sys_enter_connect(ctx: TracePointContext) -> Result<i32, i32> {
    unsafe {
        let mut addr_buf = [0u8; 16];
        let mut port: u16 = 0;
        let mut family: u16 = 0;

        let sock_fd: i32 = ctx.read_at(16).unwrap_or(0);
        let sock_ptr: u64 = ctx.read_at(24).unwrap_or(0);
        let mut event = match EVENTS.reserve::<NetworkEvent>(0) {
            Some(ev) => ev,
            None => {
                if let Some(val) = DROPPED.get_ptr_mut(0) {
                    *val += 1;
                }
                return Ok(0);
            }
        };
        if sock_ptr == 0 {
            event.discard(0);
            return Ok(0);
        }

        let family: u16 = if let Ok(f) = bpf_probe_read_user(sock_ptr as *const u16) {
            f
        } else {
            event.discard(0);
            return Ok(0);
        };

        const AF_INET: u16 = 2;
        const AF_INET6: u16 = 10;

        if family != AF_INET && family != AF_INET6 {
            event.discard(0);
            return Ok(0);
        }

        let tgid = bpf_get_current_pid_tgid();
        let pid = (tgid >> 32) as u32;
        let timestamp = bpf_ktime_get_ns();

        if family == AF_INET {
            let sa = SockAddrIn {
                sin_family: 0,
                sin_port: 0,
                sin_addr: [0u8; 4],
                _pad: [0u8; 8],
            };

            let sa: SockAddrIn = match bpf_probe_read_user(sock_ptr as *const SockAddrIn) {
                Ok(v) => v,
                Err(_) => {
                    event.discard(0);
                    return Ok(0);
                }
            };
            port = u16::from_be(sa.sin_port);
            addr_buf[..4].copy_from_slice(&sa.sin_addr);
        } else if family == AF_INET6 {
            let sa = SockaddrIn6 {
                sin6_family: 0,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: [0u8; 16],
                sin6_scope_id: 0,
            };

            let sa: SockaddrIn6 = match bpf_probe_read_user(sock_ptr as *const SockaddrIn6) {
                Ok(v) => v,
                Err(_) => {
                    event.discard(0);
                    return Ok(0);
                }
            };
            port = u16::from_be(sa.sin6_port);
            addr_buf.copy_from_slice(&sa.sin6_addr);
        }

        event.write(NetworkEvent {
            kind: EventType::Network as u32,
            pid,
            port,
            sockfd: sock_fd,
            family,
            addr: addr_buf,
            timestamp,
        });

        event.submit(0);
    }

    Ok(0)
}

#[tracepoint]
pub fn sched_process_exit(ctx: TracePointContext) -> i32 {
    match unsafe { try_sched_process_exit(ctx) } {
        Ok(k) => k,
        Err(_) => 0,
    }
}

pub fn try_sched_process_exit(ctx: TracePointContext) -> Result<i32, i32> {
    unsafe {
        let tgid = bpf_get_current_pid_tgid();
        let pid = (tgid >> 32) as u32;
        let timestamp = bpf_ktime_get_ns();

        let mut event = match EVENTS.reserve::<ProcessExitEvent>(0) {
            Some(ev) => ev,
            None => {
                if let Some(val) = DROPPED.get_ptr_mut(0) {
                    *val += 1;
                }
                return Ok(0);
            }
        };

        event.write(ProcessExitEvent {
            kind: EventType::ExecExit as u32,
            pid,
            timestamp,
        });

        event.submit(0);
    }
    Ok(0)
}

#[fentry]
pub fn filp_close(ctx: FEntryContext) -> i32 {
    match try_file_close(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

pub fn try_file_close(ctx: FEntryContext) -> Result<i32, i32> {
    unsafe {
        let tgid = bpf_get_current_pid_tgid();
        let pid = (tgid >> 32) as u32;
        let timestamp = bpf_ktime_get_ns();
        let file: *const file = ctx.arg(0);
        let mut event = match EVENTS.reserve::<FileCloseEvent>(0) {
            Some(ev) => ev,
            None => {
                if let Some(val) = DROPPED.get_ptr_mut(0) {
                    *val += 1;
                }

                return Ok(0);
            }
        };

        if file.is_null() {
            event.discard(0);
            return Ok(0);
        }

        let mut filename = [0u8; 256];
        let f_path: *const path = &(*file).__bindgen_anon_1.f_path;
        let dentry: *const dentry = (*f_path).dentry;
        let name_ptr = (*dentry).__bindgen_anon_1.d_name.name;
        bpf_probe_read_kernel_str(
            filename.as_mut_ptr() as *mut _,
            filename.len() as u32,
            name_ptr as *const _,
        );
        event.write(FileCloseEvent {
            kind: EventType::FileClose as u32,
            pid,
            timestamp,
            file_name: filename,
        });
        event.submit(0);
    }
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}
