#![no_main]
#![no_std]
#![allow(unused)]
#![allow(non_camel_case_types)]

use aya_ebpf::bindings::bpf_core_relo_kind::BPF_CORE_FIELD_BYTE_OFFSET;
use aya_ebpf::bindings::file;
use aya_ebpf::cty::c_char;
use aya_ebpf::helpers::r#gen::{
    bpf_d_path, bpf_ktime_get_ns, bpf_probe_read_kernel_str, bpf_probe_read_str,
    bpf_probe_read_user_str,
};
use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel,
};
use aya_ebpf::macros::{lsm, tracepoint};
use aya_ebpf::maps::RingBuf;
use aya_ebpf::programs::tracepoint;
use aya_ebpf::programs::{FEntryContext, LsmContext, TracePointContext};
use aya_ebpf::{EbpfContext, bindings};
use aya_ebpf_macros::map;
use aya_log_ebpf::info;
use core::ffi::c_int;
use core::panic::PanicInfo;
use core::ptr::null;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1024, 0);

#[repr(C)]
#[derive(Debug)]
pub struct ExecEvent {
    pid: u32,
    uid: u32,
    timestamp: u64,
    filename: [u8; 256],
}

#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) {
    match unsafe { try_sys_enter_execve(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    };
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
            pid,
            uid,
            timestamp: ts,
            filename,
        });

        entry.submit(0);
    }
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}
