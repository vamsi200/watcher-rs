#![allow(unused)]
#![no_std]

#[repr(C)]
#[derive(Debug, Clone)]
pub struct ExecEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub timestamp: u64,
    pub filename: [u8; 256],
}

#[repr(u32)]
#[derive(Debug)]
pub enum EventType {
    ExecEvent = 0,
    ExecExit = 1,
    FileOpen = 2,
    FileClose = 3,
    Network = 4,
}

#[repr(C)]
pub struct EventHeader {
    pub kind: u32,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FileEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub dir_fd: i32,
    pub filename: [u8; 256],
    pub mode: i32,
    pub flags: i32,
    pub timestamp: u64,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct SockAddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: [u8; 4],
    pub _pad: [u8; 8],
}

#[repr(C)]
pub struct SockaddrIn6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: [u8; 16],
    pub sin6_scope_id: u32,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct NetworkEvent {
    pub kind: u32,
    pub pid: u32,
    pub sockfd: i32,
    pub family: u16,
    pub port: u16,
    pub addr: [u8; 16],
    pub timestamp: u64,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct ProcessExitEvent {
    pub kind: u32,
    pub pid: u32,
    pub timestamp: u64,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FileCloseEvent {
    pub kind: u32,
    pub file_name: [u8; 256],
    pub pid: u32,
    pub timestamp: u64,
}
