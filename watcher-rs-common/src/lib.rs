#[repr(C)]
#[derive(Debug)]
pub struct ExecEvent {
    pub pid: u32,
    pub uid: u32,
    pub timestamp: u64,
    pub filename: [u8; 256],
}
