#![allow(unused)]
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, Write},
    path::PathBuf,
    thread::panicking,
};

use libc::locale_t;
use rkyv::{
    Archive,
    bytecheck::CheckBytes,
    de::Pool,
    rancor::{Error, Strategy},
    to_bytes,
};
use tokio::sync::mpsc::Sender;

use crate::{AppEvent, PrivilegeEvent, ProcessEvent, STATE_PATH, SuspiciousEvent, app::UiEvent};
use bpfx::file::*;
use bpfx::network::*;
use bpfx::process::*;

pub const PER_BATCH_SIZE: usize = 1000;

#[derive(Debug, Clone, Copy, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)]
pub struct BatchInfo {
    pub file_offset: u64,
    pub count: usize,
}

impl Default for BatchInfo {
    fn default() -> Self {
        Self {
            file_offset: 0,
            count: PER_BATCH_SIZE,
        }
    }
}

fn log_path() -> anyhow::Result<PathBuf> {
    Ok(STATE_PATH
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("failed to find state path"))?
        .join("events.bin"))
}

fn index_path() -> anyhow::Result<PathBuf> {
    Ok(STATE_PATH
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("failed to find state path"))?
        .join("index.bin"))
}

pub fn write_batch_info_to_disk(info: BatchInfo) -> anyhow::Result<(), anyhow::Error> {
    let path = index_path()?;

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let bytes = to_bytes::<Error>(&info)?;

    file.write_all(&(bytes.len() as u32).to_le_bytes())?;
    file.write_all(&bytes)?;

    Ok(())
}

pub fn read_batch_info() -> anyhow::Result<Vec<BatchInfo>, anyhow::Error> {
    tracing::info!("called read_batch_info");
    let mut info = Vec::new();
    let path = index_path()?;
    let mut file = File::open(path)?;

    loop {
        let mut len = [0u8; 4];
        if file.read_exact(&mut len).is_err() {
            break;
        }

        let len = u32::from_le_bytes(len) as usize;
        let mut content = vec![0; len];
        file.read_exact(&mut content);

        let event = rkyv::from_bytes::<BatchInfo, Error>(&content)?;
        info.push(event);
    }

    Ok(info)
}

pub fn read_batch(batch: usize) -> anyhow::Result<Vec<UiEvent>> {
    tracing::info!("reading from disk..");
    let batch_info = read_batch_info()?;
    let path = log_path()?;
    let mut file = File::open(path)?;

    let info = &batch_info[batch];

    file.seek(std::io::SeekFrom::Start(info.file_offset))?;

    let mut len = [0u8; 4];
    file.read_exact(&mut len)?;

    let len = u32::from_le_bytes(len) as usize;

    let mut content = vec![0; len];
    file.read_exact(&mut content)?;
    let output = rkyv::from_bytes::<Vec<UiEvent>, Error>(&content)?;
    tracing::info!("returned batch len: {}", output.len());
    Ok(output)
}

pub async fn write_to_disk(event: &Vec<UiEvent>) -> anyhow::Result<u64> {
    let path = log_path()?;
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let start_offset = file.metadata()?.len();
    let bytes = to_bytes::<Error>(event)?;
    file.write_all(&(bytes.len() as u32).to_le_bytes())?;
    file.write_all(&bytes)?;
    Ok(start_offset)
}

pub fn read_from_log(file_offset: u64) -> anyhow::Result<Vec<UiEvent>, anyhow::Error> {
    let mut events = Vec::new();
    let path = log_path()?;
    let mut file = File::open(path)?;

    file.seek(std::io::SeekFrom::Start(file_offset))?;

    let mut len = [0u8; 4];
    file.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    let mut content = vec![0; len];
    file.read_exact(&mut content)?;

    let event = rkyv::from_bytes::<Vec<UiEvent>, Error>(&content)?;
    events.extend(event);

    Ok(events)
}

#[test]
fn test_write() {
    let mut events: Vec<AppEvent> = Vec::new();
    let event_header = bpfx::EventHeader {
        timestamp_ns: 123,
        pid: 1,
        tid: 23,
        ppid: 345,
        uid: 123,
        gid: 123,
        comm: String::new(),
    };

    events.push(AppEvent::ProcessStart(ProcessStartEvent {
        header: event_header,
        filename: String::new(),
    }));

    let event_header_2 = bpfx::EventHeader {
        timestamp_ns: 130,
        pid: 13,
        tid: 233,
        ppid: 3245,
        uid: 183,
        gid: 153,
        comm: String::new(),
    };

    events.push(AppEvent::ProcessStart(ProcessStartEvent {
        header: event_header_2,
        filename: String::new(),
    }));

    // write_to_disk(&events).unwrap();
    // write_to_disk(ev2).unwrap();
    // panic!("{:#?}", read_from_log().unwrap().len());

    panic!("{:?}", read_batch_info().unwrap());

    // assert_eq!(true, read_from_log(&ev).is_ok());
}
