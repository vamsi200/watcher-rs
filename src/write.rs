use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, Write},
    path::PathBuf,
};

use rkyv::{rancor::Error, to_bytes, util::AlignedVec};

use crate::{STATE_PATH, app::UiEvent};

pub const PER_BATCH_SIZE: usize = 1000;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy)]
pub struct LogConfig {
    pub max_segment_size_mib: f64,
    pub max_storage_size_gib: f64,
}

pub struct RuntimeLogConfig {
    pub max_segment_size: u64,
    pub max_storage_size: u64,
}

impl From<LogConfig> for RuntimeLogConfig {
    fn from(config: LogConfig) -> Self {
        Self {
            max_segment_size: (config.max_segment_size_mib * 1024.0 * 1024.0) as u64,
            max_storage_size: (config.max_storage_size_gib * 1024.0 * 1024.0 * 1024.0) as u64,
        }
    }
}

#[derive(Debug, Clone, Copy, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)]
pub struct BatchInfo {
    pub segment_id: u64,
    pub file_offset: u64,
    pub count: usize,
}

impl Default for BatchInfo {
    fn default() -> Self {
        Self {
            segment_id: 0,
            file_offset: 0,
            count: PER_BATCH_SIZE,
        }
    }
}

pub fn log_path() -> color_eyre::Result<PathBuf> {
    Ok(STATE_PATH
        .as_ref()
        .ok_or_else(|| color_eyre::eyre::eyre!("failed to find state path"))?
        .join("events.bin.0"))
}

pub fn index_path() -> color_eyre::Result<PathBuf> {
    Ok(STATE_PATH
        .as_ref()
        .ok_or_else(|| color_eyre::eyre::eyre!("failed to find state path"))?
        .join("index.bin"))
}

pub fn prune_batch_info(segment_id: u64) -> color_eyre::Result<()> {
    tracing::info!("pruning old batch info of id - {}", segment_id);
    let mut batch_info = read_batch_info()?;

    let first_valid = batch_info
        .iter()
        .position(|info| info.segment_id > segment_id)
        .unwrap_or(batch_info.len());

    batch_info.drain(..first_valid);

    for batch in batch_info {
        write_batch_info_to_disk(batch)?;
    }

    Ok(())
}

pub fn write_batch_info_to_disk(
    info: BatchInfo,
) -> color_eyre::Result<(), color_eyre::eyre::Error> {
    let path = index_path()?;

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let bytes = to_bytes::<Error>(&info)?;

    file.write_all(&(bytes.len() as u32).to_le_bytes())?;
    file.write_all(&bytes)?;

    Ok(())
}

pub fn read_batch_info() -> color_eyre::Result<Vec<BatchInfo>, color_eyre::eyre::Error> {
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
        file.read_exact(&mut content)?;

        let event = rkyv::from_bytes::<BatchInfo, Error>(&content)?;
        info.push(event);
    }

    Ok(info)
}

pub fn read_batch(batch: usize, batch_info: &[BatchInfo]) -> color_eyre::Result<Vec<UiEvent>> {
    tracing::info!("reading batch {}", batch);

    let info = batch_info
        .get(batch)
        .ok_or_else(|| color_eyre::eyre::eyre!("batch {} does not exist", batch))?;

    let path = segment_path(info.segment_id);
    let mut file = File::open(path)?;

    file.seek(std::io::SeekFrom::Start(info.file_offset))?;

    let mut len = [0u8; 4];
    file.read_exact(&mut len)?;

    let len = u32::from_le_bytes(len) as usize;

    let mut content = vec![0u8; len];
    file.read_exact(&mut content)?;

    let output = rkyv::from_bytes::<Vec<UiEvent>, Error>(&content)?;

    tracing::info!("returned batch len: {}", output.len());

    Ok(output)
}

pub fn serialize_event_data(event: &Vec<UiEvent>) -> color_eyre::eyre::Result<AlignedVec> {
    Ok(to_bytes::<Error>(event)?)
}

pub fn segment_path(id: u64) -> PathBuf {
    let path = STATE_PATH.as_ref().unwrap().clone();
    path.join(format!("events.bin.{id}"))
}

pub fn write_to_disk(path: &PathBuf, bytes: AlignedVec) -> color_eyre::eyre::Result<u64> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let start_offset = file.metadata()?.len();
    file.write_all(&(bytes.len() as u32).to_le_bytes())?;
    file.write_all(&bytes)?;
    Ok(start_offset)
}

#[test]
fn test_write() {
    // let events: Vec<AppEvent> = Vec::new();
    // let event_header = bpfx::EventHeader {
    //     timestamp_ns: 123,
    //     pid: 1,
    //     tid: 23,
    //     ppid: 345,
    //     uid: 123,
    //     gid: 123,
    //     comm: String::new(),
    // };

    // events.push(AppEvent::ProcessStart(ProcessStartEvent {
    //     header: event_header,
    //     filename: String::new(),
    // }));
    //
    // let event_header_2 = bpfx::EventHeader {
    //     timestamp_ns: 130,
    //     pid: 13,
    //     tid: 233,
    //     ppid: 3245,
    //     uid: 183,
    //     gid: 153,
    //     comm: String::new(),
    // };
    //
    // events.push(AppEvent::ProcessStart(ProcessStartEvent {
    //     header: event_header_2,
    //     filename: String::new(),
    // }));

    // write_to_disk(&events).unwrap();
    // write_to_disk(ev2).unwrap();
    // panic!("{:#?}", read_from_log().unwrap().len());

    panic!("{:?}", read_batch_info().unwrap());

    // assert_eq!(true, read_from_log(&ev).is_ok());
}
