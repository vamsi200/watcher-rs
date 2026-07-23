#![allow(unused)]
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
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

use bpfx::file::*;
use bpfx::network::*;
use bpfx::process::*;

use crate::{AppEvent, PrivilegeEvent, ProcessEvent, SuspiciousEvent};

pub fn write_to_disk(event: &Vec<AppEvent>) -> anyhow::Result<(), anyhow::Error> {
    let mut file = OpenOptions::new().append(true).open("./log")?;

    let bytes = to_bytes::<Error>(event)?;

    file.write_all(&(bytes.len() as u32).to_le_bytes())?;
    file.write_all(&bytes)?;

    Ok(())
}

pub fn read_from_log(ev: &[AppEvent]) -> anyhow::Result<Vec<AppEvent>, anyhow::Error> {
    let mut events = Vec::new();
    let mut file = File::open("./log")?;
    loop {
        let mut len = [0u8; 4];
        if file.read_exact(&mut len).is_err() {
            break;
        }
        let len = u32::from_le_bytes(len) as usize;
        let mut content = vec![0; len];
        file.read_exact(&mut content)?;

        let event = rkyv::from_bytes::<Vec<AppEvent>, Error>(&content)?;
        events.extend(event);
    }

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

    events.push(AppEvent::Exec(ProcessStartEvent {
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

    events.push(AppEvent::Exec(ProcessStartEvent {
        header: event_header_2,
        filename: String::new(),
    }));

    // write_to_disk(&events).unwrap();
    // write_to_disk(ev2).unwrap();
    panic!("{:#?}", read_from_log(&events));
    // assert_eq!(true, read_from_log(&ev).is_ok());
}
