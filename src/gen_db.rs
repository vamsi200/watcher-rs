#![allow(unused)]
use std::{
    fs::{self, File, OpenOptions, create_dir, exists},
    io::{BufRead, BufReader, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::LazyLock,
};

use directories::ProjectDirs;
use libc::{setgid, setuid};
use rkyv::{rancor::Error, to_bytes};

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)]
pub struct EntryV4 {
    pub ip: u32,
    pub score: u8,
}

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)]
pub struct EntryV6 {
    pub ip: u128,
    pub score: u8,
}

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)]
pub struct IpsumDb {
    pub v4: Box<[EntryV4]>,
    pub v6: Box<[EntryV6]>,
}

pub fn drop_privleges() -> anyhow::Result<()> {
    tracing::info!("dropping privileges..");
    let gid = std::env::var("SUDO_GID").ok();
    let uid = std::env::var("SUDO_UID").ok();

    if let Some(gid) = gid
        && let Some(uid) = uid
    {
        unsafe {
            setgid(u32::from_str(&gid).unwrap());
            setuid(u32::from_str(&uid).unwrap());
        }
    } else {
        return anyhow::bail!("Failed to get gid and uid");
    }

    Ok(())
}

pub fn parse_ipsum(path: Option<&PathBuf>) -> anyhow::Result<()> {
    let Some(path) = path else {
        anyhow::bail!("Failed to get state dir");
    };

    let mut ipsum_bin = path.join("ipsum.bin");
    if exists(&ipsum_bin)? {
        return Ok(());
    }

    let mut file = File::open(path.join("ipsum.txt"))?;

    let mut ipsum_bin = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(ipsum_bin)?;

    let mut buf = String::new();
    let mut buf_reader = BufReader::new(file);
    let mut v4_map: Vec<EntryV4> = Vec::new();
    let mut v6_map: Vec<EntryV6> = Vec::new();

    loop {
        buf.clear();
        let n = buf_reader.read_line(&mut buf)?;

        if buf.starts_with("#") {
            continue;
        }

        let mut split_iter = buf.split_whitespace();

        if let Some(ip) = split_iter.next()
            && let Some(black_list_count) = split_iter.next()
        {
            if let Ok(ip) = IpAddr::from_str(ip)
                && let Ok(score) = u8::from_str(black_list_count)
            {
                match ip {
                    IpAddr::V4(ip) => {
                        let ip = u32::from(ip);
                        v4_map.push(EntryV4 { ip, score });
                    }
                    IpAddr::V6(ip) => {
                        let ip = u128::from(ip);
                        v6_map.push(EntryV6 { ip, score });
                    }
                }
            }
        }

        if n == 0 {
            break;
        }
    }

    v4_map.sort_unstable_by_key(|e| e.ip);
    v6_map.sort_unstable_by_key(|e| e.ip);

    let db = IpsumDb {
        v4: v4_map.into_boxed_slice(),
        v6: v6_map.into_boxed_slice(),
    };

    let bytes = to_bytes::<Error>(&db)?;
    ipsum_bin.write_all(&bytes);

    Ok(())
}
