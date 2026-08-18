# watcher-rs

**watcher-rs** is a Linux security observability tool that provides a real-time view of **process, network, and file-system activity** using eBPF.

It is designed to sit somewhere between a traditional system monitor and a security monitoring tool: it continuously observes system activity, presents events interactively in a terminal UI.
> **watcher-rs is an observability tool, not a complete intrusion-detection or malware-analysis system.**


## Features

- Real-time Linux system observability through eBPF
- Process lifecycle monitoring
- Network activity monitoring
- File-system activity monitoring
- Configurable event classification rules
- IP reputation lookup using the [IPsum](https://github.com/stamparm/ipsum) database
- Interactive terminal UI built with [Ratatui](https://ratatui.rs/)
- Live stream / follow-tail mode
- Persistent event storage per **run**

# What does watcher-rs observe?

watcher-rs uses **[bpfx](https://github.com/vamsi200/bpfx/)**, an eBPF library written specifically for this project, to collect low-level kernel events.

The events currently exposed to watcher-rs fall into three major categories.

## Process events

Process lifecycle activity is represented by:

```rust
pub enum ProcessEvent {
    Start(ProcessStartEvent),
    Fork(ProcessForkEvent),
    Exit(ProcessExitEvent),
}
```

## Network events

Network activity is represented by:

```rust
pub enum NetworkEvent {
    Connect(ConnectEvent),
    Accept(AcceptEvent),
    Close(CloseEvent),
    Bind(BindEvent),
    Listen(ListenEvent),
}
```

## File events

File-system activity is represented by:

```rust
pub enum FileEvent {
    Open(FileOpenEvent),
    Read(FileReadEvent),
    Close(FileCloseEvent),
    Write(FileWriteEvent),
    Delete(FileDeleteEvent),
    Rename(FileRenameEvent),
}
```

# Event classification

Events can be classified using configurable rules.

Severity levels currently range from:

```text
Info
Low
Medium
High
Critical
```

A rule may identify activity that deserves additional attention without claiming that the event is malicious.

For example, if a process accesses /etc/passwd, we can consider it more interesting than an access to an ordinary file, while an access to /etc/shadow may warrant a Critical classification.
Whole goal of classification is therefore intended to answer:

> **"Is this event interesting enough to investigate?"**


# Configurable rules

Rules are configured through:

```text
~/.config/watcher-rs/rules.toml
```

For example (default configuration):

```toml
[sensitive_path]
enabled = true

[sensitive_path.paths]
Low = [
    "/proc/",
    "/sys/",
    "/dev/",
    "/run/",
    "/var/cache/",
    "/var/log/",
    "/var/lib/",
]

Medium = [
    "/home/",
    "/root/",
    "/.ssh/",
    "/.gnupg/",
    "/.config/autostart/",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/user/",
    "/opt/",
    "/srv/",
]

High = [
    "/etc/passwd",
    "/etc/group",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/fstab",
    "/etc/pam.d/",
    "/etc/profile",
    "/etc/profile.d/",
    "/etc/environment",
    "/etc/bash.bashrc",
    "/etc/zsh/",
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/lib/",
    "/lib64/",
    "/usr/lib/",
    "/usr/lib64/",
    "/var/spool/cron/",
    "/var/lib/systemd/",
]

Critical = [
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d/",
    "/etc/ssh/sshd_config",
    "/etc/ld.so.preload",
    "/etc/crontab",
    "/etc/systemd/system/",
    "/etc/systemd/user/",
    "/boot/",
    "/boot/efi/",
    "/root/.ssh/",
    "/root/.gnupg/",
]


[suspicious_exec_path]
enabled = true

[suspicious_exec_path.paths]
Low = [
    "/run/user",
    "/var/run",
]

Medium = [
    "/tmp",
    "/var/tmp",
    "/dev/shm",
]


[suspicious_ports]
enabled = true

[suspicious_ports.ports]
Medium = [
    23,
    6660,
    6661,
    6662,
    6663,
    6664,
    6665,
    6666,
    6667,
    6668,
    6669,
    6697,
    1080,
    9001,
    9030,
    9050,
    9150,
]

High = [
    512,
    513,
    514,
    4444,
    5554,
    12345,
    27374,
    31337,
    54321,
    9051,
]
```


# IP reputation

watcher-rs maintains a local copy of the [IPsum](https://github.com/stamparm/ipsum) database and converts it into a compact binary representation for use during event processing.

The database can be updated directly from the TUI.

Press:

```text
U
```

to update the local IP reputation database.

# Storage configuration

Storage behavior is controlled through:

```text
~/.config/watcher-rs/config.toml
```

Example (default config) :

```toml
[log_config]
max_segment_size_mib = 1.0
max_storage_size_gib = 0.5
```

`max_segment_size_mib` controls the approximate size at which event data is rotated into another segment.

`max_storage_size_gib` places a limit on the amount of persistent event storage retained by watcher-rs.


# Running watcher-rs

watcher-rs observes kernel-level activity and therefore requires elevated privileges.

```bash
cargo build --release
```

Run it with:

```bash
sudo ./target/release/watcher-rs
```

# Architecture

watcher-rs is split between kernel-space eBPF instrumentation and user-space processing.

At a high level:

```text
┌───────────────────────────────────────────────┐
│                  Linux Kernel                 │
│                                               │
│       eBPF probes / instrumentation           │
└───────────────────────┬───────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────┐
│                     bpfx                      │
│                                               │
│     Process / Network / File event capture    │
└───────────────────────┬───────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────┐
│                 watcher-rs                    │
│                                               │
│  ingestion → filtering → correlation →        │
│              classification                   │
│                                               │
│              ┌──────────────┐                 │
│              │ Live Events  │                 │
│              └──────┬───────┘                 │
│                     │                         │
│                     ▼                         │
│              Persistent Store                 │
│                                               │
│                     │                         │
│                     ▼                         │
│              Ratatui TUI                      │
└───────────────────────────────────────────────┘
```

# License

See the repository's `LICENSE` file for licensing information.
