#![allow(unused)]
use crate::app::{App, ConfigState, FILTEREVENTS, UiEvent, UpdateDbState, ViewMode};
use crate::gen_db::drop_privileges;
use crate::helper::format_timestamp_ns;
use crate::write::PER_BATCH_SIZE;
use crate::*;
use bpfx::EventHeader;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, BorderType, Borders, Clear, List, ListItem, Paragraph, Wrap};

const C_BG: Color = Color::Rgb(13, 17, 23); // #0d1117
const C_BG2: Color = Color::Rgb(22, 27, 34); // #161b22
const C_BG3: Color = Color::Rgb(33, 38, 45); // #21262d
const C_BORDER: Color = Color::Rgb(48, 54, 61); // #30363d
const C_TEXT: Color = Color::Rgb(201, 209, 217); // #c9d1d9
const C_MUTED: Color = Color::Rgb(139, 148, 158); // #8b949e
const C_GREEN: Color = Color::Rgb(63, 185, 80); // #3fb950
const C_BLUE: Color = Color::Rgb(88, 166, 255); // #58a6ff
const C_PURPLE: Color = Color::Rgb(210, 168, 255); // #d2a8ff
const C_YELLOW: Color = Color::Rgb(210, 153, 34); // #d29922
const C_ORANGE: Color = Color::Rgb(255, 140, 0);
const C_RED: Color = Color::Rgb(248, 81, 73); // #f85149
const C_PATH: Color = Color::Rgb(126, 231, 135); // #7ee787

fn sev_color(s: &Severity) -> Color {
    match s {
        Severity::Info => C_MUTED,
        Severity::Low => C_BLUE,
        Severity::Medium => C_YELLOW,
        Severity::High => C_ORANGE,
        Severity::Critical => C_RED,
    }
}

pub fn render(frame: &mut Frame, app: &mut App) {
    app.update_config_notification();
    app.update_db_notification();

    let area = frame.area();
    frame.render_widget(Block::default().style(Style::default().bg(C_BG2)), area);
    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Min(0),    // main part
            Constraint::Length(1), // below stats bar
        ])
        .split(area);

    render_status_bar(frame, app, chunks[1]);

    render_main(frame, app, chunks[0]);
    render_config_notification(frame, app);
    render_update_db_notification(frame, app);
}

fn render_main(frame: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(24), // sidebar
            Constraint::Min(40),    // stream
            Constraint::Length(45), // more details part
        ])
        .split(area);

    render_side_bar(frame, app, chunks[0]);
    render_stream(frame, app, chunks[1]);
    render_detail_side_bar(frame, app, chunks[2]);
}

const TIME_W: usize = 15;
const SEV_W: usize = 10;
const PID_W: usize = 13;
const TYPE_W: usize = 15;

fn render_stream(frame: &mut Frame, app: &mut App, area: Rect) {
    let title = if app.searching {
        format!(" search: {} ", app.search_query)
    } else if !app.search_query.is_empty() {
        format!(" stream  [filter: {}] ", app.search_query)
    } else {
        " stream ".to_string()
    };

    let block = Block::default()
        .title(title)
        .title_style(Style::default().fg(C_TEXT))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(C_BORDER))
        .style(Style::default().bg(C_BG));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let header_area = Rect {
        x: inner.x,
        y: inner.y,
        width: inner.width,
        height: 1,
    };

    let sep_area = Rect {
        x: inner.x,
        y: inner.y + 1,
        width: inner.width,
        height: 1,
    };

    let list_area = Rect {
        x: inner.x,
        y: inner.y + 2,
        width: inner.width,
        height: inner.height.saturating_sub(2),
    };

    app.stream_area = inner;
    app.stream_list_offset = list_area.y - inner.y;
    app.view_port.height = list_area.height as usize;

    const DIV: &str = "│";

    let header_line = Line::from(vec![
        Span::raw("  "),
        Span::styled(format!("{:<TIME_W$}", "TIME"), Style::default().fg(C_MUTED)),
        Span::styled(format!(" {DIV} "), Style::default().fg(C_BORDER)),
        Span::styled(format!("{:<SEV_W$}", "SEV"), Style::default().fg(C_MUTED)),
        Span::styled(format!(" {DIV} "), Style::default().fg(C_BORDER)),
        Span::styled(
            format!("{:<PID_W$}", "PID/PROC"),
            Style::default().fg(C_MUTED),
        ),
        Span::styled(format!(" {DIV} "), Style::default().fg(C_BORDER)),
        Span::styled(format!("{:<TYPE_W$}", "TYPE"), Style::default().fg(C_MUTED)),
        Span::styled(format!(" {DIV} "), Style::default().fg(C_BORDER)),
        Span::styled("DETAIL", Style::default().fg(C_MUTED)),
    ]);

    frame.render_widget(
        Paragraph::new(header_line).style(Style::default().bg(C_BG)),
        header_area,
    );

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "─".repeat(inner.width as usize),
            Style::default().fg(C_BORDER),
        ))),
        sep_area,
    );

    let total = app.filtered_events.len();

    if total == 0 {
        return;
    }

    let height = list_area.height as usize;

    if height == 0 {
        return;
    }

    let total = app.filtered_events.len();
    let height = list_area.height as usize;

    let start = app.view_port.window_start.min(total.saturating_sub(1));

    let end = (start + height).min(total);

    let local_selected = app
        .stream_state
        .selected()
        .unwrap_or(0)
        .min(end.saturating_sub(start).saturating_sub(1));

    let selected_local_index = start + local_selected;

    let mut items: Vec<ListItem> = Vec::with_capacity(end - start + 1);

    for i in start..end {
        let ev_idx = app.filtered_events[i];
        let event: &UiEvent = &app.events[ev_idx];

        let sev = &event.severity;
        let is_sel = selected_local_index == i;

        let sev_col = sev_color(sev);

        let ts = format_timestamp_ns(
            event.event.timestamp(),
            app.twle_hr_format,
            app.wallclock_offset_ns,
        );

        let pid = event.event.pid();
        let kind = event.event.kind_label();
        let detail = event.event.detail();

        let bg = if is_sel {
            C_BG3
        } else if i % 2 == 1 {
            C_BG2
        } else {
            C_BG
        };

        let accent = if is_sel { "▌" } else { " " };

        let div_style = Style::default().fg(C_BORDER).bg(bg);

        let line = Line::from(vec![
            Span::styled(accent, Style::default().fg(sev_col).bg(bg)),
            // Span::styled(format!(" {} ", i), div_style),
            Span::styled(
                format!(" {:<TIME_W$}", &ts[..11.min(ts.len())]),
                Style::default().fg(C_MUTED).bg(bg),
            ),
            Span::styled(format!(" {DIV} "), div_style),
            Span::styled(
                format!("{:<w$}  ", sev.label(), w = SEV_W.saturating_sub(2)),
                Style::default()
                    .fg(sev_col)
                    .bg(bg)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!(" {DIV} "), div_style),
            Span::styled(
                format!("{:<PID_W$}", pid),
                Style::default().fg(C_TEXT).bg(bg),
            ),
            Span::styled(format!(" {DIV} "), div_style),
            Span::styled(
                format!("{:<TYPE_W$}", kind.trim()),
                Style::default().fg(C_PURPLE).bg(bg),
            ),
            Span::styled(format!(" {DIV} "), div_style),
            Span::styled(detail, Style::default().fg(detail_color(event)).bg(bg)),
        ]);

        items.push(ListItem::new(line));
    }

    items.push(ListItem::new(Line::from("")));

    app.stream_state.select(Some(local_selected));

    let list = List::new(items).style(Style::default().bg(C_BG));

    frame.render_stateful_widget(list, list_area, &mut app.stream_state);

    render_scrollbar(frame, list_area, selected_local_index, total);
}

fn render_scrollbar(frame: &mut Frame, area: Rect, selected: usize, total: usize) {
    let h = area.height as usize;
    let pos = (selected * h) / total.max(1);
    let x = area.x + area.width - 1;

    for row in 0..h {
        let ch = if row == pos { "█" } else { "░" };
        let style = if row == pos {
            Style::default().fg(C_BLUE)
        } else {
            Style::default().fg(C_BORDER)
        };
        let cell_area = Rect {
            x,
            y: area.y + row as u16,
            width: 1,
            height: 1,
        };
        frame.render_widget(Paragraph::new(ch).style(style), cell_area);
    }
}

fn detail_color(event: &UiEvent) -> Color {
    match event.severity {
        Severity::Critical => C_RED,
        Severity::High => Color::Rgb(255, 160, 100),
        _ => C_TEXT,
    }
}

pub const SEVERITY_FILTERS: &[(Severity, &str); 5] = &[
    (Severity::Critical, "Critical"),
    (Severity::High, "High"),
    (Severity::Medium, "Medium"),
    (Severity::Low, "Low"),
    (Severity::Info, "Info"),
];

fn render_side_bar(frame: &mut Frame, app: &mut App, area: Rect) {
    let block = Block::default()
        .title(" sidebar ")
        .title_style(Style::default().fg(C_TEXT))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(C_BORDER))
        .style(Style::default().bg(C_BG));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let [severity_area, sep_area, filter_area] = Layout::vertical([
        Constraint::Length((SEVERITY_FILTERS.len() + 2) as u16),
        Constraint::Length(1),
        Constraint::Min(0),
    ])
    .areas(inner);

    app.sev_area = severity_area;
    app.filter_area = filter_area;

    let severity_header = Rect {
        x: severity_area.x,
        y: severity_area.y,
        width: severity_area.width,
        height: 1,
    };

    frame.render_widget(
        Paragraph::new(Span::styled(
            " Severity ",
            Style::default().fg(C_TEXT).add_modifier(Modifier::BOLD),
        )),
        severity_header,
    );

    let severity_rows = Rect {
        x: severity_area.x,
        y: severity_area.y + 1,
        width: severity_area.width,
        height: severity_area.height.saturating_sub(1),
    };

    let rows = Layout::vertical(
        std::iter::repeat_n(Constraint::Length(1), SEVERITY_FILTERS.len()).collect::<Vec<_>>(),
    )
    .split(severity_rows);

    let sev_colors = [C_RED, C_ORANGE, C_YELLOW, C_BLUE, C_BG3];

    let counts = [
        app.crit_ev_count,
        app.high_ev_count,
        app.med_ev_count,
        app.low_ev_count,
        app.info_ev_count,
    ];

    let count_width = counts
        .iter()
        .max()
        .map(|count| count.to_string().len() as u16)
        .unwrap_or(1);

    for (i, (_, label)) in SEVERITY_FILTERS.iter().enumerate() {
        let [left, right] =
            Layout::horizontal([Constraint::Min(0), Constraint::Length(count_width)])
                .areas(rows[i]);

        let is_selected = app.selected_sevs[i];

        let marker = if is_selected { "▶" } else { "▸" };

        let left_line = Line::from(vec![
            Span::styled(
                marker,
                if is_selected {
                    Style::default().fg(C_BLUE).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(C_MUTED)
                },
            ),
            Span::raw(" "),
            Span::styled("■ ", Style::default().fg(sev_colors[i])),
            Span::styled(
                *label,
                Style::default().fg(C_TEXT).add_modifier(if is_selected {
                    Modifier::BOLD
                } else {
                    Modifier::empty()
                }),
            ),
        ]);

        frame.render_widget(Paragraph::new(left_line), left);

        frame.render_widget(
            Paragraph::new(counts[i].to_string())
                .alignment(Alignment::Right)
                .style(Style::default().fg(C_MUTED)),
            right,
        );
    }

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "─".repeat(sep_area.width as usize),
            Style::default().fg(C_BORDER),
        ))),
        sep_area,
    );

    let filter_header = Rect {
        x: filter_area.x,
        y: filter_area.y,
        width: filter_area.width,
        height: 1,
    };

    frame.render_widget(
        Paragraph::new(Span::styled(
            " Filter Events ",
            Style::default().fg(C_TEXT).add_modifier(Modifier::BOLD),
        )),
        filter_header,
    );

    let filter_list_area = Rect {
        x: filter_area.x,
        y: filter_area.y + 1,
        width: filter_area.width,
        height: filter_area.height.saturating_sub(1),
    };

    let items: Vec<ListItem> = FILTEREVENTS
        .iter()
        .enumerate()
        .map(|(idx, event)| {
            let selected = app.selected_filters[idx];

            let marker = if selected { "▶" } else { "▸" };

            ListItem::new(Line::from(vec![
                Span::styled(
                    marker,
                    if selected {
                        Style::default().fg(C_BLUE).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(C_MUTED)
                    },
                ),
                Span::raw(" "),
                Span::styled(
                    *event,
                    Style::default().fg(C_TEXT).add_modifier(if selected {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }),
                ),
            ]))
        })
        .collect();

    frame.render_widget(
        List::new(items).style(Style::default().bg(C_BG)),
        filter_list_area,
    );
}

fn render_detail_side_bar(frame: &mut Frame, app: &mut App, area: Rect) {
    let block = Block::default()
        .title(" details ")
        .title_style(Style::default().fg(C_TEXT))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(C_BORDER))
        .style(Style::default().bg(C_BG));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let event = match app.selected_event() {
        Some(event) => event,
        None => {
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    "no event selected",
                    Style::default().fg(C_MUTED),
                )))
                .alignment(Alignment::Center)
                .style(Style::default().bg(C_BG)),
                inner,
            );
            return;
        }
    };

    let lines = build_detail_lines(event, app);

    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .style(Style::default().bg(C_BG)),
        inner,
    );
}

fn section(lines: &mut Vec<Line<'static>>, title: &'static str) {
    lines.push(Line::from(vec![Span::styled(
        title,
        Style::default().fg(C_BLUE).add_modifier(Modifier::BOLD),
    )]));
    lines.push(Line::from(Span::styled(
        "─".repeat(title.len()),
        Style::default().fg(C_BORDER),
    )));
}

fn kv(lines: &mut Vec<Line<'static>>, key: &'static str, val: &str, color: Color) {
    lines.push(Line::from(vec![
        Span::styled(format!("{}", key), Style::default().fg(C_MUTED)),
        Span::styled(val.to_string(), Style::default().fg(color)),
    ]));
}

fn uid_label(uid: u32) -> String {
    match uid {
        0 => "0 (root)".into(),
        _ => uid.to_string(),
    }
}
fn uid_color(uid: u32) -> Color {
    if uid == 0 { C_RED } else { C_TEXT }
}

fn port_color(port: u16) -> Color {
    match port {
        22 | 443 | 80 => C_GREEN,
        4444 | 1337 => C_RED,
        _ => C_TEXT,
    }
}
fn family_label(family: u16) -> &'static str {
    match family {
        2 => "AF_INET",
        10 => "AF_INET6",
        _ => "unknown",
    }
}

fn render_network(
    lines: &mut Vec<Line<'static>>,
    title: &'static str,
    header: &EventHeader,
    protocol: &Protocol,
    endpoints: &SocketEndpoints,
) {
    section(lines, title);

    kv(lines, "comm ", &header.comm, C_GREEN);
    kv(lines, "pid ", &header.pid.to_string(), C_TEXT);
    kv(lines, "tid ", &header.tid.to_string(), C_TEXT);
    kv(lines, "ppid ", &header.ppid.to_string(), C_TEXT);
    kv(lines, "uid ", &header.uid.to_string(), C_TEXT);
    kv(lines, "gid ", &header.gid.to_string(), C_TEXT);

    lines.push(Line::from(""));

    section(lines, "NETWORK");

    let proto = match protocol {
        Protocol::Tcp => "TCP",
        Protocol::Udp => "UDP",
    };

    kv(lines, "protocol ", proto, C_BLUE);

    kv(
        lines,
        "source ",
        &format!("{}:{}", endpoints.local_ip, endpoints.local_port),
        C_GREEN,
    );

    kv(
        lines,
        "destination ",
        &format!("{}:{}", endpoints.remote_ip, endpoints.remote_port),
        C_BLUE,
    );
}

fn build_detail_lines(event: &UiEvent, app: &App) -> Text<'static> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    let rules = event.event.rule_name();

    let sev = &event.severity;
    let sev_col = sev_color(sev);

    let timestamp = format_timestamp_ns(
        event.event.timestamp(),
        app.twle_hr_format,
        app.wallclock_offset_ns,
    );

    lines.push(Line::from(vec![
        Span::styled("●  ", Style::default().fg(sev_col)),
        Span::styled(
            sev.label().to_string(),
            Style::default().fg(sev_col).add_modifier(Modifier::BOLD),
        ),
        Span::styled("  │  ", Style::default().fg(C_BORDER)),
        Span::styled(
            event.event.kind_label().trim().to_string(),
            Style::default().fg(C_PURPLE),
        ),
    ]));

    lines.push(Line::from(Span::styled(
        timestamp,
        Style::default().fg(C_MUTED),
    )));

    lines.push(Line::from(""));

    match &event.event {
        AppEvent::ProcessStart(e) => {
            section(&mut lines, "ProcessStart");

            kv(
                &mut lines,
                "pid      ",
                &e.event.header.pid.to_string(),
                C_TEXT,
            );
            kv(
                &mut lines,
                "ppid     ",
                &e.event.header.ppid.to_string(),
                C_TEXT,
            );
            kv(
                &mut lines,
                "uid      ",
                &uid_label(e.event.header.uid),
                uid_color(e.event.header.uid),
            );
            kv(&mut lines, "filename ", &e.event.filename, C_PATH);
            kv(&mut lines, "comm     ", &e.event.header.comm, C_PATH);
        }

        AppEvent::ProcessExit(e) => {
            let ok = e.event.exit_code >= 0;

            section(&mut lines, "ProcessExit");

            kv(
                &mut lines,
                "pid    ",
                &e.event.header.pid.to_string(),
                C_TEXT,
            );
            kv(
                &mut lines,
                "ppid   ",
                &e.event.header.ppid.to_string(),
                C_TEXT,
            );
            kv(&mut lines, "comm   ", &e.event.header.comm, C_PATH);
            kv(
                &mut lines,
                "retval ",
                &format!(
                    "{} ({})",
                    e.event.exit_code,
                    if ok { "ok" } else { "failed" }
                ),
                if ok { C_TEXT } else { C_RED },
            );
        }

        AppEvent::ProcessFork(e) => {
            section(&mut lines, "ProcessFork");

            kv(
                &mut lines,
                "child pid   ",
                &e.event.child_pid.to_string(),
                C_TEXT,
            );
            kv(&mut lines, "child comm  ", &e.event.child_comm, C_PATH);
            kv(
                &mut lines,
                "parent pid  ",
                &e.event.parent.pid.to_string(),
                C_TEXT,
            );
            kv(&mut lines, "parent comm ", &e.event.parent.comm, C_PATH);
            kv(
                &mut lines,
                "ppid        ",
                &e.event.parent.ppid.to_string(),
                C_TEXT,
            );
        }

        AppEvent::FileOpen(e) => {
            section(&mut lines, "FileOpen");

            kv(&mut lines, "name ", &e.event.header.comm, C_TEXT);
            kv(&mut lines, "pid  ", &e.event.header.pid.to_string(), C_TEXT);
            kv(
                &mut lines,
                "ppid ",
                &e.event.header.ppid.to_string(),
                C_MUTED,
            );
            kv(
                &mut lines,
                "uid  ",
                &uid_label(e.event.header.uid),
                uid_color(e.event.header.uid),
            );
            kv(
                &mut lines,
                "gid  ",
                &e.event.header.gid.to_string(),
                C_MUTED,
            );

            lines.push(Line::from(""));

            section(&mut lines, "FILE");

            let op = &e.event.file_type;
            let file_name = &e.event.file_name().to_string();
            let file_path = &e.event.file_path;

            let path_col = if crate::helper::is_sensitive_path(file_path) {
                C_RED
            } else {
                C_PATH
            };

            kv(&mut lines, "filepath ", file_path, path_col);
            kv(&mut lines, "filename ", file_name, C_TEXT);
            kv(&mut lines, "op       ", &format!("{op:?}"), C_TEXT);
            kv(&mut lines, "flags    ", &e.event.flags(), C_MUTED);
            kv(
                &mut lines,
                "mode     ",
                &format!("{:?}", e.event.file_type),
                C_MUTED,
            );

            let ok = e.event.retval >= 0;

            kv(
                &mut lines,
                "retval   ",
                &format!("{} ({})", e.event.retval, if ok { "ok" } else { "failed " }),
                if ok { C_TEXT } else { C_RED },
            );

            kv(&mut lines, "inode    ", &e.event.inode.to_string(), C_MUTED);
        }

        AppEvent::FileClose(e) => {
            section(&mut lines, "FileClose");

            kv(
                &mut lines,
                "pid      ",
                &e.event.header.pid.to_string(),
                C_TEXT,
            );
            kv(
                &mut lines,
                "ppid     ",
                &e.event.header.ppid.to_string(),
                C_MUTED,
            );
            kv(
                &mut lines,
                "uid      ",
                &uid_label(e.event.header.uid),
                uid_color(e.event.header.uid),
            );
            kv(
                &mut lines,
                "gid      ",
                &e.event.header.gid.to_string(),
                C_MUTED,
            );
            kv(&mut lines, "filepath ", &e.event.file_path, C_PATH);
            kv(&mut lines, "flags    ", &e.event.flags(), C_MUTED);

            let ok = e.event.retval >= 0;

            kv(
                &mut lines,
                "retval   ",
                &format!("{} ({})", e.event.retval, if ok { "ok" } else { "failed" }),
                if ok { C_TEXT } else { C_RED },
            );

            kv(
                &mut lines,
                "mode     ",
                &format!("{:?}", e.event.file_type),
                C_MUTED,
            );
        }

        AppEvent::FileWrite(e) => {
            section(&mut lines, "FileWrite");

            kv(
                &mut lines,
                "pid      ",
                &e.event.header.pid.to_string(),
                C_TEXT,
            );
            kv(
                &mut lines,
                "ppid     ",
                &e.event.header.ppid.to_string(),
                C_MUTED,
            );
            kv(
                &mut lines,
                "uid      ",
                &uid_label(e.event.header.uid),
                uid_color(e.event.header.uid),
            );
            kv(
                &mut lines,
                "gid      ",
                &e.event.header.gid.to_string(),
                C_MUTED,
            );
            kv(&mut lines, "filepath ", &e.event.file_path, C_PATH);
            kv(&mut lines, "flags    ", &e.event.flags(), C_MUTED);

            let ok = e.event.retval >= 0;

            kv(
                &mut lines,
                "retval   ",
                &format!("{} ({})", e.event.retval, if ok { "ok" } else { "failed" }),
                if ok { C_TEXT } else { C_RED },
            );

            kv(
                &mut lines,
                "mode     ",
                &format!("{:?}", e.event.file_type),
                C_MUTED,
            );
        }

        AppEvent::FileRename(e) => {
            section(&mut lines, "FileRename");

            kv(
                &mut lines,
                "pid           ",
                &e.event.header.pid.to_string(),
                C_TEXT,
            );
            kv(
                &mut lines,
                "ppid          ",
                &e.event.header.ppid.to_string(),
                C_MUTED,
            );
            kv(
                &mut lines,
                "uid           ",
                &uid_label(e.event.header.uid),
                uid_color(e.event.header.uid),
            );
            kv(
                &mut lines,
                "gid           ",
                &e.event.header.gid.to_string(),
                C_MUTED,
            );
            kv(&mut lines, "old_filename  ", &e.event.old_filename, C_PATH);
            kv(&mut lines, "new_filename  ", &e.event.new_filename, C_PATH);
            kv(&mut lines, "flags    ", &e.event.flags(), C_MUTED);

            let ok = e.event.retval >= 0;

            kv(
                &mut lines,
                "retval        ",
                &format!("{} ({})", e.event.retval, if ok { "ok" } else { "failed" }),
                if ok { C_TEXT } else { C_RED },
            );

            kv(
                &mut lines,
                "mode          ",
                &format!("{:?}", e.event.file_type),
                C_MUTED,
            );
        }

        AppEvent::FileRead(e) => {
            section(&mut lines, "FileRead");

            kv(
                &mut lines,
                "pid      ",
                &e.event.header.pid.to_string(),
                C_TEXT,
            );
            kv(
                &mut lines,
                "ppid     ",
                &e.event.header.ppid.to_string(),
                C_MUTED,
            );
            kv(
                &mut lines,
                "uid      ",
                &uid_label(e.event.header.uid),
                uid_color(e.event.header.uid),
            );
            kv(
                &mut lines,
                "gid      ",
                &e.event.header.gid.to_string(),
                C_MUTED,
            );
            kv(&mut lines, "filepath ", &e.event.file_path, C_PATH);
            kv(&mut lines, "flags    ", &e.event.flags(), C_MUTED);

            let ok = e.event.retval >= 0;

            kv(
                &mut lines,
                "retval   ",
                &format!("{} ({})", e.event.retval, if ok { "ok" } else { "failed" }),
                if ok { C_TEXT } else { C_RED },
            );

            kv(
                &mut lines,
                "mode     ",
                &format!("{:?}", e.event.file_type),
                C_MUTED,
            );
        }

        AppEvent::FileDelete(e) => {
            section(&mut lines, "FileDelete");

            kv(
                &mut lines,
                "pid      ",
                &e.event.header.pid.to_string(),
                C_TEXT,
            );
            kv(
                &mut lines,
                "ppid     ",
                &e.event.header.ppid.to_string(),
                C_MUTED,
            );
            kv(
                &mut lines,
                "uid      ",
                &uid_label(e.event.header.uid),
                uid_color(e.event.header.uid),
            );
            kv(
                &mut lines,
                "gid      ",
                &e.event.header.gid.to_string(),
                C_MUTED,
            );
            kv(&mut lines, "filename ", &e.event.filename, C_PATH);

            let ok = e.event.retval >= 0;

            kv(
                &mut lines,
                "retval   ",
                &format!("{} ({})", e.event.retval, if ok { "ok" } else { "failed" }),
                if ok { C_TEXT } else { C_RED },
            );

            kv(
                &mut lines,
                "mode     ",
                &format!("{:?}", e.event.file_type),
                C_MUTED,
            );
        }

        AppEvent::NetworkAccept(e) => {
            render_network(
                &mut lines,
                "Accept",
                &e.event.header,
                &e.event.protocol,
                &e.event.endpoints,
            );
        }

        AppEvent::NetworkConnect(e) => {
            render_network(
                &mut lines,
                "Connect",
                &e.event.header,
                &e.event.protocol,
                &e.event.endpoints,
            );
        }

        AppEvent::NetworkBind(e) => {
            render_network(
                &mut lines,
                "Bind",
                &e.event.header,
                &e.event.protocol,
                &e.event.endpoints,
            );
        }

        AppEvent::NetworkClose(e) => {
            render_network(
                &mut lines,
                "Close",
                &e.event.header,
                &e.event.protocol,
                &e.event.endpoints,
            );
        }

        AppEvent::NetworkListen(e) => {
            render_network(
                &mut lines,
                "Listen",
                &e.event.header,
                &e.event.protocol,
                &e.event.endpoints,
            );
        }
    }

    if !rules.is_empty() {
        lines.push(Line::from(""));
        section(&mut lines, "RULES");

        for rule in rules {
            lines.push(Line::from(vec![
                Span::styled("▸ ", Style::default().fg(C_MUTED)),
                Span::styled(rule.clone(), Style::default().fg(C_YELLOW)),
            ]));
        }
    }

    Text::from(lines)
}

fn key(s: &'static str) -> Span<'static> {
    Span::styled(format!("[{s}]"), Style::default().fg(C_TEXT).bg(C_BG3))
}

fn render_status_bar(frame: &mut Frame, app: &mut App, area: Rect) {
    let (mode, color) = if app.searching {
        ("SEARCHING", C_PURPLE)
    } else if app.pause {
        ("PAUSED", C_RED)
    } else if app.follow_tail {
        ("STREAM • FOLLOWING", C_BLUE)
    } else {
        ("STREAM", C_BLUE)
    };

    let muted = Style::default().fg(C_MUTED).bg(C_BG2);

    let spans = Line::from(vec![
        Span::styled(
            format!(" {mode} "),
            Style::default()
                .fg(C_BG)
                .bg(color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("  ", muted),
        Span::styled("↑↓ nav", muted),
        Span::styled("   ", muted),
        key("gg"),
        Span::styled(" top", muted),
        Span::styled("   ", muted),
        key("G"),
        Span::styled(" latest", muted),
        Span::styled("   ", muted),
        key("p"),
        Span::styled(if app.pause { " resume" } else { " pause" }, muted),
        Span::styled("   ", muted),
        key("/ or f"),
        Span::styled(" filter", muted),
        Span::styled("   ", muted),
        key("t"),
        Span::styled(" 12/24 format", muted),
        Span::styled("   ", muted),
        key("Ctrl + l"),
        Span::styled(" clear", muted),
        Span::styled("   ", muted),
        key("r"),
        Span::styled(" reload config", muted),
        Span::styled("   ", muted),
        key("U"),
        Span::styled(" update DB", muted),
        Span::styled("   ", muted),
        key("q"),
        Span::styled(" quit", muted),
    ]);

    frame.render_widget(
        Paragraph::new(spans).style(Style::default().bg(C_BG2)),
        area,
    );
}

fn render_config_notification(frame: &mut Frame, app: &App) {
    let Some((state, _)) = &app.config_notification else {
        return;
    };

    let message = match state {
        ConfigState::ConfigReloaded => "✓  Configuration reloaded",
        ConfigState::ConfigReloadFailed => "✗  Configuration reload failed",
    };

    let area = frame.area();

    let width = message.len() as u16 + 2;

    let notification_area = Rect {
        x: area.width.saturating_sub(width + 2),
        y: area.height.saturating_sub(5),
        width,
        height: 3,
    };

    let paragraph = Paragraph::new(message)
        .block(Block::bordered())
        .cyan()
        .alignment(Alignment::Center);

    frame.render_widget(paragraph, notification_area);
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn render_update_db_notification(frame: &mut Frame, app: &App) {
    let Some((state, _)) = &app.db_update_state else {
        return;
    };

    let message = match state {
        UpdateDbState::Updating => "↓  Updating IP reputation database...",
        UpdateDbState::Updated => "✓  IP reputation database updated",
        UpdateDbState::UpdateFailed => "✗  IP reputation database update failed",
    };

    let area = frame.area();

    let width = message.len() as u16 + 2;

    let notification_area = Rect {
        x: area.width.saturating_sub(width + 2),
        y: area.height.saturating_sub(5),
        width,
        height: 3,
    };

    let paragraph = Paragraph::new(message)
        .block(Block::bordered())
        .cyan()
        .alignment(Alignment::Center);

    frame.render_widget(paragraph, notification_area);
}
