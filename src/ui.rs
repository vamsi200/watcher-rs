#![allow(unused)]
use std::process::id;

use crate::app::{App, FILTEREVENTS, Focus, UiEvent, ViewMode};
use crate::write::{BatchInfo, PER_BATCH_SIZE};
use crate::*;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, List, ListItem, Paragraph, Scrollbar, ScrollbarOrientation,
    ScrollbarState, Wrap,
};

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
const C_RED_DIM: Color = Color::Rgb(180, 40, 40);
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
    let area = frame.area();
    frame.render_widget(Block::default().style(Style::default().bg(C_BG2)), area);
    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Min(0),    // main part
            Constraint::Length(1), // below stats bar.. should I keep it??
        ])
        .split(area);

    render_status_bar(frame, app, chunks[1]);

    render_main(frame, app, chunks[0]);
}

fn render_main(frame: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(18), // sidebar
            Constraint::Min(40),    // stream
            Constraint::Length(38), // more details part
        ])
        .split(area);

    render_side_bar(frame, app, chunks[0]);
    render_stream(frame, app, chunks[1]);
    render_detail_side_bar(frame, app, chunks[2]);
}

const TIME_W: usize = 15;
const SEV_W: usize = 10;
const PID_W: usize = 17;
const TYPE_W: usize = 20;

fn render_stream(frame: &mut Frame, app: &mut App, area: Rect) {
    let focused = if app.selected_tab == Focus::Stream {
        C_BLUE
    } else {
        C_BORDER
    };

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
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(focused))
        .style(Style::default().bg(C_BG));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let header_area = Rect {
        x: inner.x,
        y: inner.y,
        width: inner.width,
        height: 1,
    };
    let list_area = Rect {
        x: inner.x,
        y: inner.y + 1,
        width: inner.width,
        height: inner.height.saturating_sub(1),
    };

    app.stream_area = inner;

    let bg = if app.selected_tab == crate::app::Focus::Stream {
        C_BLUE
    } else {
        C_BG
    };

    let line = Line::from(vec![
        Span::raw(" "),
        Span::styled(
            format!(
                " {:<TIME_W$} {:<SEV_W$} {:<PID_W$} {:<TYPE_W$}DETAIL",
                "TIME", "SEV", "PID/PROC", "TYPE",
            ),
            Style::default().fg(C_MUTED).bg(C_BG2),
        ),
    ]);

    frame.render_widget(
        Paragraph::new(line).style(Style::default().bg(C_BG2)),
        header_area,
    );

    let total = app.filtered_events.len();

    if total == 0 {
        return;
    }

    if app.view_mode == ViewMode::Live && app.filtered_events.len() >= PER_BATCH_SIZE {
        app.view_mode = ViewMode::History;
        app.current_batch = 0;
        app.view_port.window_start = app.sev_state.selected().unwrap_or(0);
    }

    let selected = app.stream_state.selected().unwrap_or(0);

    let mut items: Vec<ListItem> = Vec::with_capacity(app.filtered_events.len());

    for (i, &ev_idx) in app.filtered_events.iter().enumerate() {
        let event: &UiEvent = &app.events[ev_idx];
        let sev = &event.severity;
        let is_sel = selected == i;
        let sev_col = sev_color(&sev);
        let ts = &event.timestamp;
        let pid = event.event.pid();
        let kind = &event.kind;
        let detail = &event.detail;
        let border_char = if is_sel { "▶" } else { " " };
        let bg = if is_sel { C_BG3 } else { C_BG };

        let line = Line::from(vec![
            Span::styled(border_char, Style::default().fg(sev_col).bg(bg)),
            Span::styled(
                format!(" {:<TIME_W$}", &ts[..11.min(ts.len())]),
                Style::default().fg(C_MUTED).bg(bg),
            ),
            Span::styled(
                format!(" {:<SEV_W$}", sev.label()),
                Style::default()
                    .fg(sev_col)
                    .bg(bg)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" {:<PID_W$}", pid),
                Style::default().fg(C_TEXT).bg(bg),
            ),
            Span::styled(
                format!(" {:<TYPE_W$}", kind.trim()),
                Style::default().fg(C_PURPLE).bg(bg),
            ),
            Span::styled(detail, Style::default().fg(detail_color(event)).bg(bg)),
        ]);

        items.push(ListItem::new(line));
    }

    items.push(ListItem::new(Line::from("")));

    let list = List::new(items).style(Style::default().bg(C_BG));
    frame.render_stateful_widget(list, list_area, &mut app.stream_state);

    render_scrollbar(frame, inner, selected, total);
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

// later maybe add like grouping..
pub const SEVERITY_FILTERS: &[(Severity, &str); 5] = &[
    (Severity::Info, "Info"),
    (Severity::Critical, "Critical"),
    (Severity::High, "High"),
    (Severity::Medium, "Medium"),
    (Severity::Low, "Low"),
];

fn render_side_bar(frame: &mut Frame, app: &mut App, area: Rect) {
    let border = if app.selected_tab == crate::app::Focus::Sidebar {
        C_BLUE
    } else {
        C_BG2
    };

    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border))
        .style(Style::default().bg(C_BG));

    let inner = outer.inner(area);
    frame.render_widget(outer, area);

    let [severity_area, filter_area] = Layout::vertical([
        Constraint::Length((SEVERITY_FILTERS.len() + 3) as u16),
        Constraint::Min(0),
    ])
    .areas(inner);

    let severity_block = Block::default().title(" Severity ");

    let severity_inner = severity_block.inner(severity_area);
    frame.render_widget(severity_block, severity_area);

    let rows = Layout::vertical(
        std::iter::repeat(Constraint::Length(1))
            .take(SEVERITY_FILTERS.len())
            .collect::<Vec<_>>(),
    )
    .split(severity_inner);

    let sev_colors = [C_BG3, C_RED, C_ORANGE, C_YELLOW, C_BLUE];
    let counts = [
        app.info_ev_count,
        app.crit_ev_count,
        app.high_ev_count,
        app.med_ev_count,
        app.low_ev_count,
    ];

    let selected = app.sev_state.selected();
    app.sev_area = severity_area;

    for (i, (_, label)) in SEVERITY_FILTERS.iter().enumerate() {
        let [left, right] =
            Layout::horizontal([Constraint::Min(0), Constraint::Length(4)]).areas(rows[i]);

        let is_selected = selected == Some(i);

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
            Paragraph::new(format!("{:>4}", counts[i])).style(Style::default().fg(C_MUTED)),
            right,
        );
    }

    let filter_block = Block::default().title(" Filter Events ");

    let filter_inner = filter_block.inner(filter_area);
    frame.render_widget(filter_block, filter_area);
    app.filter_area = filter_area;

    let selected = app.filter_state.selected();

    let items: Vec<ListItem> = FILTEREVENTS
        .iter()
        .enumerate()
        .map(|(idx, event)| {
            let selected = Some(idx) == selected;

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

    frame.render_widget(List::new(items), filter_inner);
}

fn render_detail_side_bar(frame: &mut Frame, app: &mut App, area: Rect) {
    let bg = if app.selected_tab == crate::app::Focus::Detail {
        C_BLUE
    } else {
        C_BG2
    };

    let block = Block::default()
        .title(" detail ")
        .title_style(Style::default().fg(C_TEXT))
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(bg))
        .style(Style::default().bg(C_BG));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let event = match app.selected_event() {
        Some(s) => s,
        None => {
            frame.render_widget(
                Paragraph::new(Span::styled(
                    "\n  no event selected",
                    Style::default().fg(C_MUTED),
                )),
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
        Span::styled(format!("{:<8}", key), Style::default().fg(C_MUTED)),
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

fn build_detail_lines(event: &UiEvent, app: &App) -> Text<'static> {
    let mut lines: Vec<Line<'static>> = Vec::new();

    let sev = &event.severity;
    let sev_col = sev_color(&sev);

    lines.push(Line::from(vec![
        Span::styled(
            sev.label().to_string(),
            Style::default().fg(sev_col).add_modifier(Modifier::BOLD),
        ),
        Span::styled("  ", Style::default()),
        Span::styled(event.kind.trim().to_string(), Style::default().fg(C_PURPLE)),
    ]));
    lines.push(Line::from(Span::styled(
        event.timestamp.clone(),
        Style::default().fg(C_MUTED),
    )));
    lines.push(Line::from(""));

    match &event.event {
        AppEvent::Exec(e) => {
            section(&mut lines, "PROCESS");
            kv(&mut lines, "pid", &e.header.pid.to_string(), C_TEXT);
            kv(
                &mut lines,
                "uid",
                &uid_label(e.header.uid),
                uid_color(e.header.uid),
            );
            kv(&mut lines, "file", &e.header.comm, C_PATH);
        }
        AppEvent::ExecExit(e) => {
            section(&mut lines, "PROCESS");
            kv(&mut lines, "pid", &e.header.pid.to_string(), C_TEXT);
        }
        AppEvent::File(e) => {
            section(&mut lines, "PROCESS");
            kv(&mut lines, "name", &e.event.header.comm, C_TEXT);
            kv(&mut lines, "pid", &e.event.header.pid.to_string(), C_TEXT);
            kv(
                &mut lines,
                "uid",
                &uid_label(e.event.header.uid),
                uid_color(e.event.header.uid),
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
            kv(&mut lines, "op", &format!("{op:?}"), C_TEXT);
            kv(
                &mut lines,
                "flags",
                &format!("{:#010x}", e.event.flags),
                C_MUTED,
            );
            kv(
                &mut lines,
                "mode",
                &format!("{:?}", e.event.file_type),
                C_MUTED,
            );
        }
        AppEvent::FileClose(e) => {
            section(&mut lines, "FILE");
            kv(&mut lines, "pid", &e.event.header.pid.to_string(), C_TEXT);
            kv(&mut lines, "path", &e.event.header.comm, C_PATH);
        }
        AppEvent::Network(e) => {
            let addr = e.endpoints.remote_ip.to_string();
            section(&mut lines, "PROCESS");
            kv(&mut lines, "pid", &e.header.pid.to_string(), C_TEXT);
            lines.push(Line::from(""));
            section(&mut lines, "NETWORK");
            kv(&mut lines, "dst", &addr, C_BLUE);
            kv(
                &mut lines,
                "port",
                &e.endpoints.remote_port.to_string(),
                port_color(e.endpoints.remote_port),
            );
            // kv(&mut lines, "family", &family_label(e.), C_MUTED);
            // kv(&mut lines, "sockfd", &e.sockfd.to_string(), C_MUTED);
        } // AppEvent::Process(e) => {
          //     section(&mut lines, "PROCESS");
          //     kv(&mut lines, "name", &e.info.name, C_TEXT);
          //     kv(&mut lines, "pid", &e.info.pid.to_string(), C_TEXT);
          //     kv(&mut lines, "ppid", &e.info.ppid.to_string(), C_MUTED);
          //     kv(&mut lines, "uid", &uid_label(e.uid), uid_color(e.uid));
          //     lines.push(Line::from(""));
          //     section(&mut lines, "CMDLINE");
          //     lines.push(Line::from(Span::styled(
          //         e.info.cmdline.clone(),
          //         Style::default().fg(C_PATH),
          //     )));
          // }
          // AppEvent::Privilege(e) => {
          //     section(&mut lines, "PROCESS");
          //     kv(&mut lines, "pid", &e.pid.to_string(), C_TEXT);
          //     kv(&mut lines, "uid", &uid_label(e.uid), uid_color(e.uid));
          //     lines.push(Line::from(""));
          //     section(&mut lines, "PRIVILEGE");
          //     kv(&mut lines, "binary", &e.binary, C_PATH);
          //     kv(
          //         &mut lines,
          //         "setuid",
          //         &e.is_setuid.to_string(),
          //         if e.is_setuid { C_RED } else { C_MUTED },
          //     );
          // }
          // AppEvent::Suspicious(e) => {
          //     section(&mut lines, "SUSPICIOUS");
          //     kv(&mut lines, "pid", &e.pid.to_string(), C_TEXT);
          //     kv(&mut lines, "file", &e.file, C_PATH);
          //     lines.push(Line::from(""));
          //     section(&mut lines, "REASON");
          //     lines.push(Line::from(Span::styled(
          //         e.reason.clone(),
          //         Style::default().fg(C_RED),
          //     )));
          // }
    }

    Text::from(lines)
}

// should I make this a popup?? coule be annoying..
fn render_alert(frame: &mut Frame) {
    todo!()
}

fn render_help_popup(frame: &mut Frame, app: &mut App) {
    todo!()
}

fn key(s: &'static str) -> Span<'static> {
    Span::styled(format!("[{s}]"), Style::default().fg(C_TEXT).bg(C_BG3))
}

fn render_status_bar(frame: &mut Frame, app: &mut App, area: Rect) {
    let mode = match app.selected_tab {
        Focus::Sidebar => "SIDEBAR",
        Focus::Stream => "STREAM ",
        Focus::Detail => "DETAIL ",
        Focus::Filter => "FILTER",
    };

    let filter_label = &app.event_name;

    let spans = Line::from(vec![
        Span::styled(
            format!(" {mode} "),
            Style::default()
                .fg(C_BG)
                .bg(C_BLUE)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("  ", Style::default().bg(C_BG2)),
        Span::styled("↑↓ nav  ", Style::default().fg(C_MUTED).bg(C_BG2)),
        key("Tab"),
        Span::styled(" panel  ", Style::default().fg(C_MUTED).bg(C_BG2)),
        key("p"),
        Span::styled(
            if app.pause { " resume  " } else { " pause  " },
            Style::default().fg(C_MUTED).bg(C_BG2),
        ),
        key("/"),
        Span::styled(" search  ", Style::default().fg(C_MUTED).bg(C_BG2)),
        key("f"),
        Span::styled(" filter  ", Style::default().fg(C_MUTED).bg(C_BG2)),
        key("t"),
        Span::styled(" 12/24 format  ", Style::default().fg(C_MUTED).bg(C_BG2)),
        key("Esc"),
        Span::styled(" back/dismiss  ", Style::default().fg(C_MUTED).bg(C_BG2)),
        key("q"),
        Span::styled(" quit", Style::default().fg(C_MUTED).bg(C_BG2)),
        Span::styled(
            format!("   Selected [{filter_label}]"),
            Style::default().fg(C_MUTED).bg(C_BG2),
        ),
    ]);

    frame.render_widget(
        Paragraph::new(spans).style(Style::default().bg(C_BG2)),
        area,
    );
}
