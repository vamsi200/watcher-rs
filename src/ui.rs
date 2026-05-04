#![allow(unused)]
use crate::app::App;
use crate::*;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, List, ListItem, Paragraph};

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

    render_main(frame, app, area);
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

fn render_stream(frame: &mut Frame, app: &mut App, area: Rect) {
    let bg = if app.selected_tab == crate::app::Focus::Stream {
        C_BLUE
    } else {
        C_BG2
    };

    let block = Block::default()
        .title("stream baby")
        .title_style(Style::default().fg(C_TEXT))
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(bg))
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

    let line = Line::from(vec![
        Span::styled(
            format!(
                "{:<12} {:<6} {:<18} {:<12}",
                "TIME", "SEV", "PID/PROC", "TYPE"
            ),
            Style::default().fg(C_MUTED).bg(C_BG2),
        ),
        Span::styled("DETAIL", Style::default().fg(C_MUTED).bg(C_BG2)),
    ]);

    frame.render_widget(
        Paragraph::new(line).style(Style::default().bg(C_BG2)),
        header_area,
    );

    let mut items: Vec<ListItem> = Vec::new();
    let bg = C_BG3;

    if let Some(event) = &app.events {
        let sev = event.severity();

        let sev_col = sev_color(&sev);
        let ts = format_timestamp_ns(event.timestamp());
        let pid = event.pid();
        let kind = event.kind_label();
        let detail = event.detail();

        let line = Line::from(vec![
            Span::styled(
                format!("{:<11} ", &ts[..11.min(ts.len())]),
                Style::default().fg(C_MUTED).bg(bg),
            ),
            Span::styled(
                format!("{:<4} ", sev.label()),
                Style::default()
                    .fg(sev_col)
                    .bg(bg)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("{:<5} ", pid), Style::default().fg(C_TEXT).bg(bg)),
            Span::styled(
                format!("{:<11} ", kind.trim()),
                Style::default().fg(C_PURPLE).bg(bg),
            ),
            Span::styled(detail, Style::default().fg(detail_color(event)).bg(bg)),
        ]);

        items.push(ListItem::new(line));
    }

    let list = List::new(items).style(Style::default().bg(C_BG));
    frame.render_widget(list, area);
}

fn detail_color(event: &AppEvent) -> Color {
    match event.severity() {
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
    let bg = if app.selected_tab == crate::app::Focus::Sidebar {
        C_BLUE
    } else {
        C_BG2
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Plain)
        .border_style(Style::default().fg(bg))
        .style(Style::default().bg(C_BG2));

    let inner_part = block.inner(area);
    frame.render_widget(block, area);

    let mut items: Vec<ListItem> = Vec::new();

    items.push(ListItem::new(Line::from(vec![Span::styled(
        "SEVERITY",
        Style::default().fg(C_MUTED).add_modifier(Modifier::BOLD),
    )])));

    let sev_colors = [C_TEXT, C_RED, C_ORANGE, C_YELLOW, C_BLUE];
    let indicators = ["  ", "■ ", "■ ", "■ ", "■ "];

    let label_stle = Style::default().fg(C_TEXT).add_modifier(Modifier::BOLD);

    let counts = [
        app.info_ev_count,
        app.crit_ev_count,
        app.high_ev_count,
        app.med_ev_count,
        app.low_ev_count,
    ];

    for (i, (filter, label)) in SEVERITY_FILTERS.iter().enumerate() {
        let indicator_color = sev_colors[i];
        let line = Line::from(vec![
            Span::styled(
                indicators[i],
                Style::default().fg(indicator_color).bg(C_BG3),
            ),
            Span::styled(*label, label_stle.bg(C_BG)),
            Span::styled(
                format!("{:>5}", counts[i]),
                Style::default().fg(C_MUTED).bg(C_BG3),
            ),
        ]);
        items.push(ListItem::new(line));
    }
    items.push(ListItem::new(Line::from("")));

    let list = List::new(items).style(Style::default().bg(C_BG));
    frame.render_widget(list, inner_part);
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
}

// should I make this a popup?? coule be annoying..
fn render_alert(frame: &mut Frame) {
    todo!()
}

fn render_help_popup(frame: &mut Frame, app: &mut App) {
    todo!()
}
