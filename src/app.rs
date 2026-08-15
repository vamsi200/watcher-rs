use crate::AppEvent;
use crate::Severity;
use crate::ui::*;
use crate::write::BatchInfo;
use crate::write::PER_BATCH_SIZE;
use crate::write::RuntimeLogConfig;
use crate::write::log_path;
use crate::write::prune_batch_info;
use crate::write::read_batch;
use crate::write::read_batch_info;
use crate::write::segment_path;
use crate::write::serialize_event_data;
use crate::write::write_batch_info_to_disk;
use crate::write::write_to_disk;
use crossterm::event::DisableMouseCapture;
use crossterm::event::MouseButton;
use crossterm::event::MouseEvent;
use crossterm::event::MouseEventKind;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::LeaveAlternateScreen;
use nix::time::ClockId;
use nix::time::clock_gettime;
use ratatui::DefaultTerminal;
use ratatui::layout::Position;
use ratatui::layout::Rect;
use ratatui::widgets::ListState;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tokio::sync::watch;

const LIVE_BUFFER_SIZE: usize = 10_000;

#[derive(Debug, PartialEq)]
pub enum ViewMode {
    Live,
    History,
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
pub struct UiEvent {
    pub event: AppEvent,
    pub severity: Severity,
}

#[derive(Debug)]
pub enum ConfigState {
    ConfigReloaded,
    ConfigReloadFailed,
}

impl UiEvent {
    pub fn new(ev: AppEvent) -> Self {
        let severity = ev.severity();

        UiEvent {
            event: ev,
            severity,
        }
    }
}

#[derive(Debug)]
pub struct App {
    pub running: bool,
    pub events: Vec<UiEvent>,
    pub alert: Option<String>,
    pub crit_ev_count: usize,
    pub high_ev_count: usize,
    pub med_ev_count: usize,
    pub low_ev_count: usize,
    pub info_ev_count: usize,
    pub selected_event: Option<UiEvent>,
    pub filtered_events: Vec<usize>,
    pub searching: bool,
    pub search_query: String,
    pub pause: bool,
    pub event_idx: usize,
    pub g_char: bool,
    pub twle_hr_format: bool,
    pub wallclock_offset_ns: u64,
    pub sev_state: ListState,
    pub stream_state: ListState,
    pub filter_state: ListState,
    pub sev_area: Rect,
    pub filter_area: Rect,
    pub stream_area: Rect,
    pub view_mode: ViewMode,
    pub view_port: Viewport,
    pub current_batch: usize,
    pub loaded_range: (usize, usize),
    pub total_batches: usize,
    pub follow_tail: bool,
    pub selected_filters: Vec<bool>,
    pub selected_sevs: Vec<bool>,
    pub config_notification: Option<(ConfigState, Instant)>,
    pub stream_list_offset: u16,
    pub follow_tail_dirty: bool,
    pub tail_events_since_reload: usize,
}

#[derive(Debug)]
pub struct Viewport {
    /// Number of visible rows.
    pub height: usize,

    /// Global index of self.events[0]
    pub window_start: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Focus {
    Sidebar,
    Stream,
    Detail,
    Filter,
}

impl Default for App {
    fn default() -> Self {
        Self {
            running: true,
            events: Vec::with_capacity(PER_BATCH_SIZE),
            alert: None,
            crit_ev_count: 0,
            high_ev_count: 0,
            med_ev_count: 0,
            low_ev_count: 0,
            info_ev_count: 0,
            selected_event: None,
            filtered_events: Vec::with_capacity(PER_BATCH_SIZE),
            searching: false,
            search_query: String::new(),
            pause: false,
            event_idx: 0,
            g_char: false,
            twle_hr_format: false,
            wallclock_offset_ns: 0,
            sev_state: ListState::default(),
            filter_state: ListState::default(),
            filter_area: Rect::default(),
            stream_area: Rect::default(),
            stream_state: ListState::default(),
            view_mode: ViewMode::Live,
            current_batch: 0,
            view_port: Viewport {
                height: 0,
                window_start: 0,
            },
            loaded_range: (0, 0),
            total_batches: 0,
            follow_tail: false,
            sev_area: Rect::default(),
            selected_filters: vec![false; FILTEREVENTS.len()],
            selected_sevs: vec![false; SEVERITY_FILTERS.len()],
            config_notification: None,
            stream_list_offset: 0,
            follow_tail_dirty: false,
            tail_events_since_reload: 0,
        }
    }
}

pub async fn writer_thread(
    mut receiver: Receiver<UiEvent>,
    batch_tx: Sender<bool>,
    log_config: RuntimeLogConfig,
) -> color_eyre::Result<()> {
    let mut batch = Vec::with_capacity(PER_BATCH_SIZE);
    let mut batch_info = BatchInfo::default();
    let mut count = 0;
    let mut path = log_path()?;
    let mut segment_id = 0;
    let mut total_size = 0;
    let mut oldest_segment_id = 0;

    while let Some(event) = receiver.recv().await {
        batch.push(event);

        if batch.len() >= PER_BATCH_SIZE {
            let serialized_data = serialize_event_data(&batch)?;
            let batch_size = 4 + serialized_data.len() as u64;

            let mut file_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

            if file_size > 0 && file_size + batch_size > log_config.max_segment_size {
                segment_id += 1;
                path = segment_path(segment_id);
                file_size = 0;
            }

            let start_offset = write_to_disk(&path, serialized_data)?;
            file_size += batch_size;
            total_size += batch_size;

            while total_size > log_config.max_storage_size && oldest_segment_id < segment_id {
                let path = segment_path(oldest_segment_id);

                let size = std::fs::metadata(&path)?.len();

                tracing::info!(
                    "exceeded set max_storage_size, removing old batch - {}",
                    path.display()
                );

                std::fs::remove_file(&path)?;
                prune_batch_info(oldest_segment_id)?;

                total_size -= size;
                oldest_segment_id += 1;
            }

            count += 1;
            batch_info.file_offset = start_offset;
            batch_info.count = count;
            batch_info.segment_id = segment_id;

            write_batch_info_to_disk(batch_info)?;
            batch_tx.send(true).await?;
            batch.clear();
        }
    }

    Ok(())
}

fn row_at(area: Rect, col: u16, row: u16, len: usize) -> Option<usize> {
    if !area.contains(Position::new(col, row)) {
        return None;
    }

    let rel = row - area.y;

    if rel == 0 {
        return None;
    }

    let idx = (rel - 1) as usize;

    (idx < len).then_some(idx)
}

fn row_at_stream(app: &App, col: u16, row: u16) -> Option<usize> {
    let area = app.stream_area;
    if !area.contains(Position::new(col, row)) {
        return None;
    }
    let rel = (row - area.y) as usize;
    let idx = rel + app.stream_state.offset() - app.stream_list_offset as usize;
    (idx < app.filtered_events.len()).then_some(idx)
}

pub const FILTEREVENTS: [&str; 14] = [
    "ProcessStart",
    "ProcessExit",
    "ProcessFork",
    "FileOpen",
    "FileClose",
    "FileRead",
    "FileDelete",
    "FileRename",
    "FileWrite",
    "NetworkAccept",
    "NetworkConnect",
    "NetworkBind",
    "NetworkListen",
    "NetworkClose",
];

impl App {
    pub fn new() -> Self {
        Self::default()
    }

    fn ensure_batches_loaded(&mut self, global_selected: usize) -> color_eyre::Result<()> {
        if self.total_batches == 0 {
            return Ok(());
        }

        let last_batch = self.total_batches.saturating_sub(1);

        let batch = (global_selected / PER_BATCH_SIZE).min(last_batch);

        let (lo, hi) = self.loaded_range;

        if batch >= lo && batch <= hi {
            return Ok(());
        }

        let (new_lo, new_hi) = if batch < lo {
            (batch.saturating_sub(1), batch)
        } else {
            (batch, (batch + 2).min(last_batch))
        };

        self.load_batch_range(new_lo, new_hi)
    }

    fn check_config_state(&mut self, state: ConfigState) {
        self.config_notification = Some((state, Instant::now() + Duration::from_secs(3)));
    }

    pub fn update_config_notification(&mut self) {
        if let Some((_, expires_at)) = &self.config_notification
            && Instant::now() >= *expires_at
        {
            self.config_notification = None;
        }
    }

    fn load_batch_range(&mut self, lo: usize, hi: usize) -> color_eyre::Result<()> {
        self.events.clear();
        self.filtered_events.clear();

        let batch_info = read_batch_info()?;

        for b in lo..=hi {
            let batch_events = read_batch(b, &batch_info)?;

            for ev in batch_events {
                let idx = self.events.len();
                self.events.push(ev);

                if self.search_query.is_empty()
                    || match_query(&self.events[idx], &self.search_query)
                {
                    self.filtered_events.push(idx);
                }
            }
        }

        self.loaded_range = (lo, hi);
        self.view_port.window_start = lo * PER_BATCH_SIZE;

        Ok(())
    }

    pub async fn push(
        &mut self,
        ev: AppEvent,
        writer_tx: &Sender<UiEvent>,
    ) -> color_eyre::Result<()> {
        let has_filters = self.selected_filters.iter().any(|&x| x);

        let filter = !has_filters
            || self
                .selected_filters
                .iter()
                .enumerate()
                .any(|(idx, selected)| *selected && ev.matches_filter(idx));

        if !filter {
            return Ok(());
        }

        let ev = UiEvent::new(ev);

        let has_sev_filters = self.selected_sevs.iter().any(|&x| x);

        let sev_filter = !has_sev_filters
            || self
                .selected_sevs
                .iter()
                .enumerate()
                .any(|(idx, sel)| *sel && ev.severity == SEVERITY_FILTERS[idx].0);

        if sev_filter {
            match ev.event.severity() {
                Severity::Critical => self.crit_ev_count += 1,
                Severity::High => self.high_ev_count += 1,
                Severity::Medium => self.med_ev_count += 1,
                Severity::Low => self.low_ev_count += 1,
                Severity::Info => self.info_ev_count += 1,
            }

            match self.view_mode {
                ViewMode::Live => {
                    let idx = self.events.len();

                    self.events.push(ev.clone());
                    if let Err(e) = writer_tx.try_send(ev) {
                        tracing::info!("ERROR: {e}");
                    }

                    if self.search_query.is_empty()
                        || match_query(&self.events[idx], &self.search_query)
                    {
                        self.filtered_events.push(idx);
                    }
                }

                ViewMode::History => {
                    if self.follow_tail {
                        let idx = self.events.len();

                        self.events.push(ev.clone());

                        self.tail_events_since_reload += 1;
                        if self.search_query.is_empty()
                            || match_query(&self.events[idx], &self.search_query)
                        {
                            self.filtered_events.push(idx);
                            self.follow_tail_dirty = true;
                        }

                        writer_tx.try_send(ev)?;
                    } else {
                        writer_tx.send(ev).await?;
                    }
                }
            }

            if self.filtered_events.is_empty() {
                self.stream_state.select(Some(0));
            } else {
                self.stream_state.select(Some(
                    self.stream_state
                        .selected()
                        .unwrap_or(0)
                        .min(self.filtered_events.len() - 1),
                ));
            }
        }

        Ok(())
    }

    pub fn search_events(&mut self) {
        self.filtered_events.clear();

        for (i, ev) in self.events.iter().enumerate() {
            if self.search_query.is_empty() || match_query(ev, &self.search_query) {
                self.filtered_events.push(i);
            }
        }

        self.stream_state.select(Some(
            self.stream_state
                .selected()
                .unwrap_or(0)
                .min(self.filtered_events.len().saturating_sub(1)),
        ));
    }

    fn handle_mouse(&mut self, mouse: MouseEvent) {
        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some(idx) = row_at(
                    self.sev_area,
                    mouse.column,
                    mouse.row,
                    SEVERITY_FILTERS.len(),
                ) {
                    self.selected_sevs[idx] = !self.selected_sevs[idx];
                    self.sev_state.select(Some(idx));
                }
                if let Some(idx) = row_at(
                    self.filter_area,
                    mouse.column,
                    mouse.row,
                    FILTEREVENTS.len(),
                ) {
                    self.selected_filters[idx] = !self.selected_filters[idx];
                    self.filter_state.select(Some(idx));
                }
                if let Some(idx) = row_at_stream(self, mouse.column, mouse.row) {
                    self.stream_state.select(Some(idx));
                }
            }
            MouseEventKind::ScrollDown => self.scroll_down(),
            MouseEventKind::ScrollUp => {
                if self.follow_tail {
                    self.follow_tail = false;
                }
                self.scroll_up()
            }
            _ => {}
        }
    }

    fn handle_key(
        &mut self,
        key: KeyEvent,
        config_watcher: &watch::Sender<bool>,
    ) -> color_eyre::Result<()> {
        if self.searching {
            match key.code {
                KeyCode::Char('w') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.search_clear();
                }
                KeyCode::Char(c) => {
                    self.search_push(c);
                }
                KeyCode::Backspace => {
                    self.search_pop();
                }
                KeyCode::Esc | KeyCode::Enter => {
                    self.searching = false;
                }

                _ => {}
            }
        }

        match key.code {
            KeyCode::Char('r') => {
                if !self.searching || !self.running {
                    config_watcher.send(true)?;
                }
            }

            KeyCode::Up | KeyCode::Char('k') => {
                if self.follow_tail {
                    self.follow_tail = false;
                }
                self.scroll_up();
            }
            KeyCode::Down | KeyCode::Char('j') => self.scroll_down(),
            KeyCode::Char('g') => {
                if self.g_char {
                    self.g_char = false;
                    self.follow_tail = false;

                    if self.view_mode == ViewMode::History {
                        tracing::info!("in history.");
                        if let Err(e) = self.ensure_batches_loaded(0) {
                            tracing::error!("failed to load batch: {e}");
                            return Err(color_eyre::eyre::eyre!("failed to load batch: {e}"));
                        }
                    }
                    self.view_port.window_start = self.loaded_range.0 * PER_BATCH_SIZE;
                    self.stream_state.select(Some(0));
                    self.get_selected();
                } else {
                    self.g_char = true;
                }
            }

            KeyCode::Char('G') => {
                if !self.pause {
                    self.follow_tail = true;
                    self.view_mode = ViewMode::History;

                    let total = self.filtered_events.len();
                    let height = self.view_port.height as usize;

                    if total > 0 && height > 0 {
                        let last_global = total - 1;

                        self.view_port.window_start = last_global.saturating_sub(height - 1);

                        let local_selected = last_global - self.view_port.window_start;

                        self.stream_state.select(Some(local_selected));

                        self.get_selected();
                    }
                }
            }

            KeyCode::Char('q') => {
                if !self.searching {
                    self.running = false
                }
            }
            KeyCode::Char('t') => {
                self.twle_hr_format = !self.twle_hr_format;
            }
            KeyCode::Char('f') | KeyCode::Char('/') => {
                self.searching = true;
                self.search_query.clear();
            }
            KeyCode::Char('l') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                tracing::info!("clearning..");
                self.view_mode = ViewMode::Live;
                self.events.clear();
                self.filtered_events.clear();
                self.view_port.window_start = 0;
                self.stream_state.select(None);
                self.selected_event = None;

                self.crit_ev_count = 0;
                self.high_ev_count = 0;
                self.med_ev_count = 0;
                self.low_ev_count = 0;
                self.info_ev_count = 0;
            }
            KeyCode::Char('p') => self.pause = !self.pause,
            _ => {
                self.g_char = false;
            }
        }
        Ok(())
    }

    pub async fn run(
        mut self,
        mut terminal: DefaultTerminal,
        mut rx: Receiver<AppEvent>,
        sh_tx: &watch::Sender<bool>,
        writer_tx: &Sender<UiEvent>,
        mut batch_rx: Receiver<bool>,
        config_reload_tx: watch::Sender<bool>,
        mut config_rx: Receiver<ConfigState>,
    ) -> color_eyre::Result<()> {
        let realtime_ns = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_nanos() as u64;

        let mono = clock_gettime(ClockId::CLOCK_MONOTONIC)?;
        let mono_ns = mono.tv_sec() as u64 * 1_000_000_000 + mono.tv_nsec() as u64;

        self.wallclock_offset_ns = realtime_ns - mono_ns;

        let (input_tx, mut input_rx) = tokio::sync::mpsc::channel::<Event>(100);

        std::thread::spawn(move || {
            loop {
                match event::read() {
                    Ok(event) => {
                        if input_tx.blocking_send(event).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!("input error: {e}");
                        break;
                    }
                }
            }
        });

        let mut tick = tokio::time::interval(Duration::from_millis(150));

        while self.running {
            tokio::select! {
                Some(event) = input_rx.recv() => {
                    match event {
                        Event::Key(key) => self.handle_key(key, &config_reload_tx)?,
                        Event::Mouse(mouse) => self.handle_mouse(mouse),
                        _ => {}
                    }
                }

                Some(event) = rx.recv() => {
                    if !self.pause {
                        self.push(event, writer_tx).await?;
                    }
                }

                Some(_) = batch_rx.recv() => {
                    self.total_batches = read_batch_info()?.len();

                    if self.follow_tail
                        && self.tail_events_since_reload >= LIVE_BUFFER_SIZE
                        && self.total_batches > 0
                    {
                        let last_batch = self.total_batches - 1;

                        self.load_batch_range(last_batch, last_batch)?;

                        self.tail_events_since_reload = 0;

                        self.follow_tail_dirty = true;
                    }
                }

                Some(val) = config_rx.recv() => {
                    self.check_config_state(val);
                }

            _ = tick.tick() => {
                if self.follow_tail_dirty {
                    let total = self.filtered_events.len();
                    let height = self.view_port.height as usize;

                    if total > 0 && height > 0 {
                        let last = total - 1;

                        self.view_port.window_start =
                            last.saturating_sub(height - 1);

                        self.stream_state.select(Some(
                            last - self.view_port.window_start
                        ));

                        self.get_selected();
                    }

                    self.follow_tail_dirty = false;
                }

                terminal.draw(|frame| {
                    render(frame, &mut self);
                })?;
            }
            }
        }

        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;

        tracing::info!("Sending shutdown");
        sh_tx.send(true)?;

        Ok(())
    }

    pub fn scroll_up(&mut self) {
        let height = self.view_port.height as usize;

        if height == 0 {
            return;
        }

        let local = self.stream_state.selected().unwrap_or(0);

        let global = self.view_port.window_start + local;

        if global == 0 {
            return;
        }

        let next_global = global - 1;

        if self.view_mode == ViewMode::History {
            if let Err(e) = self.ensure_batches_loaded(next_global) {
                tracing::error!("failed to load batch: {e}");
                return;
            }
        }

        let loaded_global_start = self.loaded_range.0 * PER_BATCH_SIZE;
        let next_loaded_local = next_global.saturating_sub(loaded_global_start);
        let current_loaded_local = self
            .view_port
            .window_start
            .saturating_sub(loaded_global_start);

        let new_window_local = if next_loaded_local < current_loaded_local {
            next_loaded_local
        } else {
            current_loaded_local
        };

        self.view_port.window_start = loaded_global_start + new_window_local;
        let new_selected = next_loaded_local.saturating_sub(new_window_local);
        self.stream_state.select(Some(new_selected));
        self.get_selected();
    }

    pub fn scroll_down(&mut self) {
        let height = self.view_port.height as usize;

        if height == 0 {
            return;
        }

        let local = self.stream_state.selected().unwrap_or(0);

        let global = self.view_port.window_start + local;
        let next_global = global + 1;

        if self.view_mode == ViewMode::History {
            if let Err(e) = self.ensure_batches_loaded(next_global) {
                tracing::error!("failed to load batch: {e}");
                return;
            }
        }

        let loaded_global_start = self.loaded_range.0 * PER_BATCH_SIZE;

        let next_loaded_local = next_global.saturating_sub(loaded_global_start);

        if next_loaded_local >= self.filtered_events.len() {
            return;
        }

        let current_window_local = self
            .view_port
            .window_start
            .saturating_sub(loaded_global_start);

        let new_window_local = if next_loaded_local >= current_window_local + height {
            next_loaded_local - height + 1
        } else {
            current_window_local
        };

        self.view_port.window_start = loaded_global_start + new_window_local;
        let new_selected = next_loaded_local.saturating_sub(new_window_local);
        self.stream_state.select(Some(new_selected));
        self.get_selected();
    }

    pub fn get_selected(&mut self) {
        let Some(local) = self.stream_state.selected() else {
            self.selected_event = None;
            return;
        };

        let global = self.view_port.window_start + local;
        let loaded_global_start = self.loaded_range.0 * PER_BATCH_SIZE;

        let loaded_local = match global.checked_sub(loaded_global_start) {
            Some(v) => v,
            None => {
                self.selected_event = None;
                return;
            }
        };

        if let Some(&idx) = self.filtered_events.get(loaded_local) {
            self.selected_event = self.events.get(idx).cloned();
        } else {
            self.selected_event = None;
        }
    }

    pub fn search_push(&mut self, c: char) {
        self.search_query.push(c);
        self.search_events();
    }
    pub fn search_pop(&mut self) {
        self.search_query.pop();
        self.search_events();
    }

    pub fn search_clear(&mut self) {
        self.search_query.clear();
        self.search_events();
    }

    pub fn selected_event(&self) -> Option<&UiEvent> {
        let local = self.stream_state.selected()?;

        let global = self.view_port.window_start + local;
        let loaded_global_start = self.loaded_range.0 * PER_BATCH_SIZE;

        let loaded_local = global.checked_sub(loaded_global_start)?;

        self.filtered_events
            .get(loaded_local)
            .and_then(|&idx| self.events.get(idx))
    }
}

pub fn match_query(e: &UiEvent, st: &str) -> bool {
    let detail = &e.event.detail();
    let kind = &e.event.kind_label();

    if st.bytes().all(|b| b.is_ascii_digit()) && e.event.pid().to_string().contains(st) {
        return true;
    }
    detail.contains(st) || kind.contains(st)
}
