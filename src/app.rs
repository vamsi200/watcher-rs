use crate::AppEvent;
use crate::Severity;
use crate::gen_db::regain_privs;
use crate::gen_db::update_ipsum_db;
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
use tracing::info;

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

#[derive(Debug, PartialEq)]
pub enum UpdateDbState {
    Updating,
    Updated,
    UpdateFailed,
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
    pub live_buffer: bool,
    pub base_global: usize,
    pub flushed_global: usize,
    pub db_update_state: Option<(UpdateDbState, Instant)>,
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
            live_buffer: false,
            base_global: 0,
            flushed_global: 0,
            db_update_state: None,
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
            (batch, (batch + 1).min(last_batch))
        };
        info!("loading batch: {new_lo} {new_hi}");

        self.load_batch_range(new_lo, new_hi)
    }

    fn check_config_state(&mut self, state: ConfigState) {
        self.config_notification = Some((state, Instant::now() + Duration::from_secs(3)));
    }

    fn check_update_db_state(&mut self, state: UpdateDbState) {
        self.db_update_state = Some((state, Instant::now() + Duration::from_secs(3)));
    }

    pub fn update_db_notification(&mut self) {
        if let Some((_, expires_at)) = &self.db_update_state
            && Instant::now() >= *expires_at
        {
            self.db_update_state = None;
        }
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

        info!("batch: {:?}", batch_info);
        info!("lo: {}, hi: {}", lo, hi);

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

        if self.follow_tail {
            writer_tx.try_send(ev.clone()).ok();
        } else {
            writer_tx.send(ev.clone()).await?;
        }

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
        }

        let idx = self.events.len();
        self.events.push(ev);
        if self.search_query.is_empty() || match_query(&self.events[idx], &self.search_query) {
            self.filtered_events.push(idx);
            if self.follow_tail {
                self.follow_tail_dirty = true;
            }
        }

        if self.follow_tail {
            self.evict_flushed_prefix();
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
        db_tx: Sender<bool>,
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

            KeyCode::Char('U') => {
                self.check_update_db_state(UpdateDbState::Updating);

                std::thread::spawn(move || {
                    let result = update_ipsum_db().unwrap_or(false);
                    let _ = db_tx.blocking_send(result).unwrap();
                });
            }

            KeyCode::Up | KeyCode::Char('k') => {
                if self.follow_tail {
                    self.follow_tail = false;
                    self.follow_tail_dirty = false;
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
                } else {
                    self.follow_tail = false;
                }

                let total = self.filtered_events.len();
                let height = self.view_port.height as usize;

                if total > 0 && height > 0 {
                    let last_local = total - 1;
                    let local_window_start = last_local.saturating_sub(height - 1);

                    if self.live_buffer {
                        self.view_port.window_start = local_window_start;
                    } else {
                        let loaded_global_start = self.loaded_range.0 * PER_BATCH_SIZE;
                        self.view_port.window_start = loaded_global_start + local_window_start;
                    }

                    let local_selected = last_local - local_window_start;

                    self.stream_state.select(Some(local_selected));
                    self.get_selected();
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
        db_tx: Sender<bool>,
        mut db_rx: Receiver<bool>,
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
                        Event::Key(key) => self.handle_key(key, &config_reload_tx, db_tx.clone())?,
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

                    if self.follow_tail {
                        self.on_flush_confirmed(
                            self.total_batches * PER_BATCH_SIZE,
                            self.total_batches,
                        );
                    }
                }

                Some(result) = db_rx.recv() => {
                    if result {
                        self.check_update_db_state(UpdateDbState::Updated);
                    }else{
                        self.check_update_db_state(UpdateDbState::UpdateFailed);
                    }
                    regain_privs()?;
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

                            let window_start =
                            last.saturating_sub(height - 1);

                            self.view_port.window_start = window_start;

                            self.stream_state.select(Some(
                            last - window_start
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

    pub fn on_flush_confirmed(&mut self, flushed_count: usize, total_batches: usize) {
        info!("flushing..");
        self.flushed_global = flushed_count;
        self.total_batches = total_batches;
        self.evict_flushed_prefix();
    }

    fn evict_flushed_prefix(&mut self) {
        if self.events.len() <= LIVE_BUFFER_SIZE {
            return;
        }

        let excess = self.events.len() - LIVE_BUFFER_SIZE;
        let flushed_local = self.flushed_global.saturating_sub(self.base_global);
        let evict = excess.min(flushed_local);
        if evict == 0 {
            return;
        }

        self.events.drain(0..evict);
        self.base_global += evict;

        self.filtered_events.retain_mut(|idx| {
            if *idx < evict {
                false
            } else {
                *idx -= evict;
                true
            }
        });

        if self.view_port.window_start < self.base_global {
            self.view_port.window_start = self.base_global;
            self.stream_state.select(Some(0));
        }
        info!(
            "events size: {}, filtered_events size: {}",
            self.events.len(),
            self.filtered_events.len()
        );
    }

    fn ensure_backward_loaded(&mut self, global_needed: usize) -> color_eyre::Result<()> {
        if global_needed >= self.base_global || self.total_batches == 0 {
            return Ok(());
        }

        let last_batch = self.total_batches.saturating_sub(1);
        let batch = (global_needed / PER_BATCH_SIZE).min(last_batch);
        if batch >= self.loaded_range.0 && self.base_global <= batch * PER_BATCH_SIZE {
            return Ok(());
        }

        let batch_info = read_batch_info()?;
        let mut batch_events = read_batch(batch, &batch_info)?;
        let prepend_count = batch_events.len();

        batch_events.append(&mut self.events);
        self.events = batch_events;

        for idx in self.filtered_events.iter_mut() {
            *idx += prepend_count;
        }
        let mut new_filtered: Vec<usize> = (0..prepend_count)
            .filter(|&i| {
                self.search_query.is_empty() || match_query(&self.events[i], &self.search_query)
            })
            .collect();
        new_filtered.extend(self.filtered_events.drain(..));
        self.filtered_events = new_filtered;

        self.base_global = batch * PER_BATCH_SIZE;
        self.loaded_range.0 = self.loaded_range.0.min(batch);

        Ok(())
    }

    fn ensure_forward_loaded(&mut self, global_needed: usize) -> color_eyre::Result<()> {
        if self.total_batches == 0 {
            return Ok(());
        }

        let last_batch = self.total_batches - 1;
        let persisted_end = (last_batch + 1) * PER_BATCH_SIZE;

        let loaded_end = self.base_global + self.events.len();

        tracing::info!(
            "forward: needed={global_needed}, loaded_end={loaded_end}, persisted_end={persisted_end}, \
         base={}, events={}, batches={}",
            self.base_global,
            self.events.len(),
            self.total_batches,
        );

        if global_needed < loaded_end {
            return Ok(());
        }

        if global_needed >= persisted_end {
            return Ok(());
        }

        let batch = global_needed / PER_BATCH_SIZE;

        let batch_info = read_batch_info()?;
        let mut batch_events = read_batch(batch, &batch_info)?;

        let appended = batch_events.len();

        let old_len = self.events.len();
        self.events.append(&mut batch_events);

        for idx in old_len..self.events.len() {
            if self.search_query.is_empty() || match_query(&self.events[idx], &self.search_query) {
                self.filtered_events.push(idx);
            }
        }

        self.loaded_range.1 = batch;

        info!(
            "forward loaded batch: {batch}, appended: {appended}, events: {}",
            self.events.len()
        );

        Ok(())
    }

    fn scroll_up_live(&mut self) {
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

        if next_global < self.base_global {
            if let Err(e) = self.ensure_backward_loaded(next_global) {
                tracing::error!("failed to load batch: {e}");
                return;
            }
        }

        let next_local = next_global - self.base_global;

        let current_window_local = self.view_port.window_start.saturating_sub(self.base_global);

        let new_window_local = next_local.min(current_window_local);

        self.view_port.window_start = self.base_global + new_window_local;

        self.stream_state
            .select(Some(next_local - new_window_local));

        self.get_selected();
    }

    fn scroll_down_live(&mut self) {
        let height = self.view_port.height as usize;
        if height == 0 {
            return;
        }

        let local = self.stream_state.selected().unwrap_or(0);
        let global = self.view_port.window_start + local;
        let next_global = global + 1;

        if let Err(e) = self.ensure_forward_loaded(next_global) {
            tracing::error!("failed to load batch: {e}");
            return;
        }

        let Some(next_local) = next_global.checked_sub(self.base_global) else {
            return;
        };

        if next_local >= self.filtered_events.len() {
            return;
        }

        let current_window_local = self.view_port.window_start.saturating_sub(self.base_global);

        let new_window_local = if next_local >= current_window_local + height {
            next_local - height + 1
        } else {
            current_window_local
        };

        self.view_port.window_start = self.base_global + new_window_local;

        self.stream_state
            .select(Some(next_local - new_window_local));

        self.get_selected();
    }

    fn scroll_up_history(&mut self) {
        let height = self.view_port.height as usize;
        if height == 0 {
            return;
        }

        let local = self.stream_state.selected().unwrap_or(0);
        let global = self.view_port.window_start + local;

        if global == 0 {
            tracing::info!("global is zero");
            return;
        }

        let next_global = global - 1;

        let loaded_start = self.base_global;
        let loaded_end = self.base_global + self.events.len();

        if next_global < loaded_start || next_global >= loaded_end {
            if let Err(e) = self.ensure_batches_loaded(next_global) {
                tracing::error!("failed to load batch: {e}");
                return;
            }
        }

        let Some(next_local) = next_global.checked_sub(self.base_global) else {
            return;
        };

        if next_local >= self.events.len() {
            return;
        }

        let current_window_local = self.view_port.window_start.saturating_sub(self.base_global);

        let new_window_local = next_local.min(current_window_local);

        self.view_port.window_start = self.base_global + new_window_local;

        self.stream_state
            .select(Some(next_local - new_window_local));

        self.get_selected();
    }

    fn scroll_down_history(&mut self) {
        let height = self.view_port.height as usize;
        if height == 0 {
            return;
        }

        let local = self.stream_state.selected().unwrap_or(0);
        let global = self.view_port.window_start + local;
        let next_global = global + 1;

        if let Err(e) = self.ensure_batches_loaded(next_global) {
            tracing::error!("failed to load batch: {e}");
            return;
        }

        let Some(next_local) = next_global.checked_sub(self.base_global) else {
            return;
        };

        if next_local >= self.filtered_events.len() {
            return;
        }

        let current_window_local = self.view_port.window_start.saturating_sub(self.base_global);

        let new_window_local = if next_local >= current_window_local + height {
            next_local - height + 1
        } else {
            current_window_local
        };

        self.view_port.window_start = self.base_global + new_window_local;

        self.stream_state
            .select(Some(next_local - new_window_local));

        self.get_selected();
    }

    pub fn scroll_up(&mut self) {
        if self.follow_tail {
            self.scroll_up_live();
        } else {
            self.scroll_up_history();
        }
    }

    pub fn scroll_down(&mut self) {
        if self.follow_tail {
            self.scroll_down_live();
        } else {
            self.scroll_down_history();
        }
    }

    pub fn get_selected(&mut self) {
        let Some(local) = self.stream_state.selected() else {
            self.selected_event = None;
            return;
        };

        let global = self.view_port.window_start + local;
        let Some(loaded_local) = global.checked_sub(self.base_global) else {
            self.selected_event = None;
            return;
        };

        self.selected_event = self
            .filtered_events
            .get(loaded_local)
            .and_then(|&idx| self.events.get(idx).cloned());
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
