use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, Key, Modifiers, RichText};
use egui_extras::{Column, TableBuilder};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::detect::{self, DetRule, RuleSource, Severity};
use crate::loader::{self, FileInfo, Msg, Render};
use crate::model::{level_name, Col, Record, Section};
use crate::search::{Query, SearchOptions};

// ---------------------------------------------------------------- columns

struct ColDef {
    name: &'static str,
    width: f32,
    default: bool,
}

const C_LEVEL: usize = 0;
const C_TIME: usize = 1;
const C_RECORD: usize = 2;
const C_ERID: usize = 3;
const C_EVENT: usize = 4;
const C_DESC: usize = 5;
const C_DETECT: usize = 6;
const C_PROVIDER: usize = 7;
const C_CHANNEL: usize = 8;
const C_COMPUTER: usize = 9;
const C_USER: usize = 10;
const C_PID: usize = 11;
const C_TID: usize = 12;
const C_TASK: usize = 13;
const C_OPCODE: usize = 14;
const C_KEYWORDS: usize = 15;
const C_DATA: usize = 16;

#[rustfmt::skip]
const COLS: [ColDef; 17] = [
    ColDef { name: "Level", width: 105.0, default: true },
    ColDef { name: "Date and Time (UTC)", width: 215.0, default: true },
    ColDef { name: "Record #", width: 75.0, default: true },
    ColDef { name: "EventRecordID", width: 105.0, default: false },
    ColDef { name: "Event ID", width: 70.0, default: true },
    ColDef { name: "Description", width: 260.0, default: true },
    ColDef { name: "Detection", width: 220.0, default: true },
    ColDef { name: "Provider", width: 220.0, default: true },
    ColDef { name: "Channel", width: 110.0, default: false },
    ColDef { name: "Computer", width: 150.0, default: true },
    ColDef { name: "User SID", width: 120.0, default: false },
    ColDef { name: "PID", width: 60.0, default: false },
    ColDef { name: "TID", width: 60.0, default: false },
    ColDef { name: "Task", width: 60.0, default: false },
    ColDef { name: "Opcode", width: 60.0, default: false },
    ColDef { name: "Keywords", width: 150.0, default: false },
    ColDef { name: "Event Data", width: 300.0, default: true },
];

/// Level filter buckets: Critical, Error, Warning, Information (0 and 4), Verbose.
const LEVELS: [(&str, &[u8]); 5] = [
    ("Critical", &[1]),
    ("Error", &[2]),
    ("Warning", &[3]),
    ("Information", &[0, 4]),
    ("Verbose", &[5]),
];

/// What the Detections filter is showing.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Detection {
    /// Events matched by any rule.
    All,
    /// Index into the rule list.
    Rule(usize),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DetailTab {
    General,
    Json,
    Xml,
}

#[derive(Serialize, Deserialize)]
#[serde(default)]
struct Settings {
    columns: Vec<bool>,
    search_opts: SearchOptions,
    dark: bool,
    recent: Vec<PathBuf>,
    /// Folder of Sigma rules to import at startup.
    sigma_dir: Option<PathBuf>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            columns: COLS.iter().map(|c| c.default).collect(),
            search_opts: SearchOptions::default(),
            dark: true,
            recent: Vec::new(),
            sigma_dir: None,
        }
    }
}

/// Things a context menu asked for; applied after the UI pass so menus don't need `&mut self`.
enum Action {
    AddTerm(String),
    OnlyEventId(u32),
    ExcludeEventId(u32),
    TimeFrom(String),
    TimeTo(String),
    Copy(String, &'static str),
    CopyRendered(u32, u64, Render),
    ShowDetection(usize),
    Open(PathBuf),
}

/// Aggregates for the Log Summary window.
#[derive(Default)]
struct Summary {
    records: usize,
    first: String,
    last: String,
    levels: [usize; LEVELS.len()],
    computers: Vec<(String, usize)>,
    channels: Vec<(String, usize)>,
    providers: Vec<(String, usize)>,
    event_ids: Vec<(u32, String, &'static str, usize)>,
    accounts: Vec<(String, usize)>,
    ips: Vec<(String, usize)>,
    key_counts: Vec<usize>,
}

pub struct App {
    settings: Settings,

    file: Option<PathBuf>,
    info: Option<FileInfo>,
    records: Vec<Record>,
    keys: Vec<Box<str>>,
    keys_lc: Vec<Box<str>>,
    loader: Option<Receiver<Msg>>,
    load_started: Instant,
    load_time: Option<Duration>,
    records_done: bool,
    record_errors: usize,
    last_error: Option<String>,
    fatal: Option<String>,

    // Filter inputs.
    search: String,
    search_edited: Option<Instant>,
    event_ids: String,
    provider: Option<String>,
    levels: [bool; LEVELS.len()],
    time_from: String,
    time_to: String,
    sort_col: usize,
    sort_asc: bool,

    // Filter pipeline caches: query hits -> sort order -> view.
    query: Query,
    query_error: Option<String>,
    hits: Option<Vec<bool>>,
    hits_for: Option<(String, SearchOptions)>,
    order: Vec<u32>,
    order_for: (usize, usize),
    view: Vec<u32>,
    view_dirty: bool,
    last_refresh: Instant,
    filter_time: Duration,
    providers: Vec<(String, usize)>,
    /// Number of records `providers` was counted over (recount only when it changes).
    providers_counted: usize,
    summary: Option<Summary>,

    // Detections: built-in hunting rules, run once a file has finished loading.
    /// Built-in rules followed by imported Sigma rules.
    rules: Vec<DetRule>,
    sigma_rx: Option<Receiver<crate::sigma::LoadReport>>,
    sigma_status: Option<SigmaStatus>,
    detections: Vec<detect::Hits>,
    detections_ran: bool,
    detect_errors: Vec<String>,
    detect_time: Duration,
    /// Rules (indices into `rules`) matching each record, highest severity first.
    record_rules: HashMap<u32, Vec<u32>>,
    active_detection: Option<Detection>,
    detection_mask: Option<Vec<bool>>,
    show_empty_rules: bool,

    selected: Option<usize>,
    scroll_to_selected: bool,
    tab: DetailTab,
    /// JSON/XML of the selected record, rendered on demand from its chunk.
    rendered: Option<(usize, DetailTab, Result<String, String>)>,
    show_summary: bool,
    show_about: bool,
    fields_filter: String,
    focus_search: bool,
    toast: Option<(String, Instant)>,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, path: Option<PathBuf>) -> Self {
        let mut settings: Settings = cc
            .storage
            .and_then(|s| eframe::get_value(s, "settings_v3"))
            .unwrap_or_default();
        settings.columns.resize(COLS.len(), false);
        cc.egui_ctx.set_visuals(if settings.dark {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        });
        cc.egui_ctx.style_mut(|s| {
            s.spacing.item_spacing = egui::vec2(8.0, 4.0);
            s.spacing.button_padding = egui::vec2(8.0, 3.0);
        });

        let mut app = Self {
            settings,
            file: None,
            info: None,
            records: Vec::new(),
            keys: Vec::new(),
            keys_lc: Vec::new(),
            loader: None,
            load_started: Instant::now(),
            load_time: None,
            records_done: false,
            record_errors: 0,
            last_error: None,
            fatal: None,
            search: String::new(),
            search_edited: None,
            event_ids: String::new(),
            provider: None,
            levels: [true; LEVELS.len()],
            time_from: String::new(),
            time_to: String::new(),
            sort_col: C_TIME,
            sort_asc: true,
            query: Query::Empty,
            query_error: None,
            hits: None,
            hits_for: None,
            order: Vec::new(),
            order_for: (usize::MAX, 0),
            view: Vec::new(),
            view_dirty: false,
            last_refresh: Instant::now(),
            filter_time: Duration::ZERO,
            providers: Vec::new(),
            providers_counted: usize::MAX,
            summary: None,
            rules: detect::builtin_rules(),
            sigma_rx: None,
            sigma_status: None,
            detections: Vec::new(),
            detections_ran: false,
            detect_errors: Vec::new(),
            detect_time: Duration::ZERO,
            record_rules: HashMap::new(),
            active_detection: None,
            detection_mask: None,
            show_empty_rules: false,
            selected: None,
            scroll_to_selected: false,
            tab: DetailTab::General,
            rendered: None,
            show_summary: false,
            show_about: false,
            fields_filter: String::new(),
            focus_search: false,
            toast: None,
        };
        #[cfg(target_os = "macos")]
        crate::macos::set_context(&cc.egui_ctx);
        if let Some(dir) = app.settings.sigma_dir.clone() {
            if sigma_import_marker().is_some_and(|m| m.exists()) {
                // The previous import never finished (the app quit or crashed during it):
                // don't retry automatically, or a bad rule file could crash every launch.
                app.toast("The last Sigma import didn't finish, so it wasn't repeated. Use Detections → Reload to try again.");
                if let Some(m) = sigma_import_marker() {
                    let _ = std::fs::remove_file(m);
                }
            } else {
                app.load_sigma(dir, &cc.egui_ctx);
            }
        }
        if let Some(p) = path {
            app.open(p, &cc.egui_ctx);
        }
        app
    }

    // ---------------------------------------------------------------- loading

    fn open(&mut self, path: PathBuf, ctx: &egui::Context) {
        self.records.clear();
        self.keys.clear();
        self.keys_lc.clear();
        self.view.clear();
        self.order.clear();
        self.order_for = (usize::MAX, 0);
        self.hits = None;
        self.hits_for = None;
        self.providers.clear();
        self.providers_counted = usize::MAX;
        self.provider = None;
        self.summary = None;
        self.detections.clear();
        self.detections_ran = false;
        self.detect_errors.clear();
        self.record_rules.clear();
        self.active_detection = None;
        self.detection_mask = None;
        self.info = None;
        self.selected = None;
        self.rendered = None;
        self.record_errors = 0;
        self.last_error = None;
        self.fatal = None;
        self.records_done = false;
        self.load_time = None;
        self.load_started = Instant::now();
        // Dropping the old receiver cancels any in-flight load.
        self.loader = Some(loader::spawn(path.clone(), ctx.clone()));
        ctx.send_viewport_cmd(egui::ViewportCommand::Title(format!(
            "Tidewatch — {}",
            path.file_name().unwrap_or_default().to_string_lossy()
        )));
        self.settings.recent.retain(|p| p != &path);
        self.settings.recent.insert(0, path.clone());
        self.settings.recent.truncate(10);
        self.file = Some(path);
    }

    fn open_dialog(&mut self, ctx: &egui::Context) {
        if let Some(p) = rfd::FileDialog::new()
            .add_filter("Windows Event Log", &["evtx"])
            .add_filter("All files", &["*"])
            .pick_file()
        {
            self.open(p, ctx);
        }
    }

    fn poll_loader(&mut self) {
        let Some(rx) = &self.loader else { return };
        let deadline = Instant::now() + Duration::from_millis(12);
        loop {
            match rx.try_recv() {
                Ok(Msg::Info(info)) => self.info = Some(info),
                Ok(Msg::Records { records, new_keys }) => {
                    self.keys_lc
                        .extend(new_keys.iter().map(|k| k.to_lowercase().into_boxed_str()));
                    self.keys.extend(new_keys);
                    self.records.extend(records);
                    self.view_dirty = true;
                }
                Ok(Msg::RecordError(e)) => {
                    self.record_errors += 1;
                    self.last_error = Some(e);
                }
                Ok(Msg::Done) => {
                    self.records_done = true;
                    self.load_time = Some(self.load_started.elapsed());
                    // Field names are now complete, so recompile the query against all of them.
                    self.hits_for = None;
                    self.summary = None;
                    self.view_dirty = true;
                    self.last_refresh = Instant::now() - Duration::from_secs(1);
                    self.loader = None;
                    break;
                }
                Ok(Msg::Fatal(e)) => {
                    self.fatal = Some(e);
                    self.records_done = true;
                    self.loader = None;
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.loader = None;
                    break;
                }
            }
            if Instant::now() > deadline {
                break;
            }
        }
    }

    // ---------------------------------------------------------------- filtering

    fn mark_dirty(&mut self) {
        self.view_dirty = true;
        self.last_refresh = Instant::now() - Duration::from_secs(1);
    }

    fn search_changed(&mut self) {
        self.search_edited = Some(Instant::now());
        self.view_dirty = true;
    }

    fn refresh_view_if_needed(&mut self, ctx: &egui::Context) {
        if !self.view_dirty {
            return;
        }
        // Debounce typing on big logs so each keystroke doesn't rescan everything.
        if let Some(t) = self.search_edited {
            let debounce = match self.records.len() {
                n if n > 250_000 => 100,
                n if n > 50_000 => 40,
                _ => 0,
            };
            let wait = Duration::from_millis(debounce).saturating_sub(t.elapsed());
            if !wait.is_zero() {
                ctx.request_repaint_after(wait);
                return;
            }
        }
        // While streaming in records, don't refilter on every frame.
        // While loading, refresh less often on big logs: each refresh re-sorts and re-filters
        // everything loaded so far and competes with the parser for CPU.
        let interval = if self.records_done {
            0
        } else {
            (self.records.len() as u64 / 2_500).clamp(300, 2_000)
        };
        if self.last_refresh.elapsed() < Duration::from_millis(interval) {
            return;
        }
        self.view_dirty = false;
        self.search_edited = None;
        self.last_refresh = Instant::now();
        if self.records_done && !self.detections_ran && self.fatal.is_none() {
            self.run_detections();
        }
        let t = Instant::now();
        self.rebuild_view();
        self.filter_time = t.elapsed();
    }

    /// Stage 1: which records match the search query. Cached and updated incrementally:
    /// new records are scanned on their own, and a query that only narrows the previous one
    /// rescans only the previous hits.
    fn update_hits(&mut self) -> bool {
        let opts = self.settings.search_opts;
        let key = (self.search.trim().to_string(), opts);
        let n = self.records.len();
        let records = &self.records;
        let keys_lc = &self.keys_lc;

        if key.0.is_empty() {
            self.query = Query::Empty;
            self.query_error = None;
            self.hits = None;
            self.hits_for = Some(key);
            return true;
        }

        let same = self.hits_for.as_ref() == Some(&key);
        if !same {
            match Query::compile(&key.0, opts, keys_lc) {
                Ok(q) => {
                    self.query = q;
                    self.query_error = None;
                }
                Err(e) => {
                    // Keep showing the last good results.
                    self.query_error = Some(e);
                    return false;
                }
            }
        }
        let query = &self.query;

        match (&mut self.hits, &self.hits_for) {
            (Some(hits), Some(_)) if same => {
                let start = hits.len();
                let new: Vec<bool> = (start..n)
                    .into_par_iter()
                    .map(|i| query.matches(&records[i], opts, keys_lc))
                    .collect();
                hits.extend(new);
            }
            (Some(hits), Some((old, old_opts)))
                if *old_opts == opts && hits.len() == n && Query::narrows(old, &key.0, opts) =>
            {
                hits.par_iter_mut().enumerate().for_each(|(i, h)| {
                    if *h {
                        *h = query.matches(&records[i], opts, keys_lc);
                    }
                });
            }
            _ => {
                self.hits = Some(
                    records
                        .par_iter()
                        .map(|r| query.matches(r, opts, keys_lc))
                        .collect(),
                );
            }
        }
        self.hits_for = Some(key);
        true
    }

    /// Stage 2: all records sorted by the current column; only redone when the column or
    /// record count changes. Direction is applied when walking it.
    fn update_order(&mut self) {
        let want = (self.sort_col, self.records.len());
        if self.order_for == want {
            return;
        }
        let records = &self.records;
        let col = self.sort_col;
        let mut order: Vec<u32> = (0..records.len() as u32).collect();
        order.par_sort_unstable_by(|&a, &b| {
            let (ra, rb) = (&records[a as usize], &records[b as usize]);
            cmp_col(ra, rb, col).then(ra.record_id.cmp(&rb.record_id))
        });
        self.order = order;
        self.order_for = want;
    }

    /// Stage 3: walk the sort order keeping records that pass the query and cheap filters.
    fn rebuild_view(&mut self) {
        if !self.update_hits() {
            return;
        }
        self.update_order();

        let (include, exclude) = parse_event_ids(&self.event_ids);
        let all_levels = self.levels.iter().all(|b| *b);
        let mut level_ok = [false; 256];
        for ((_, lv), on) in LEVELS.iter().zip(self.levels) {
            for l in *lv {
                level_ok[*l as usize] = on;
            }
        }
        let from = normalize_time(&self.time_from);
        let to = normalize_time(&self.time_to);
        let provider = self.provider.as_deref();
        let detection_mask = self.detection_mask.as_deref();
        let records = &self.records;
        let hits = self.hits.as_deref();

        let keep = |&i: &u32| {
            let r = &records[i as usize];
            hits.is_none_or(|h| h[i as usize])
                && detection_mask.is_none_or(|m| m[i as usize])
                && (all_levels || level_ok[r.level as usize])
                && (include.is_empty() || include.contains(&r.event_id))
                && !exclude.contains(&r.event_id)
                && provider.is_none_or(|p| r.provider() == p)
                && (from.is_empty() || *r.timestamp >= *from)
                && (to.is_empty()
                    || r.timestamp.get(..to.len()).unwrap_or(&r.timestamp) <= to.as_str())
        };
        self.view = if self.sort_asc {
            self.order.par_iter().filter(|i| keep(i)).copied().collect()
        } else {
            self.order
                .par_iter()
                .rev()
                .filter(|i| keep(i))
                .copied()
                .collect()
        };

        // Provider counts only change when records arrive; recounting on every keystroke
        // costs hundreds of milliseconds on multi-million-event logs.
        if self.providers_counted != records.len() {
            let mut counts: HashMap<&str, usize> = HashMap::new();
            for r in records {
                *counts.entry(r.provider()).or_default() += 1;
            }
            self.providers = sorted_counts(counts.into_iter().map(|(k, v)| (k.to_string(), v)));
            self.providers_counted = records.len();
        }
    }

    fn set_sort(&mut self, col: usize) {
        if self.sort_col == col {
            self.sort_asc = !self.sort_asc;
        } else {
            self.sort_col = col;
            self.sort_asc = true;
        }
        self.mark_dirty();
        self.scroll_to_selected = true;
    }

    fn filters_active(&self) -> bool {
        !self.search.trim().is_empty()
            || !self.event_ids.trim().is_empty()
            || self.provider.is_some()
            || self.levels.iter().any(|b| !b)
            || !self.time_from.trim().is_empty()
            || !self.time_to.trim().is_empty()
            || self.active_detection.is_some()
    }

    fn clear_filters(&mut self) {
        self.search.clear();
        self.event_ids.clear();
        self.provider = None;
        self.levels = [true; LEVELS.len()];
        self.time_from.clear();
        self.time_to.clear();
        self.set_detection(None);
        self.mark_dirty();
    }

    fn run_detections(&mut self) {
        let t = Instant::now();
        let (hits, errors) = detect::run(&self.rules, &self.records, &self.keys_lc);
        self.detect_time = t.elapsed();
        self.record_rules.clear();
        for h in &hits {
            for &i in &h.records {
                self.record_rules.entry(i).or_default().push(h.rule as u32);
            }
        }
        for rules in self.record_rules.values_mut() {
            rules.sort_by_key(|&r| std::cmp::Reverse(self.rules[r as usize].severity));
        }
        self.detections = hits;
        self.detect_errors = errors;
        self.detections_ran = true;
    }

    fn set_detection(&mut self, d: Option<Detection>) {
        self.active_detection = d;
        self.detection_mask = d.map(|d| {
            let mut mask = vec![false; self.records.len()];
            match d {
                Detection::All => {
                    for &i in self.record_rules.keys() {
                        mask[i as usize] = true;
                    }
                }
                Detection::Rule(rule) => {
                    if let Some(h) = self.detections.iter().find(|h| h.rule == rule) {
                        for &i in &h.records {
                            mask[i as usize] = true;
                        }
                    }
                }
            }
            mask
        });
        self.mark_dirty();
    }

    fn rule_hits(&self, rule: usize) -> usize {
        self.detections
            .iter()
            .find(|h| h.rule == rule)
            .map_or(0, |h| h.records.len())
    }

    /// Append a term to the text query (switching out of regex mode if needed).
    fn add_term(&mut self, term: String) {
        if self.settings.search_opts.regex {
            self.settings.search_opts.regex = false;
            self.search.clear();
            self.toast("Switched search to text mode");
        }
        let trimmed = self.search.trim_end().len();
        self.search.truncate(trimmed);
        if !self.search.is_empty() {
            self.search.push(' ');
        }
        self.search.push_str(&term);
        self.mark_dirty();
    }

    fn apply(&mut self, action: Action, ctx: &egui::Context) {
        match action {
            Action::AddTerm(t) => self.add_term(t),
            Action::OnlyEventId(id) => {
                self.event_ids = id.to_string();
                self.mark_dirty();
            }
            Action::ExcludeEventId(id) => {
                if !self.event_ids.trim().is_empty() {
                    self.event_ids.push_str(", ");
                }
                self.event_ids.push_str(&format!("-{id}"));
                self.mark_dirty();
            }
            Action::TimeFrom(t) => {
                self.time_from = t;
                self.mark_dirty();
            }
            Action::TimeTo(t) => {
                self.time_to = t;
                self.mark_dirty();
            }
            Action::Copy(text, what) => {
                ctx.copy_text(text);
                self.toast(format!("Copied {what}"));
            }
            Action::CopyRendered(chunk, id, format) => {
                let result = self
                    .file
                    .as_deref()
                    .ok_or_else(|| "no file open".to_string())
                    .and_then(|p| loader::render(p, &[(chunk, id)], format));
                match result.ok().and_then(|mut m| m.remove(&(chunk, id))) {
                    Some(text) => {
                        ctx.copy_text(text);
                        self.toast(if format == Render::Xml {
                            "Copied event XML"
                        } else {
                            "Copied event JSON"
                        });
                    }
                    None => self.toast("Could not re-read the event from the file"),
                }
            }
            Action::ShowDetection(rule) => self.set_detection(Some(Detection::Rule(rule))),
            Action::Open(p) => self.open(p, ctx),
        }
    }

    fn compute_summary(&mut self) {
        let records = &self.records;
        let mut s = Summary {
            records: records.len(),
            ..Default::default()
        };
        let mut computers = HashMap::<&str, usize>::new();
        let mut channels = HashMap::<&str, usize>::new();
        let mut ids = HashMap::<(u32, &str), (usize, &'static str)>::new();
        let mut accounts = HashMap::<&str, usize>::new();
        let mut ips = HashMap::<&str, usize>::new();
        s.key_counts = vec![0; self.keys.len()];
        let target_user = self.keys.iter().position(|k| &**k == "TargetUserName");
        let ip = self.keys.iter().position(|k| &**k == "IpAddress");
        for r in records {
            if s.first.is_empty() || *r.timestamp < *s.first {
                s.first = r.timestamp.to_string();
            }
            if *r.timestamp > *s.last {
                s.last = r.timestamp.to_string();
            }
            if let Some(b) = LEVELS.iter().position(|(_, lv)| lv.contains(&r.level)) {
                s.levels[b] += 1;
            }
            *computers.entry(r.col(Col::Computer)).or_default() += 1;
            *channels.entry(r.col(Col::Channel)).or_default() += 1;
            ids.entry((r.event_id, r.provider()))
                .or_insert((0, r.description))
                .0 += 1;
            for f in r.fields.iter() {
                s.key_counts[f.key as usize] += 1;
                let v = r.value(f);
                if v.is_empty() || v == "-" {
                    continue;
                }
                if Some(f.key as usize) == target_user {
                    *accounts.entry(v).or_default() += 1;
                } else if Some(f.key as usize) == ip {
                    *ips.entry(v).or_default() += 1;
                }
            }
        }
        let own =
            |m: HashMap<&str, usize>| sorted_counts(m.into_iter().map(|(k, v)| (k.to_string(), v)));
        s.computers = own(computers);
        s.channels = own(channels);
        s.accounts = own(accounts);
        s.ips = own(ips);
        s.providers = self.providers.clone();
        let mut ids: Vec<_> = ids
            .into_iter()
            .map(|((id, p), (n, d))| (id, p.to_string(), d, n))
            .collect();
        ids.sort_by(|a, b| b.3.cmp(&a.3).then(a.0.cmp(&b.0)));
        s.event_ids = ids;
        self.summary = Some(s);
    }

    // ---------------------------------------------------------------- input

    fn handle_keys(&mut self, ctx: &egui::Context) {
        if ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::O)) {
            self.open_dialog(ctx);
        }
        if ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::F)) {
            self.focus_search = true;
        }
        if ctx.memory(|m| m.focused().is_some()) || self.view.is_empty() {
            return;
        }
        let (up, down, home, end, pgup, pgdn) = ctx.input(|i| {
            (
                i.key_pressed(Key::ArrowUp),
                i.key_pressed(Key::ArrowDown),
                i.key_pressed(Key::Home),
                i.key_pressed(Key::End),
                i.key_pressed(Key::PageUp),
                i.key_pressed(Key::PageDown),
            )
        });
        if !(up || down || home || end || pgup || pgdn) {
            return;
        }
        let pos = self
            .selected
            .and_then(|s| self.view.iter().position(|&i| i as usize == s));
        let last = self.view.len() - 1;
        let new_pos = match pos {
            None => 0,
            Some(p) if up => p.saturating_sub(1),
            Some(p) if down => (p + 1).min(last),
            Some(p) if pgup => p.saturating_sub(25),
            Some(p) if pgdn => (p + 25).min(last),
            Some(_) if home => 0,
            Some(_) => last,
        };
        self.select(Some(self.view[new_pos] as usize));
        self.scroll_to_selected = true;
    }

    fn select(&mut self, idx: Option<usize>) {
        self.selected = idx;
        self.rendered = None;
    }

    fn toast(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now()));
    }

    // ---------------------------------------------------------------- export

    fn export(&mut self, csv: bool) {
        let name = self
            .file
            .as_ref()
            .and_then(|p| p.file_stem())
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "events".into());
        let ext = if csv { "csv" } else { "jsonl" };
        let Some(path) = rfd::FileDialog::new()
            .set_file_name(format!("{name}-filtered.{ext}"))
            .add_filter(ext.to_uppercase(), &[ext])
            .save_file()
        else {
            return;
        };
        let result = if csv {
            self.write_csv(&path).map(|()| 0)
        } else {
            self.write_jsonl(&path)
        };
        match result {
            Ok(0) => self.toast(format!(
                "Exported {} events to {}",
                fmt_num(self.view.len()),
                path.display()
            )),
            Ok(missing) => self.toast(format!(
                "Exported {} events to {}; {} could not be re-read from the source file",
                fmt_num(self.view.len() - missing),
                path.display(),
                fmt_num(missing)
            )),
            Err(e) => self.toast(format!("Export failed: {e}")),
        }
    }

    fn write_csv(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        // Values come from the log file and may be attacker-controlled: make sure a
        // spreadsheet never interprets them as formulas.
        let safe = csv_safe;
        let mut w = csv::Writer::from_path(path)?;
        w.write_record([
            "RecordID",
            "TimeCreated",
            "Level",
            "EventID",
            "Description",
            "Provider",
            "Channel",
            "Computer",
            "UserSID",
            "ProcessID",
            "ThreadID",
            "Keywords",
            "EventData",
        ])?;
        for &i in &self.view {
            let r = &self.records[i as usize];
            let data: Vec<String> = r
                .fields
                .iter()
                .filter(|f| f.section != Section::System)
                .map(|f| {
                    csv_safe(&format!("{}={}", self.keys[f.key as usize], r.value(f))).into_owned()
                })
                .collect();
            w.write_record([
                &r.record_id.to_string(),
                &*safe(&r.timestamp),
                level_name(r.level),
                &r.event_id.to_string(),
                r.description,
                &*safe(r.provider()),
                &*safe(r.col(Col::Channel)),
                &*safe(r.col(Col::Computer)),
                &*safe(r.col(Col::UserSid)),
                &*safe(r.col(Col::Pid)),
                &*safe(r.col(Col::Tid)),
                &*safe(r.col(Col::Keywords)),
                &data.join("\n"),
            ])?;
        }
        w.flush()?;
        Ok(())
    }

    /// Returns how many events could not be re-read from the source file.
    fn write_jsonl(&self, path: &Path) -> Result<usize, Box<dyn std::error::Error>> {
        use std::io::Write;
        let src = self.file.as_ref().ok_or("no file open")?;
        let mut w = std::io::BufWriter::new(std::fs::File::create(path)?);
        let mut missing = 0;
        // Render in slices so huge exports don't hold every event's JSON in memory at once.
        for part in self.view.chunks(20_000) {
            let wanted: Vec<(u32, u64)> = part
                .iter()
                .map(|&i| {
                    (
                        self.records[i as usize].chunk,
                        self.records[i as usize].record_id,
                    )
                })
                .collect();
            let rendered = loader::render(src, &wanted, Render::JsonLine)?;
            for key in &wanted {
                match rendered.get(key) {
                    Some(json) => {
                        w.write_all(json.as_bytes())?;
                        w.write_all(b"\n")?;
                    }
                    None => missing += 1,
                }
            }
        }
        w.flush()?;
        Ok(missing)
    }

    // ---------------------------------------------------------------- UI: top

    fn menu_bar(&mut self, ui: &mut egui::Ui, actions: &mut Vec<Action>) {
        let ctx = ui.ctx().clone();
        egui::menu::bar(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui
                    .add(egui::Button::new("Open…").shortcut_text("⌘O"))
                    .clicked()
                {
                    ui.close_menu();
                    self.open_dialog(&ctx);
                }
                ui.add_enabled_ui(!self.settings.recent.is_empty(), |ui| {
                    ui.menu_button("Open Recent", |ui| {
                        for p in &self.settings.recent {
                            let label = p.file_name().unwrap_or_default().to_string_lossy();
                            if ui
                                .button(label)
                                .on_hover_text(p.display().to_string())
                                .clicked()
                            {
                                actions.push(Action::Open(p.clone()));
                                ui.close_menu();
                            }
                        }
                    });
                });
                ui.separator();
                let can_export = !self.view.is_empty();
                if ui
                    .add_enabled(can_export, egui::Button::new("Export filtered as CSV…"))
                    .clicked()
                {
                    ui.close_menu();
                    self.export(true);
                }
                if ui
                    .add_enabled(
                        can_export,
                        egui::Button::new("Export filtered as JSON Lines…"),
                    )
                    .clicked()
                {
                    ui.close_menu();
                    self.export(false);
                }
            });
            ui.menu_button("View", |ui| {
                ui.checkbox(&mut self.show_summary, "Log Summary");
                ui.separator();
                ui.label(RichText::new("Columns").weak());
                for (i, c) in COLS.iter().enumerate() {
                    ui.checkbox(&mut self.settings.columns[i], c.name);
                }
                if ui.button("Reset columns").clicked() {
                    self.settings.columns = COLS.iter().map(|c| c.default).collect();
                }
                ui.separator();
                let dark = ui.visuals().dark_mode;
                if ui
                    .button(if dark { "Light mode" } else { "Dark mode" })
                    .clicked()
                {
                    self.settings.dark = !dark;
                    ctx.set_visuals(if dark {
                        egui::Visuals::light()
                    } else {
                        egui::Visuals::dark()
                    });
                    ui.close_menu();
                }
            });
            ui.menu_button("Help", |ui| {
                ui.set_max_width(460.0);
                if ui.button("About Tidewatch").clicked() {
                    self.show_about = true;
                    ui.close_menu();
                }
                ui.separator();
                search_help(ui);
            });
        });
    }

    fn filter_bar(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        ui.add_space(4.0);

        // Row 1: search.
        ui.horizontal(|ui| {
            if ui.button("📂 Open").on_hover_text("Open an .evtx file (⌘O)").clicked() {
                self.open_dialog(&ctx);
            }
            ui.separator();

            let mut opts = self.settings.search_opts;
            ui.selectable_value(&mut opts.regex, false, "Text")
                .on_hover_text("Words, \"phrases\", -exclude, Field:contains, Field=equals, Field~regex");
            ui.selectable_value(&mut opts.regex, true, ".* Regex")
                .on_hover_text("One regex over every Field=value line (multi-line mode: ^ and $ match per field)");
            ui.toggle_value(&mut opts.case_sensitive, "Aa")
                .on_hover_text("Case sensitive");
            if opts != self.settings.search_opts {
                self.settings.search_opts = opts;
                self.mark_dirty();
            }

            let hint = if opts.regex {
                r"regex, e.g.  ^CommandLine=.*-enc(odedcommand)?\s"
            } else {
                "search all fields…   e.g.  TargetUserName:admin  LogonType=3  -svchost  \"exact phrase\""
            };
            let width = (ui.available_width() - 230.0).max(200.0);
            let search_id = egui::Id::new("search_box");
            let text_color = if self.query_error.is_some() { Some(Color32::from_rgb(240, 90, 90)) } else { None };
            let r = ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .id(search_id)
                    .hint_text(hint)
                    .font(egui::TextStyle::Monospace)
                    .text_color_opt(text_color)
                    .desired_width(width),
            );
            if self.focus_search {
                r.request_focus();
                self.focus_search = false;
            }
            if r.changed() {
                self.search_changed();
            }
            if r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                self.search_edited = None; // apply immediately
            }
            if let Some(e) = &self.query_error {
                r.on_hover_text(RichText::new(e).monospace());
            }

            self.fields_menu(ui);
            if ui.button("?").on_hover_ui(search_help).clicked() {}
        });
        if let Some(e) = &self.query_error {
            ui.colored_label(
                Color32::from_rgb(240, 90, 90),
                format!("Invalid query: {}", e.lines().last().unwrap_or(e)),
            );
        }

        // Row 2: detections and structured filters.
        ui.horizontal(|ui| {
            self.detections_menu(ui);
            ui.separator();
            ui.label("Event IDs");
            let r = ui
                .add(
                    egui::TextEdit::singleline(&mut self.event_ids)
                        .hint_text("4624, 4625, -4634")
                        .desired_width(130.0),
                )
                .on_hover_text(
                    "Comma-separated. Prefix with - to exclude. Ranges like 4720-4767 work.",
                );
            if r.changed() {
                self.mark_dirty();
            }

            ui.label("Provider");
            let current = self.provider.clone().unwrap_or_else(|| "All".into());
            let mut changed = false;
            egui::ComboBox::from_id_salt("provider")
                .selected_text(truncate_label(&current, 28))
                .width(200.0)
                .height(400.0)
                .show_ui(ui, |ui| {
                    changed |= ui
                        .selectable_value(&mut self.provider, None, "All")
                        .changed();
                    for (name, count) in &self.providers {
                        let label = format!("{name}  ({})", fmt_num(*count));
                        changed |= ui
                            .selectable_value(&mut self.provider, Some(name.clone()), label)
                            .changed();
                    }
                });
            if changed {
                self.mark_dirty();
            }

            ui.label("From");
            let tip = "UTC, any prefix of YYYY-MM-DD hh:mm:ss.ffffff";
            if ui
                .add(
                    egui::TextEdit::singleline(&mut self.time_from)
                        .hint_text("2024-01-31 08:00")
                        .desired_width(130.0),
                )
                .on_hover_text(tip)
                .changed()
            {
                self.mark_dirty();
            }
            ui.label("To");
            if ui
                .add(
                    egui::TextEdit::singleline(&mut self.time_to)
                        .hint_text("2024-01-31 17:30")
                        .desired_width(130.0),
                )
                .on_hover_text(format!(
                    "{tip}. Inclusive: 2024-01-31 includes that whole day."
                ))
                .changed()
            {
                self.mark_dirty();
            }

            ui.separator();
            let dark = ui.visuals().dark_mode;
            for (i, (name, lv)) in LEVELS.iter().enumerate() {
                let text = RichText::new(*name).color(level_color(lv[0], dark));
                if ui.checkbox(&mut self.levels[i], text).changed() {
                    self.mark_dirty();
                }
            }

            if self.filters_active() {
                ui.separator();
                if ui.button("✖ Clear filters").clicked() {
                    self.clear_filters();
                }
            }
        });
        ui.add_space(4.0);
    }

    /// Dropdown of every field name in the log; picking one starts a `Field:` term.
    fn fields_menu(&mut self, ui: &mut egui::Ui) {
        let counts = self.summary.as_ref().map(|s| s.key_counts.clone());
        let mut picked: Option<String> = None;
        ui.menu_button("Fields ⏷", |ui| {
            ui.set_min_width(320.0);
            ui.add(
                egui::TextEdit::singleline(&mut self.fields_filter)
                    .hint_text("filter field names")
                    .desired_width(300.0),
            )
            .request_focus();
            ui.label(
                RichText::new("Click to add  Field:  to the search")
                    .weak()
                    .small(),
            );
            ui.separator();
            let f = self.fields_filter.to_lowercase();
            let mut names: Vec<(usize, &str)> = self
                .keys
                .iter()
                .enumerate()
                .filter(|(i, _)| f.is_empty() || self.keys_lc[*i].contains(&f))
                .map(|(i, k)| (i, &**k))
                .collect();
            names.sort_by_key(|(_, n)| n.to_lowercase());
            egui::ScrollArea::vertical()
                .max_height(420.0)
                .show(ui, |ui| {
                    for (i, name) in names {
                        let label = match counts.as_ref().and_then(|c| c.get(i)) {
                            Some(n) => format!("{name}   ({})", fmt_num(*n)),
                            None => name.to_string(),
                        };
                        if ui.button(label).clicked() {
                            picked = Some(name.to_string());
                            ui.close_menu();
                        }
                    }
                });
        });
        if let Some(name) = picked {
            if self.settings.search_opts.regex {
                self.settings.search_opts.regex = false;
                self.search.clear();
            }
            if !self.search.is_empty() && !self.search.ends_with(' ') {
                self.search.push(' ');
            }
            self.search.push_str(&name);
            self.search.push(':');
            self.focus_search = true;
            self.search_changed();
        }
    }

    fn detections_menu(&mut self, ui: &mut egui::Ui) {
        let matched_rules = self.detections.len();
        let label = if !self.detections_ran {
            "Detections".to_string()
        } else {
            format!("Detections ({matched_rules})")
        };
        let dark = ui.visuals().dark_mode;
        let mut picked: Option<Option<Detection>> = None;
        let button = if matched_rules > 0 {
            RichText::new(format!("🛡 {label} ⏷")).color(severity_color(
                self.detections
                    .iter()
                    .map(|h| self.rules[h.rule].severity)
                    .max()
                    .unwrap_or(Severity::Info),
                dark,
            ))
        } else {
            RichText::new(format!("🛡 {label} ⏷"))
        };
        ui.menu_button(button, |ui| {
            ui.set_min_width(480.0);
            self.sigma_controls(ui);
            ui.separator();
            if !self.detections_ran {
                ui.label("Detections run once the file has finished loading.");
                return;
            }
            let flagged = self.record_rules.len();
            ui.label(
                RichText::new(format!(
                    "{matched_rules} of {} rules matched · {} flagged · {} ms",
                    self.rules.len(),
                    plural(flagged, "event"),
                    self.detect_time.as_millis()
                ))
                .weak(),
            );
            for e in &self.detect_errors {
                ui.colored_label(Color32::from_rgb(230, 80, 80), format!("Rule error: {e}"));
            }
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        flagged > 0,
                        egui::Button::new(format!(
                            "Show all flagged events ({})",
                            fmt_num(flagged)
                        )),
                    )
                    .clicked()
                {
                    picked = Some(Some(Detection::All));
                    ui.close_menu();
                }
                if self.active_detection.is_some() && ui.button("✖ Clear").clicked() {
                    picked = Some(None);
                    ui.close_menu();
                }
            });
            ui.checkbox(&mut self.show_empty_rules, "Show rules with no matches");
            ui.separator();

            let mut order: Vec<usize> = (0..self.rules.len()).collect();
            order.sort_by_key(|&i| {
                (
                    self.rules[i].tactic,
                    std::cmp::Reverse(self.rules[i].severity),
                    self.rules[i].name.clone(),
                )
            });
            // Size from the visible rows: the scroll area otherwise keeps the height it had
            // before "show rules with no matches" was toggled.
            let visible: Vec<usize> = order
                .iter()
                .copied()
                .filter(|&i| self.show_empty_rules || self.rule_hits(i) > 0)
                .collect();
            let mut tactics: Vec<_> = visible.iter().map(|&i| self.rules[i].tactic).collect();
            tactics.dedup();
            let row_h = ui.spacing().interact_size.y + ui.spacing().item_spacing.y;
            let height = ((visible.len() + tactics.len()) as f32 * row_h
                + 8.0 * tactics.len() as f32)
                .min(520.0);
            egui::ScrollArea::vertical()
                .id_salt(("detections_list", self.show_empty_rules))
                .min_scrolled_height(height)
                .max_height(520.0)
                .show(ui, |ui| {
                    let mut last_tactic = None;
                    for i in order {
                        let rule = &self.rules[i];
                        let n = self.rule_hits(i);
                        if n == 0 && !self.show_empty_rules {
                            continue;
                        }
                        if last_tactic != Some(rule.tactic) {
                            last_tactic = Some(rule.tactic);
                            ui.add_space(4.0);
                            ui.label(RichText::new(rule.tactic.label()).strong());
                        }
                        ui.horizontal(|ui| {
                            let sev = RichText::new(format!("{:<8}", rule.severity.label()))
                                .monospace()
                                .color(severity_color(rule.severity, dark));
                            ui.label(sev);
                            let name = truncate_label(&rule.name, 70);
                            let text = if n > 0 {
                                RichText::new(name)
                            } else {
                                RichText::new(name).weak()
                            };
                            let selected = self.active_detection == Some(Detection::Rule(i));
                            let r = ui
                                .add_enabled(n > 0, egui::SelectableLabel::new(selected, text))
                                .on_hover_text(format!(
                                    "{}  ·  {}\n\n{}",
                                    rule.mitre,
                                    rule.tactic.label(),
                                    rule.description
                                ));
                            if r.clicked() {
                                picked = Some(Some(Detection::Rule(i)));
                                ui.close_menu();
                            }
                            if rule.source == RuleSource::Sigma {
                                ui.label(RichText::new("Sigma").small().weak());
                            }
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.label(RichText::new(fmt_num(n)).monospace());
                                },
                            );
                        });
                    }
                    if matched_rules == 0 && !self.show_empty_rules {
                        ui.label(RichText::new("No rule matched this log.").weak());
                    }
                });
        });
        if let Some(d) = picked {
            self.set_detection(d);
            self.scroll_to_selected = true;
        }
    }

    /// Explains the active detection above the table.
    fn detection_banner(&mut self, ui: &mut egui::Ui) {
        let Some(active) = self.active_detection else {
            return;
        };
        let dark = ui.visuals().dark_mode;
        let mut clear = false;
        egui::Frame::group(ui.style())
            .fill(ui.visuals().faint_bg_color)
            .inner_margin(egui::Margin::symmetric(10.0, 8.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                match active {
                    Detection::All => {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("🛡 All flagged events").strong());
                            ui.label(format!(
                                "{} events matched at least one detection rule",
                                fmt_num(self.record_rules.len())
                            ));
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    clear = ui.button("✖ Clear").clicked();
                                },
                            );
                        });
                    }
                    Detection::Rule(i) => {
                        let rule = &self.rules[i];
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format!(" {} ", rule.severity.label()))
                                    .strong()
                                    .color(Color32::BLACK)
                                    .background_color(severity_color(rule.severity, dark)),
                            );
                            ui.label(RichText::new(&rule.name).strong().size(15.0));
                            ui.label(
                                RichText::new(format!("· {}", plural(self.rule_hits(i), "event")))
                                    .weak(),
                            );
                            if rule.source == RuleSource::Sigma {
                                ui.label(RichText::new("· imported Sigma rule").weak());
                            }
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    clear = ui.button("✖ Clear").clicked();
                                },
                            );
                        });
                        if !rule.description.is_empty() {
                            ui.label(&rule.description);
                        }
                        ui.horizontal_wrapped(|ui| {
                            if !rule.mitre.is_empty() {
                                ui.label(RichText::new("ATT&CK").weak());
                                for t in rule.mitre.split(',').map(str::trim) {
                                    ui.hyperlink_to(t, mitre_url(t));
                                }
                            }
                            ui.label(RichText::new(format!("· {}", rule.tactic.label())).weak());
                            ui.add_space(8.0);
                            ui.label(RichText::new("Log source").weak());
                            ui.label(RichText::new(&rule.log_source).monospace());
                        });
                        ui.horizontal_wrapped(|ui| {
                            ui.label(RichText::new("Logic").weak());
                            ui.label(RichText::new(rule.logic.join("   OR   ")).monospace());
                            if let Some(t) = rule.threshold {
                                let what = match t.distinct {
                                    Some(d) => format!("≥{} distinct {d}", t.min),
                                    None => format!("≥{} events", t.min),
                                };
                                ui.label(
                                    RichText::new(format!(
                                        "then {what} per {} within {}",
                                        t.group_by.join(" + "),
                                        fmt_window(t.window_secs)
                                    ))
                                    .monospace(),
                                );
                            }
                        });
                        if !rule.detail.is_empty() {
                            egui::CollapsingHeader::new(
                                RichText::new("Detection logic (Sigma)").weak(),
                            )
                            .id_salt(("rule_detail", i))
                            .show(ui, |ui| {
                                egui::ScrollArea::vertical()
                                    .max_height(220.0)
                                    .show(ui, |ui| {
                                        let mut text = rule.detail.as_str();
                                        ui.add(
                                            egui::TextEdit::multiline(&mut text)
                                                .code_editor()
                                                .desired_width(f32::INFINITY),
                                        );
                                    });
                            });
                        }
                        if !rule.false_positives.is_empty() {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(RichText::new("False positives").weak());
                                ui.label(&rule.false_positives);
                            });
                        }
                        if !rule.references.is_empty() {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(RichText::new("References").weak());
                                for url in &rule.references {
                                    if url.starts_with("http://") || url.starts_with("https://") {
                                        ui.hyperlink_to(short_url(url), url);
                                    } else {
                                        ui.label(url);
                                    }
                                }
                            });
                        }
                        {
                            ui.horizontal_wrapped(|ui| {
                                if !rule.author.is_empty() {
                                    ui.label(RichText::new("Original rule by").weak());
                                    ui.label(&rule.author);
                                }
                                if let Some(url) = &rule.license_url {
                                    ui.label(RichText::new("·").weak());
                                    if url == detect::RULE_LICENSE_URL {
                                        ui.hyperlink_to("Detection Rule License 1.1", url);
                                    } else {
                                        ui.label(format!("License: {url}"));
                                    }
                                }
                                ui.label(RichText::new("·").weak());
                                let mut id = rule.id.clone();
                                if !rule.status.is_empty() {
                                    id.push_str(&format!(" · status: {}", rule.status));
                                }
                                ui.label(RichText::new(id).weak().small()).on_hover_text(
                                    if rule.location.is_empty() {
                                        "Built-in rule"
                                    } else {
                                        rule.location.as_str()
                                    },
                                );
                            });
                        }
                    }
                }
            });
        if clear {
            self.set_detection(None);
        }
        ui.add_space(4.0);
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if let Some(f) = &self.file {
                ui.label(
                    RichText::new(f.file_name().unwrap_or_default().to_string_lossy()).strong(),
                )
                .on_hover_text(f.display().to_string());
                ui.separator();
            }
            if self.file.is_none() {
                ui.label(RichText::new("No file open").weak());
            } else if !self.records_done {
                ui.spinner();
                ui.label(format!("Parsing… {} events", fmt_num(self.records.len())));
            } else {
                ui.label(format!(
                    "{} of {} events",
                    fmt_num(self.view.len()),
                    fmt_num(self.records.len())
                ));
                if self.filters_active() {
                    ui.label(
                        RichText::new(format!("· filtered in {} ms", self.filter_time.as_millis()))
                            .weak(),
                    );
                }
                if let Some(t) = self.load_time {
                    ui.label(RichText::new(format!("· parsed in {:.2}s", t.as_secs_f64())).weak());
                }
            }
            if self.record_errors > 0 {
                ui.separator();
                let r = ui.label(
                    RichText::new(format!("⚠ {} corrupt records skipped", self.record_errors))
                        .color(Color32::from_rgb(230, 170, 50)),
                );
                if let Some(e) = &self.last_error {
                    r.on_hover_text(format!("Last error: {e}"));
                }
            }
            if let Some((msg, at)) = &self.toast {
                if at.elapsed() < Duration::from_secs(4) {
                    ui.separator();
                    ui.label(RichText::new(msg).strong());
                    ui.ctx().request_repaint_after(Duration::from_millis(500));
                }
            }
        });
    }

    // ---------------------------------------------------------------- UI: table

    fn table(&mut self, ui: &mut egui::Ui, actions: &mut Vec<Action>) {
        let dark = ui.visuals().dark_mode;
        let row_height = ui.text_style_height(&egui::TextStyle::Body) + 6.0;
        let scroll_target = if self.scroll_to_selected {
            self.selected
                .and_then(|s| self.view.iter().position(|&i| i as usize == s))
        } else {
            None
        };
        self.scroll_to_selected = false;

        let visible: Vec<usize> = (0..COLS.len())
            .filter(|&i| self.settings.columns[i])
            .collect();
        if visible.is_empty() {
            ui.label("All columns are hidden — enable some under View → Columns.");
            return;
        }

        let mut clicked: Option<usize> = None;
        let mut sort_clicked: Option<usize> = None;

        let mut builder = TableBuilder::new(ui)
            .id_salt(("table", visible.clone()))
            .striped(true)
            .resizable(true)
            .sense(egui::Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .min_scrolled_height(0.0)
            .max_scroll_height(f32::INFINITY);
        for (n, &c) in visible.iter().enumerate() {
            builder = builder.column(if n + 1 == visible.len() {
                Column::remainder().at_least(80.0)
            } else {
                Column::initial(COLS[c].width).at_least(40.0).clip(true)
            });
        }
        if let Some(row) = scroll_target {
            builder = builder.scroll_to_row(row, Some(egui::Align::Center));
        }

        builder
            .header(row_height + 2.0, |mut header| {
                for &c in &visible {
                    header.col(|ui| {
                        let mut text = COLS[c].name.to_string();
                        if c == self.sort_col {
                            text.push_str(if self.sort_asc { " ⏶" } else { " ⏷" });
                        }
                        let r = ui.add(
                            egui::Label::new(RichText::new(text).strong())
                                .sense(egui::Sense::click())
                                .selectable(false)
                                .truncate(),
                        );
                        if c != C_DATA
                            && c != C_DETECT
                            && r.on_hover_cursor(egui::CursorIcon::PointingHand).clicked()
                        {
                            sort_clicked = Some(c);
                        }
                    });
                }
            })
            .body(|body| {
                body.rows(row_height, self.view.len(), |mut row| {
                    let idx = self.view[row.index()] as usize;
                    let r = &self.records[idx];
                    row.set_selected(self.selected == Some(idx));
                    for &c in &visible {
                        row.col(|ui| {
                            let text = match c {
                                C_LEVEL => RichText::new(format!(
                                    "{} {}",
                                    level_icon(r.level),
                                    level_name(r.level)
                                ))
                                .color(level_color(r.level, dark)),
                                C_TIME => RichText::new(&*r.timestamp).monospace(),
                                C_RECORD => RichText::new(r.record_id.to_string()).monospace(),
                                C_ERID => RichText::new(r.col(Col::EventRecordId)).monospace(),
                                C_EVENT => {
                                    RichText::new(r.event_id.to_string()).monospace().strong()
                                }
                                C_DESC => RichText::new(r.description),
                                C_DETECT => match self.record_rules.get(&(idx as u32)) {
                                    Some(rules) => {
                                        let top = &self.rules[rules[0] as usize];
                                        let more = if rules.len() > 1 {
                                            format!("  +{}", rules.len() - 1)
                                        } else {
                                            String::new()
                                        };
                                        RichText::new(format!("{}{more}", top.name))
                                            .color(severity_color(top.severity, dark))
                                    }
                                    None => RichText::new(""),
                                },
                                C_PROVIDER => RichText::new(r.provider()),
                                C_CHANNEL => RichText::new(r.col(Col::Channel)),
                                C_COMPUTER => RichText::new(r.col(Col::Computer)),
                                C_USER => RichText::new(r.col(Col::UserSid)).monospace(),
                                C_PID => RichText::new(r.col(Col::Pid)).monospace(),
                                C_TID => RichText::new(r.col(Col::Tid)).monospace(),
                                C_TASK => RichText::new(r.col(Col::Task)).monospace(),
                                C_OPCODE => RichText::new(r.col(Col::Opcode)).monospace(),
                                C_KEYWORDS => RichText::new(r.col(Col::Keywords)).monospace(),
                                C_DATA => RichText::new(r.summary(&self.keys, 300)).weak(),
                                _ => unreachable!(),
                            };
                            ui.add(egui::Label::new(text).truncate().selectable(false));
                        });
                    }
                    let resp = row.response();
                    if resp.clicked() || resp.secondary_clicked() {
                        clicked = Some(idx);
                    }
                    resp.context_menu(|ui| row_menu(ui, r, actions));
                });
            });

        if let Some(c) = sort_clicked {
            self.set_sort(c);
        }
        if let Some(i) = clicked {
            self.select(Some(i));
        }
    }

    // ---------------------------------------------------------------- UI: details

    fn details(&mut self, ui: &mut egui::Ui, actions: &mut Vec<Action>) {
        let Some(idx) = self.selected else {
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new("Select an event to see its details").weak());
            });
            return;
        };

        ui.horizontal(|ui| {
            let r = &self.records[idx];
            let dark = ui.visuals().dark_mode;
            ui.label(
                RichText::new(format!("{} {}", level_icon(r.level), level_name(r.level)))
                    .color(level_color(r.level, dark)),
            );
            ui.label(
                RichText::new(format!("Event {}", r.event_id))
                    .strong()
                    .size(15.0),
            );
            if !r.description.is_empty() {
                ui.label(RichText::new(r.description).size(15.0));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.selectable_value(&mut self.tab, DetailTab::Xml, "XML");
                ui.selectable_value(&mut self.tab, DetailTab::Json, "JSON");
                ui.selectable_value(&mut self.tab, DetailTab::General, "Details");
            });
        });
        ui.horizontal_wrapped(|ui| {
            let r = &self.records[idx];
            let meta = [
                ("Time", &*r.timestamp),
                ("Computer", r.col(Col::Computer)),
                ("Provider", r.provider()),
                ("Channel", r.col(Col::Channel)),
            ];
            for (k, v) in meta {
                ui.label(RichText::new(k).weak());
                ui.label(RichText::new(v).monospace());
                ui.add_space(8.0);
            }
            ui.label(RichText::new("Record #").weak()).on_hover_text(
                "Record number in the file. The event's own EventRecordID is under System.",
            );
            ui.label(RichText::new(r.record_id.to_string()).monospace());
        });
        if let Some(rules) = self.record_rules.get(&(idx as u32)) {
            let dark = ui.visuals().dark_mode;
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Detections").weak());
                for &rule in rules {
                    let rule = rule as usize;
                    let r = &self.rules[rule];
                    let text = RichText::new(format!("[{}] {}", r.severity.label(), r.name))
                        .color(severity_color(r.severity, dark));
                    if ui
                        .link(text)
                        .on_hover_text(format!(
                            "{}\n\nOriginal rule by {} (Detection Rule License 1.1).\nClick to show all matches.",
                            r.description, r.author
                        ))
                        .clicked()
                    {
                        actions.push(Action::ShowDetection(rule));
                    }
                }
            });
        }
        ui.separator();

        match self.tab {
            DetailTab::General => self.details_fields(ui, idx, actions),
            tab => {
                if self
                    .rendered
                    .as_ref()
                    .is_none_or(|(i, t, _)| *i != idx || *t != tab)
                {
                    let r = &self.records[idx];
                    let format = if tab == DetailTab::Xml {
                        Render::Xml
                    } else {
                        Render::JsonPretty
                    };
                    let result = self
                        .file
                        .as_deref()
                        .ok_or_else(|| "no file open".to_string())
                        .and_then(|p| loader::render(p, &[(r.chunk, r.record_id)], format))
                        .and_then(|mut m| {
                            m.remove(&(r.chunk, r.record_id)).ok_or_else(|| {
                                "record could not be re-read from the file".to_string()
                            })
                        });
                    self.rendered = Some((idx, tab, result));
                }
                match &self.rendered {
                    Some((_, _, Ok(text))) => {
                        let id = if tab == DetailTab::Xml { "xml" } else { "json" };
                        code_view(ui, id, text, actions);
                    }
                    Some((_, _, Err(e))) => {
                        ui.colored_label(Color32::from_rgb(230, 80, 80), e);
                    }
                    None => {}
                }
            }
        }
    }

    fn details_fields(&self, ui: &mut egui::Ui, idx: usize, actions: &mut Vec<Action>) {
        let r = &self.records[idx];
        let opts = self.settings.search_opts;
        let section = |s: &[Section]| -> Vec<&crate::model::Field> {
            r.fields.iter().filter(|f| s.contains(&f.section)).collect()
        };
        let data = section(&[Section::EventData, Section::UserData]);
        let other = section(&[Section::Other]);
        let system = section(&[Section::System]);

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .id_salt("details_general")
            .show(ui, |ui| {
                ui.columns(2, |cols| {
                    cols[0].label(RichText::new("Event Data").strong());
                    if data.is_empty() {
                        cols[0].label(RichText::new("(none)").weak());
                    }
                    self.kv_grid(&mut cols[0], "evdata", r, &data, opts, actions);
                    if !other.is_empty() {
                        cols[0].add_space(10.0);
                        cols[0].label(RichText::new("Additional").strong());
                        self.kv_grid(&mut cols[0], "other", r, &other, opts, actions);
                    }
                    cols[1].label(RichText::new("System").strong());
                    self.kv_grid(&mut cols[1], "system", r, &system, opts, actions);
                });
            });
    }

    fn kv_grid(
        &self,
        ui: &mut egui::Ui,
        id: &str,
        rec: &Record,
        fields: &[&crate::model::Field],
        opts: SearchOptions,
        actions: &mut Vec<Action>,
    ) {
        // Hand-rolled rather than egui::Grid: Grid centers cells vertically, which pushes the
        // key of a long multi-line value (e.g. a script block) out of view.
        let dark = ui.visuals().dark_mode;
        let key_font = egui::TextStyle::Body.resolve(ui.style());
        let widest = fields
            .iter()
            .map(|f| {
                let key = self.keys[f.key as usize].to_string();
                ui.fonts(|fo| {
                    fo.layout_no_wrap(key, key_font.clone(), Color32::WHITE)
                        .size()
                        .x
                })
            })
            .fold(0.0, f32::max);
        let key_w = (widest + 12.0).min(ui.available_width() * 0.4);
        let stripe = ui.visuals().faint_bg_color;
        ui.push_id(id, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for (n, f) in fields.iter().enumerate() {
                let key = &*self.keys[f.key as usize];
                let value = rec.value(f);
                let fill = if n % 2 == 1 {
                    stripe
                } else {
                    Color32::TRANSPARENT
                };
                egui::Frame::none()
                    .fill(fill)
                    .inner_margin(egui::Margin::symmetric(2.0, 2.0))
                    .show(ui, |ui| {
                        ui.horizontal_top(|ui| {
                            ui.allocate_ui_with_layout(
                                egui::vec2(key_w, 0.0),
                                egui::Layout::top_down(egui::Align::Min),
                                |ui| {
                                    ui.set_width(key_w);
                                    ui.add(egui::Label::new(RichText::new(key).weak()).truncate());
                                },
                            );
                            let ranges =
                                self.query
                                    .highlights(f.key, &self.keys_lc, key, value, opts);
                            let job = highlighted(ui, value, &ranges, rec.note(f), dark);
                            let r =
                                ui.add(egui::Label::new(job).wrap().sense(egui::Sense::click()));
                            r.context_menu(|ui| field_menu(ui, key, value, actions));
                        });
                    });
            }
        });
    }

    // ---------------------------------------------------------------- UI: summary

    fn summary_window(&mut self, ctx: &egui::Context, actions: &mut Vec<Action>) {
        if !self.show_summary {
            return;
        }
        if self
            .summary
            .as_ref()
            .is_none_or(|s| s.records != self.records.len())
            && self.records_done
        {
            self.compute_summary();
        }
        let mut open = self.show_summary;
        egui::Window::new("Log Summary")
            .open(&mut open)
            .default_size([560.0, 640.0])
            .vscroll(true)
            .show(ctx, |ui| {
                let Some(s) = &self.summary else {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Waiting for parsing to finish…");
                    });
                    return;
                };
                ui.label(RichText::new("Click any entry to filter by it.").weak());
                ui.add_space(4.0);
                egui::CollapsingHeader::new(RichText::new("File").strong())
                    .default_open(true)
                    .show(ui, |ui| {
                        egui::Grid::new("fileinfo")
                            .num_columns(2)
                            .striped(true)
                            .show(ui, |ui| {
                                let mut row = |k: &str, v: String| {
                                    ui.label(RichText::new(k).weak());
                                    ui.label(RichText::new(v).monospace());
                                    ui.end_row();
                                };
                                if let Some(p) = &self.file {
                                    row("Path", p.display().to_string());
                                }
                                if let Some(i) = &self.info {
                                    row("Size", fmt_bytes(i.size));
                                    row(
                                        "Format version",
                                        format!("{}.{}", i.major_version, i.minor_version),
                                    );
                                    row(
                                        "Chunks",
                                        format!(
                                            "{} (first {}, last {})",
                                            i.chunk_count, i.first_chunk, i.last_chunk
                                        ),
                                    );
                                    row("Next record ID", i.next_record_id.to_string());
                                    let mut flags = Vec::new();
                                    if i.dirty {
                                        flags.push("dirty (not cleanly closed)");
                                    }
                                    if i.full {
                                        flags.push("full");
                                    }
                                    row(
                                        "Flags",
                                        if flags.is_empty() {
                                            "clean".into()
                                        } else {
                                            flags.join(", ")
                                        },
                                    );
                                }
                                row("Events", fmt_num(s.records));
                                if self.record_errors > 0 {
                                    row("Corrupt records", fmt_num(self.record_errors));
                                }
                                row("First event", s.first.clone());
                                row("Last event", s.last.clone());
                                let lv: Vec<String> = LEVELS
                                    .iter()
                                    .zip(s.levels)
                                    .filter(|(_, n)| *n > 0)
                                    .map(|((name, _), n)| format!("{name}: {}", fmt_num(n)))
                                    .collect();
                                row("Levels", lv.join(", "));
                            });
                    });

                count_section(
                    ui,
                    "Computers",
                    &s.computers,
                    true,
                    |v| format!("Computer={}", quote(v)),
                    actions,
                );
                count_section(
                    ui,
                    "Channels",
                    &s.channels,
                    false,
                    |v| format!("Channel={}", quote(v)),
                    actions,
                );
                count_section(
                    ui,
                    "Providers",
                    &s.providers,
                    false,
                    |v| format!("Provider.Name={}", quote(v)),
                    actions,
                );

                egui::CollapsingHeader::new(
                    RichText::new(format!("Event IDs ({})", s.event_ids.len())).strong(),
                )
                .default_open(true)
                .show(ui, |ui| {
                    egui::Grid::new("ids")
                        .num_columns(3)
                        .striped(true)
                        .show(ui, |ui| {
                            for (id, provider, desc, n) in s.event_ids.iter().take(300) {
                                if ui
                                    .link(RichText::new(id.to_string()).monospace().strong())
                                    .clicked()
                                {
                                    actions.push(Action::OnlyEventId(*id));
                                }
                                ui.label(RichText::new(fmt_num(*n)).monospace());
                                let d = if desc.is_empty() {
                                    provider.as_str()
                                } else {
                                    desc
                                };
                                ui.label(d).on_hover_text(provider);
                                ui.end_row();
                            }
                        });
                });
                if !s.accounts.is_empty() {
                    count_section(
                        ui,
                        "Target accounts (TargetUserName)",
                        &s.accounts,
                        false,
                        |v| format!("TargetUserName={}", quote(v)),
                        actions,
                    );
                }
                if !s.ips.is_empty() {
                    count_section(
                        ui,
                        "Source addresses (IpAddress)",
                        &s.ips,
                        false,
                        |v| format!("IpAddress={}", quote(v)),
                        actions,
                    );
                }
            });
        self.show_summary = open;
    }

    fn welcome(&mut self, ui: &mut egui::Ui, actions: &mut Vec<Action>) {
        ui.vertical_centered(|ui| {
            ui.add_space(ui.available_height() * 0.25);
            ui.label(RichText::new("Tidewatch").size(32.0).strong());
            ui.label(RichText::new("Windows event log viewer and threat hunting").weak());
            ui.add_space(8.0);
            ui.label(
                RichText::new("Drop a .evtx file here, double-click one in Finder, or")
                    .weak()
                    .size(16.0),
            );
            ui.add_space(8.0);
            if ui
                .button(RichText::new("📂 Open file…").size(18.0))
                .clicked()
            {
                let ctx = ui.ctx().clone();
                self.open_dialog(&ctx);
            }
            if let Some(e) = &self.fatal {
                ui.add_space(16.0);
                ui.colored_label(Color32::from_rgb(230, 80, 80), e);
            }
            if !self.settings.recent.is_empty() {
                ui.add_space(24.0);
                ui.label(RichText::new("Recent").weak());
                for p in self.settings.recent.iter().take(6) {
                    let name = p.file_name().unwrap_or_default().to_string_lossy();
                    if ui
                        .link(name)
                        .on_hover_text(p.display().to_string())
                        .clicked()
                    {
                        actions.push(Action::Open(p.clone()));
                    }
                }
            }
        });
    }
}

/// Exists while a Sigma import is running; see the startup check in `App::new`.
fn sigma_import_marker() -> Option<PathBuf> {
    eframe::storage_dir("Tidewatch").map(|d| d.join("sigma-import-in-progress"))
}

/// Result of the last Sigma import.
struct SigmaStatus {
    dir: PathBuf,
    rules: usize,
    files: usize,
    skipped: Vec<(PathBuf, String)>,
}

impl App {
    fn load_sigma(&mut self, dir: PathBuf, ctx: &egui::Context) {
        if let Some(marker) = sigma_import_marker() {
            if let Some(parent) = marker.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(&marker, b"");
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let ctx = ctx.clone();
        let _ = std::thread::Builder::new()
            .name("sigma-import".into())
            .stack_size(16 << 20)
            .spawn(move || {
                let report = crate::sigma::load_dir(&dir);
                let _ = tx.send(report);
                ctx.request_repaint();
            });
        self.sigma_rx = Some(rx);
    }

    fn poll_sigma(&mut self) {
        let Some(rx) = &self.sigma_rx else { return };
        let report = match rx.try_recv() {
            Ok(report) => report,
            Err(std::sync::mpsc::TryRecvError::Empty) => return,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.sigma_rx = None;
                self.toast("Sigma import failed unexpectedly");
                return;
            }
        };
        self.sigma_rx = None;
        if let Some(m) = sigma_import_marker() {
            let _ = std::fs::remove_file(m);
        }
        let dir = self.settings.sigma_dir.clone().unwrap_or_default();
        let n = report.rules.len();
        let drl = report.drl;
        let mut rules = detect::builtin_rules();
        rules.extend(
            report
                .rules
                .into_iter()
                .map(|r| DetRule::from_sigma(r, drl)),
        );
        self.rules = rules;
        self.sigma_status = Some(SigmaStatus {
            dir,
            rules: n,
            files: report.files,
            skipped: report.skipped,
        });
        self.rerun_detections();
        self.toast(format!("Imported {} Sigma rules", fmt_num(n)));
    }

    fn remove_sigma(&mut self) {
        self.settings.sigma_dir = None;
        self.sigma_status = None;
        self.sigma_rx = None;
        self.rules = detect::builtin_rules();
        self.rerun_detections();
    }

    /// Rule indices changed: drop results that refer to the old list and run again.
    fn rerun_detections(&mut self) {
        self.set_detection(None);
        self.detections.clear();
        self.record_rules.clear();
        self.detections_ran = false;
        self.mark_dirty();
    }

    fn sigma_controls(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        ui.horizontal(|ui| {
            ui.label(RichText::new("Sigma rules").strong());
            if self.sigma_rx.is_some() {
                ui.spinner();
                ui.label(RichText::new("importing…").weak());
            } else if let Some(st) = &self.sigma_status {
                let name = st
                    .dir
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                let mut hover = format!(
                    "{}\n{} rule files, {} imported, {} skipped",
                    st.dir.display(),
                    fmt_num(st.files),
                    fmt_num(st.rules),
                    fmt_num(st.skipped.len())
                );
                for (path, why) in st.skipped.iter().take(12) {
                    hover.push_str(&format!(
                        "\n• {}: {why}",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    ));
                }
                if st.skipped.len() > 12 {
                    hover.push_str("\n…");
                }
                ui.label(format!("{} imported from {name}", fmt_num(st.rules)))
                    .on_hover_text(hover);
            } else {
                ui.label(RichText::new("none imported").weak());
            }
        });
        ui.horizontal(|ui| {
            if ui
                .button("Import folder…")
                .on_hover_text("Choose a folder of Sigma .yml rules, e.g. a download of github.com/SigmaHQ/sigma")
                .clicked()
            {
                if let Some(dir) = rfd::FileDialog::new().set_title("Choose a folder of Sigma rules").pick_folder() {
                    self.settings.sigma_dir = Some(dir.clone());
                    self.load_sigma(dir, &ctx);
                }
                ui.close_menu();
            }
            if let Some(dir) = self.settings.sigma_dir.clone() {
                if ui.button("Reload").clicked() {
                    self.load_sigma(dir, &ctx);
                    ui.close_menu();
                }
                if ui.button("Remove").clicked() {
                    self.remove_sigma();
                    ui.close_menu();
                }
            }
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let dropped = ctx.input(|i| i.raw.dropped_files.iter().find_map(|f| f.path.clone()));
        if let Some(p) = dropped {
            self.open(p, ctx);
        }
        #[cfg(target_os = "macos")]
        if let Some(p) = crate::macos::take_opened().pop() {
            self.open(p, ctx);
        }

        self.poll_loader();
        self.poll_sigma();
        self.refresh_view_if_needed(ctx);
        if self.loader.is_some() || self.view_dirty {
            ctx.request_repaint_after(Duration::from_millis(50));
        }
        self.handle_keys(ctx);

        let mut actions = Vec::new();
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            self.menu_bar(ui, &mut actions);
            if self.file.is_some() {
                self.filter_bar(ui);
            }
        });
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| self.status_bar(ui));

        if self.file.is_none() || (self.records.is_empty() && self.fatal.is_some()) {
            egui::CentralPanel::default().show(ctx, |ui| self.welcome(ui, &mut actions));
        } else {
            egui::TopBottomPanel::bottom("details")
                .resizable(true)
                .default_height(340.0)
                .min_height(120.0)
                .frame(
                    egui::Frame::side_top_panel(&ctx.style())
                        .inner_margin(egui::Margin::symmetric(10.0, 6.0)),
                )
                .show(ctx, |ui| self.details(ui, &mut actions));
            egui::CentralPanel::default().show(ctx, |ui| {
                self.detection_banner(ui);
                egui::ScrollArea::horizontal().show(ui, |ui| self.table(ui, &mut actions));
            });
            self.summary_window(ctx, &mut actions);
        }

        about_window(ctx, &mut self.show_about);

        for a in actions {
            self.apply(a, ctx);
        }

        if ctx.input(|i| !i.raw.hovered_files.is_empty()) {
            let painter =
                ctx.layer_painter(egui::LayerId::new(egui::Order::Foreground, "drop".into()));
            let rect = ctx.screen_rect();
            painter.rect_filled(rect, 0.0, Color32::from_black_alpha(160));
            painter.text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "Drop to open",
                egui::FontId::proportional(28.0),
                Color32::WHITE,
            );
        }
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, "settings_v3", &self.settings);
    }
}

// ---------------------------------------------------------------- helpers

fn about_window(ctx: &egui::Context, open: &mut bool) {
    egui::Window::new("About Tidewatch")
        .open(open)
        .collapsible(false)
        .resizable(false)
        .default_width(440.0)
        .show(ctx, |ui| {
            ui.label(RichText::new("Tidewatch").size(22.0).strong());
            ui.label(RichText::new(format!("Version {}", env!("CARGO_PKG_VERSION"))).weak());
            ui.label("Windows event log viewer and threat hunting for macOS.");
            ui.add_space(8.0);
            ui.label(RichText::new("License").strong());
            ui.label(
                "Licensed under the PolyForm Small Business License 1.0.0: free for companies \
                 with fewer than 100 people and less than US$1M (2019, inflation-adjusted) \
                 annual revenue. Larger organizations need a commercial license; see the README.",
            );
            ui.hyperlink_to(
                "PolyForm Small Business License 1.0.0",
                "https://polyformproject.org/licenses/small-business/1.0.0",
            );
            ui.add_space(8.0);
            ui.label(RichText::new("Detection rules").strong());
            ui.label(
                "Built-in detections are adapted from Sigma and Hayabusa rules, licensed under \
                 the Detection Rule License 1.1. Imported Sigma rules keep their own license. \
                 Each rule shows its original authors and source.",
            );
            ui.hyperlink_to("Detection Rule License 1.1", detect::RULE_LICENSE_URL);
            ui.add_space(8.0);
            ui.label(RichText::new("Built with").strong());
            ui.label("evtx, egui/eframe, rayon, regex, memchr, serde, yaml_serde, rfd (MIT / Apache-2.0).");
        });
}

fn row_menu(ui: &mut egui::Ui, r: &Record, actions: &mut Vec<Action>) {
    if ui
        .button(format!("Show only Event ID {}", r.event_id))
        .clicked()
    {
        actions.push(Action::OnlyEventId(r.event_id));
        ui.close_menu();
    }
    if ui
        .button(format!("Exclude Event ID {}", r.event_id))
        .clicked()
    {
        actions.push(Action::ExcludeEventId(r.event_id));
        ui.close_menu();
    }
    let computer = r.col(Col::Computer);
    if !computer.is_empty() && ui.button(format!("Filter Computer = {computer}")).clicked() {
        actions.push(Action::AddTerm(format!("Computer={}", quote(computer))));
        ui.close_menu();
    }
    ui.separator();
    if ui.button("Events from this time onward").clicked() {
        actions.push(Action::TimeFrom(r.timestamp.to_string()));
        ui.close_menu();
    }
    if ui.button("Events up to this time").clicked() {
        actions.push(Action::TimeTo(r.timestamp.to_string()));
        ui.close_menu();
    }
    ui.separator();
    if ui.button("Copy as JSON").clicked() {
        actions.push(Action::CopyRendered(
            r.chunk,
            r.record_id,
            Render::JsonPretty,
        ));
        ui.close_menu();
    }
    if ui.button("Copy as XML").clicked() {
        actions.push(Action::CopyRendered(r.chunk, r.record_id, Render::Xml));
        ui.close_menu();
    }
    if ui.button("Copy fields as text").clicked() {
        actions.push(Action::Copy(r.text.to_string(), "event fields"));
        ui.close_menu();
    }
}

fn field_menu(ui: &mut egui::Ui, key: &str, value: &str, actions: &mut Vec<Action>) {
    let short = truncate_label(value, 40);
    if ui.button(format!("Filter: {key} = {short}")).clicked() {
        actions.push(Action::AddTerm(format!("{key}={}", quote(value))));
        ui.close_menu();
    }
    if ui.button(format!("Exclude: {key} = {short}")).clicked() {
        actions.push(Action::AddTerm(format!("-{key}={}", quote(value))));
        ui.close_menu();
    }
    if ui.button("Search for this value in any field").clicked() {
        actions.push(Action::AddTerm(quote(value)));
        ui.close_menu();
    }
    ui.separator();
    if ui.button("Copy value").clicked() {
        actions.push(Action::Copy(value.to_string(), "value"));
        ui.close_menu();
    }
    if ui.button("Copy field = value").clicked() {
        actions.push(Action::Copy(format!("{key}={value}"), "field"));
        ui.close_menu();
    }
}

fn count_section(
    ui: &mut egui::Ui,
    title: &str,
    items: &[(String, usize)],
    open: bool,
    term: impl Fn(&str) -> String,
    actions: &mut Vec<Action>,
) {
    egui::CollapsingHeader::new(RichText::new(format!("{title} ({})", items.len())).strong())
        .default_open(open)
        .show(ui, |ui| {
            egui::Grid::new(title)
                .num_columns(2)
                .striped(true)
                .show(ui, |ui| {
                    for (name, n) in items.iter().take(200) {
                        let label = if name.is_empty() { "(empty)" } else { name };
                        if ui.link(label).clicked() {
                            actions.push(Action::AddTerm(term(name)));
                        }
                        ui.label(RichText::new(fmt_num(*n)).monospace());
                        ui.end_row();
                    }
                });
        });
}

fn code_view(ui: &mut egui::Ui, id: &'static str, text: &str, actions: &mut Vec<Action>) {
    if ui.button("📋 Copy").clicked() {
        actions.push(Action::Copy(text.to_string(), id));
    }
    egui::ScrollArea::both()
        .auto_shrink([false, false])
        .id_salt(id)
        .show(ui, |ui| {
            let mut s = text;
            ui.add(
                egui::TextEdit::multiline(&mut s)
                    .code_editor()
                    .desired_width(f32::INFINITY),
            );
        });
}

/// Monospace value with search hits highlighted, followed by its decoded meaning.
fn highlighted(
    ui: &egui::Ui,
    value: &str,
    ranges: &[std::ops::Range<usize>],
    note: Option<&str>,
    dark: bool,
) -> egui::text::LayoutJob {
    use egui::text::{LayoutJob, TextFormat};
    let font = egui::TextStyle::Monospace.resolve(ui.style());
    let normal = TextFormat {
        font_id: font.clone(),
        color: ui.visuals().text_color(),
        ..Default::default()
    };
    let hit = TextFormat {
        font_id: font.clone(),
        color: Color32::BLACK,
        background: if dark {
            Color32::from_rgb(240, 200, 80)
        } else {
            Color32::from_rgb(255, 220, 90)
        },
        ..Default::default()
    };
    let mut job = LayoutJob::default();
    let mut pos = 0;
    for r in ranges {
        let (start, end) = (r.start.max(pos), r.end.min(value.len()));
        if start >= end || !value.is_char_boundary(start) || !value.is_char_boundary(end) {
            continue;
        }
        job.append(&value[pos..start], 0.0, normal.clone());
        job.append(&value[start..end], 0.0, hit.clone());
        pos = end;
    }
    job.append(&value[pos..], 0.0, normal);
    if let Some(n) = note {
        let fmt = TextFormat {
            font_id: egui::TextStyle::Body.resolve(ui.style()),
            color: if dark {
                Color32::from_rgb(130, 190, 140)
            } else {
                Color32::from_rgb(30, 120, 50)
            },
            italics: true,
            ..Default::default()
        };
        job.append(&format!("  {n}"), 0.0, fmt);
    }
    job
}

fn search_help(ui: &mut egui::Ui) {
    ui.label(RichText::new("Search syntax").strong());
    egui::Grid::new("help")
        .num_columns(2)
        .spacing([16.0, 4.0])
        .show(ui, |ui| {
            let rows = [
                ("mimikatz", "any field contains the text"),
                ("admin 10.0.0.5", "all terms must match"),
                ("\"logon type\"", "exact phrase"),
                ("-svchost", "exclude"),
                ("TargetUserName:adm", "field contains"),
                (
                    "LogonType=3",
                    "field equals (raw or decoded, e.g. =Network)",
                ),
                ("CommandLine~\"-enc\\s\"", "field matches regex"),
                ("ScriptBlockText:", "field exists"),
                (
                    "id=4624  pid=4",
                    "aliases: id, provider, user, pid, tid, time",
                ),
            ];
            for (q, d) in rows {
                ui.label(RichText::new(q).monospace());
                ui.label(d);
                ui.end_row();
            }
        });
    ui.add_space(4.0);
    ui.label("Regex mode runs one regex over every “Field=value” line; ^ and $ match per field.");
    ui.label("“Aa” toggles case sensitivity. ⌘F focuses search. Right-click values to filter.");
}

/// Prefix cells that a spreadsheet would treat as a formula (`=`, `+`, `-`, `@`, tab, CR)
/// with an apostrophe, the standard defence against CSV/formula injection.
fn csv_safe(s: &str) -> std::borrow::Cow<'_, str> {
    if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}").into()
    } else {
        s.into()
    }
}

fn severity_color(s: Severity, dark: bool) -> Color32 {
    match (s, dark) {
        (Severity::Critical, _) => Color32::from_rgb(235, 60, 120),
        (Severity::High, true) => Color32::from_rgb(245, 105, 90),
        (Severity::High, false) => Color32::from_rgb(200, 45, 30),
        (Severity::Medium, true) => Color32::from_rgb(240, 175, 60),
        (Severity::Medium, false) => Color32::from_rgb(175, 105, 0),
        (Severity::Low, true) => Color32::from_rgb(120, 180, 240),
        (Severity::Low, false) => Color32::from_rgb(30, 100, 190),
        (Severity::Info, true) => Color32::from_gray(160),
        (Severity::Info, false) => Color32::from_gray(90),
    }
}

/// "T1558.003" -> https://attack.mitre.org/techniques/T1558/003/
fn mitre_url(t: &str) -> String {
    format!(
        "https://attack.mitre.org/techniques/{}/",
        t.replace('.', "/")
    )
}

fn short_url(url: &str) -> String {
    let s = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host = s.split('/').next().unwrap_or(s);
    let last = s.trim_end_matches('/').rsplit('/').next().unwrap_or("");
    if last.is_empty() || last == host {
        host.to_string()
    } else {
        format!("{host} › {}", truncate_label(last, 40))
    }
}

fn plural(n: usize, noun: &str) -> String {
    format!("{} {noun}{}", fmt_num(n), if n == 1 { "" } else { "s" })
}

fn fmt_window(secs: i64) -> String {
    match secs {
        s if s % 3600 == 0 && s >= 3600 => format!("{} h", s / 3600),
        s if s % 60 == 0 && s >= 60 => format!("{} min", s / 60),
        s => format!("{s} s"),
    }
}

fn cmp_col(a: &Record, b: &Record, col: usize) -> Ordering {
    fn num(s: &str) -> u64 {
        s.strip_prefix("0x")
            .map(|h| u64::from_str_radix(h, 16).unwrap_or(0))
            .unwrap_or_else(|| s.parse().unwrap_or(0))
    }
    fn severity(l: u8) -> u8 {
        if l == 0 {
            4
        } else {
            l
        }
    }
    match col {
        C_LEVEL => severity(a.level).cmp(&severity(b.level)),
        C_TIME => a.timestamp.cmp(&b.timestamp),
        C_RECORD => a.record_id.cmp(&b.record_id),
        C_ERID => num(a.col(Col::EventRecordId)).cmp(&num(b.col(Col::EventRecordId))),
        C_EVENT => a.event_id.cmp(&b.event_id),
        C_DESC => a.description.cmp(b.description),
        C_PROVIDER => a.provider().cmp(b.provider()),
        C_CHANNEL => a.col(Col::Channel).cmp(b.col(Col::Channel)),
        C_COMPUTER => a.col(Col::Computer).cmp(b.col(Col::Computer)),
        C_USER => a.col(Col::UserSid).cmp(b.col(Col::UserSid)),
        C_PID => num(a.col(Col::Pid)).cmp(&num(b.col(Col::Pid))),
        C_TID => num(a.col(Col::Tid)).cmp(&num(b.col(Col::Tid))),
        C_TASK => num(a.col(Col::Task)).cmp(&num(b.col(Col::Task))),
        C_OPCODE => num(a.col(Col::Opcode)).cmp(&num(b.col(Col::Opcode))),
        C_KEYWORDS => a.col(Col::Keywords).cmp(b.col(Col::Keywords)),
        _ => Ordering::Equal,
    }
}

/// Quote a value for the query language if it needs it.
fn quote(v: &str) -> String {
    if !v.is_empty() && !v.chars().any(|c| c.is_whitespace() || c == '"') && !v.starts_with('-') {
        v.to_string()
    } else {
        format!("\"{}\"", v.replace('"', "\"\""))
    }
}

fn normalize_time(s: &str) -> String {
    s.trim().replacen('T', " ", 1)
}

fn level_color(level: u8, dark: bool) -> Color32 {
    match (level, dark) {
        (1, _) => Color32::from_rgb(220, 50, 90),
        (2, true) => Color32::from_rgb(240, 100, 100),
        (2, false) => Color32::from_rgb(190, 30, 30),
        (3, true) => Color32::from_rgb(235, 180, 60),
        (3, false) => Color32::from_rgb(170, 110, 0),
        (5, true) => Color32::from_gray(150),
        (5, false) => Color32::from_gray(100),
        (_, true) => Color32::from_rgb(120, 170, 235),
        (_, false) => Color32::from_rgb(30, 90, 180),
    }
}

fn level_icon(level: u8) -> &'static str {
    match level {
        1 | 2 => "⛔",
        3 => "⚠",
        5 => "…",
        _ => "ℹ",
    }
}

/// "4624, 4625-4630, -4634" -> (include, exclude)
fn parse_event_ids(s: &str) -> (HashSet<u32>, HashSet<u32>) {
    let mut include = HashSet::new();
    let mut exclude = HashSet::new();
    for part in s.split([',', ' ']).map(str::trim).filter(|p| !p.is_empty()) {
        let (target, body) = match part.strip_prefix('-') {
            Some(rest) => (&mut exclude, rest),
            None => (&mut include, part),
        };
        if let Some((a, b)) = body.split_once('-') {
            if let (Ok(a), Ok(b)) = (a.trim().parse::<u32>(), b.trim().parse::<u32>()) {
                if b >= a && b - a <= 100_000 {
                    target.extend(a..=b);
                }
            }
        } else if let Ok(n) = body.parse() {
            target.insert(n);
        }
    }
    (include, exclude)
}

fn sorted_counts(it: impl Iterator<Item = (String, usize)>) -> Vec<(String, usize)> {
    let mut v: Vec<_> = it.collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v
}

fn fmt_num(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn fmt_bytes(n: u64) -> String {
    match n {
        n if n >= 1 << 30 => format!("{:.2} GB", n as f64 / (1u64 << 30) as f64),
        n if n >= 1 << 20 => format!("{:.1} MB", n as f64 / (1u64 << 20) as f64),
        n if n >= 1 << 10 => format!("{:.1} KB", n as f64 / 1024.0),
        n => format!("{n} B"),
    }
}

fn truncate_label(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        format!("{}…", s.chars().take(max).collect::<String>())
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn csv_cells_cannot_become_formulas() {
        for evil in [
            "=HYPERLINK(\"http://x\")",
            "+1",
            "-2+3",
            "@SUM(A1)",
            "\tx",
            "\rx",
        ] {
            assert!(super::csv_safe(evil).starts_with('\''), "{evil:?}");
        }
        assert_eq!(super::csv_safe("DC01.corp.local"), "DC01.corp.local");
    }

    use super::*;

    #[test]
    fn event_id_parsing() {
        let (inc, exc) = parse_event_ids("4624, 4625-4627, -4634");
        assert_eq!(inc, HashSet::from([4624, 4625, 4626, 4627]));
        assert_eq!(exc, HashSet::from([4634]));
    }

    #[test]
    fn number_formatting() {
        assert_eq!(fmt_num(0), "0");
        assert_eq!(fmt_num(1234567), "1,234,567");
    }

    #[test]
    fn quoting() {
        assert_eq!(quote("SYSTEM"), "SYSTEM");
        assert_eq!(quote("NT AUTHORITY"), "\"NT AUTHORITY\"");
        assert_eq!(quote("-"), "\"-\"");
        assert_eq!(quote("a\"b"), "\"a\"\"b\"");
    }
}
