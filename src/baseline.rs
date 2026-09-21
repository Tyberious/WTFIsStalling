//! Before and after: every run leaves a small file of its numbers next to the report, and the
//! next run on the same PC compares itself with it. That turns "update this driver" into
//! something checkable ("stalls 14 -> 0") instead of two walls of text to diff by eye.
//!
//! The file is a plain `key=value` text format, one line per key, numbers written with Rust's
//! own `Display` (always a `.`, never a locale comma). It is deliberately not JSON: the record
//! is a handful of scalars plus one line per finding, and a serde dependency would cost the
//! single-file exe more than the format is worth. Unknown keys are ignored, malformed or
//! foreign files are ignored quietly, and nothing here may ever fail or delay a run.

use std::path::{Path, PathBuf};

use crate::summary::{Finding, Health, Severity, Summary};

/// Bumped when the meaning of a key changes. Files with another version are ignored.
pub const FORMAT: u32 = 1;
const MAGIC: &str = "wtfis-run";
/// Extension of the data file written next to `WTFIsStalling-<timestamp>.txt`.
pub const EXT: &str = "wtfis";
/// Older baselines are not offered: the PC has usually changed by then.
pub const MAX_AGE_DAYS: i64 = 30;
/// At most this many numbers per finding; the first one is the one it is judged by.
pub const MAX_METRICS: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unit {
    Count,
    Ms,
    Sec,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scaling {
    /// Grows with the length of the run, so runs of different lengths compare it per minute.
    WithTime,
    /// A worst case, or something the person did: it does not grow with the run.
    Fixed,
    /// Counted from the Windows event log's 7-day look-back. A fix made today cannot show up
    /// here yet, so this number must never be presented as "no change after your fix".
    LooksBack,
}

/// The one number that measures a finding, so two runs can be compared without reading prose.
/// Every metric is "lower is better".
#[derive(Clone, Debug, PartialEq)]
pub struct Metric {
    pub label: String,
    pub value: f64,
    pub unit: Unit,
    pub scaling: Scaling,
}

impl Metric {
    /// A count of things that happened while monitoring (more monitoring, more of them).
    pub fn count(label: &str, n: impl Into<f64>) -> Metric {
        Metric { label: label.into(), value: n.into(), unit: Unit::Count, scaling: Scaling::WithTime }
    }
    /// A count that does not grow with the run: flagged moments, a worst case's occurrences.
    pub fn flat(label: &str, n: impl Into<f64>) -> Metric {
        Metric { label: label.into(), value: n.into(), unit: Unit::Count, scaling: Scaling::Fixed }
    }
    pub fn ms(label: &str, value: f64) -> Metric {
        Metric { label: label.into(), value, unit: Unit::Ms, scaling: Scaling::Fixed }
    }
    pub fn secs(label: &str, value: impl Into<f64>) -> Metric {
        Metric { label: label.into(), value: value.into(), unit: Unit::Sec, scaling: Scaling::WithTime }
    }
    /// Counted from the last 7 days of the Windows event log.
    pub fn logged(label: &str, n: impl Into<f64>) -> Metric {
        Metric { label: label.into(), value: n.into(), unit: Unit::Count, scaling: Scaling::LooksBack }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct FindingRecord {
    pub key: String,
    pub severity: Severity,
    pub title: String,
    pub metrics: Vec<Metric>,
}

/// Everything one run stores for the next one to compare against. Numbers only: no prose, no
/// event log, nothing that identifies the PC or the person.
#[derive(Clone, Debug, PartialEq)]
pub struct RunRecord {
    pub tool: String,
    /// Unix seconds, for "how long ago" and for picking the newest baseline.
    pub unix_time: i64,
    /// Local "YYYY-MM-DD HH:MM" as the run saw it, for display only.
    pub when: String,
    pub machine: String,
    pub seconds: f64,
    pub light: bool,
    pub stalls_kernel: u32,
    pub stalls_starve: u32,
    pub worst_kernel_ms: f64,
    pub worst_sched_ms: f64,
    pub marks: u32,
    pub marks_clean: u32,
    pub health: Health,
    pub findings: Vec<FindingRecord>,
}

impl Default for RunRecord {
    fn default() -> RunRecord {
        RunRecord {
            tool: env!("CARGO_PKG_VERSION").to_string(),
            unix_time: 0,
            when: String::new(),
            machine: String::new(),
            seconds: 0.0,
            light: false,
            stalls_kernel: 0,
            stalls_starve: 0,
            worst_kernel_ms: 0.0,
            worst_sched_ms: 0.0,
            marks: 0,
            marks_clean: 0,
            health: Health::NoData,
            findings: Vec::new(),
        }
    }
}

// ---- the file format ---------------------------------------------------------------------

fn health_name(h: Health) -> &'static str {
    match h {
        Health::Ok => "ok",
        Health::Warning => "warning",
        Health::Problem => "problem",
        Health::NoData => "nodata",
    }
}

fn severity_name(s: Severity) -> &'static str {
    match s {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
    }
}

/// Fields are separated by `|` and metric parts by `;`, so neither may appear inside one. Both
/// runs sanitize the same way, so keys still match; the characters do not occur in practice.
fn field(s: &str) -> String {
    s.chars().map(|c| if c == '|' || c == ';' || c.is_control() { ' ' } else { c }).collect()
}

fn metric_text(m: &Metric) -> String {
    let unit = match m.unit {
        Unit::Count => "count",
        Unit::Ms => "ms",
        Unit::Sec => "sec",
    };
    let scaling = match m.scaling {
        Scaling::WithTime => "time",
        Scaling::Fixed => "fixed",
        Scaling::LooksBack => "back",
    };
    format!("{};{:.3};{unit};{scaling}", field(&m.label), m.value)
}

fn parse_metric(text: &str) -> Option<Metric> {
    let mut parts = text.split(';');
    let label = parts.next()?.to_string();
    let value: f64 = parts.next()?.trim().parse().ok()?;
    let unit = match parts.next()? {
        "count" => Unit::Count,
        "ms" => Unit::Ms,
        "sec" => Unit::Sec,
        _ => return None,
    };
    let scaling = match parts.next()? {
        "time" => Scaling::WithTime,
        "fixed" => Scaling::Fixed,
        "back" => Scaling::LooksBack,
        _ => return None,
    };
    (value.is_finite() && !label.is_empty()).then_some(Metric { label, value, unit, scaling })
}

pub fn to_text(rec: &RunRecord) -> String {
    let mut out = vec![
        format!("{MAGIC} {FORMAT}"),
        format!("tool={}", field(&rec.tool)),
        format!("time={}", rec.unix_time),
        format!("when={}", field(&rec.when)),
        format!("machine={}", field(&rec.machine)),
        format!("seconds={:.1}", rec.seconds),
        format!("light={}", u8::from(rec.light)),
        format!("stalls_kernel={}", rec.stalls_kernel),
        format!("stalls_starve={}", rec.stalls_starve),
        format!("worst_wake_kernel_ms={:.3}", rec.worst_kernel_ms),
        format!("worst_wake_sched_ms={:.3}", rec.worst_sched_ms),
        format!("marks={}", rec.marks),
        format!("marks_clean={}", rec.marks_clean),
        format!("health={}", health_name(rec.health)),
    ];
    for f in &rec.findings {
        let mut line = format!("finding={}|{}|{}", field(&f.key), severity_name(f.severity), field(&f.title));
        for m in f.metrics.iter().take(MAX_METRICS) {
            line.push('|');
            line.push_str(&metric_text(m));
        }
        out.push(line);
    }
    out.join("\r\n") + "\r\n"
}

/// Never panics and never guesses: anything that is not exactly this format returns None.
pub fn parse(text: &str) -> Option<RunRecord> {
    let mut lines = text.lines();
    let (magic, version) = lines.next()?.trim().split_once(' ')?;
    if magic != MAGIC || version.trim().parse::<u32>().ok()? != FORMAT {
        return None;
    }
    let mut rec = RunRecord::default();
    let (mut seen_time, mut seen_machine) = (false, false);
    for line in lines {
        let Some((key, value)) = line.trim_end().split_once('=') else { continue };
        match key {
            "tool" => rec.tool = value.to_string(),
            "time" => match value.trim().parse() {
                Ok(t) => {
                    rec.unix_time = t;
                    seen_time = true;
                }
                Err(_) => return None,
            },
            "when" => rec.when = value.to_string(),
            "machine" => {
                rec.machine = value.trim().to_string();
                seen_machine = !rec.machine.is_empty();
            }
            "seconds" => rec.seconds = value.trim().parse().ok().filter(|s: &f64| s.is_finite())?,
            "light" => rec.light = value.trim() == "1",
            "stalls_kernel" => rec.stalls_kernel = value.trim().parse().ok()?,
            "stalls_starve" => rec.stalls_starve = value.trim().parse().ok()?,
            "worst_wake_kernel_ms" => rec.worst_kernel_ms = value.trim().parse().ok()?,
            "worst_wake_sched_ms" => rec.worst_sched_ms = value.trim().parse().ok()?,
            "marks" => rec.marks = value.trim().parse().ok()?,
            "marks_clean" => rec.marks_clean = value.trim().parse().ok()?,
            "health" => {
                rec.health = match value.trim() {
                    "ok" => Health::Ok,
                    "warning" => Health::Warning,
                    "problem" => Health::Problem,
                    _ => Health::NoData,
                }
            }
            "finding" => {
                let mut parts = value.split('|');
                let key = parts.next()?.to_string();
                let severity = match parts.next()? {
                    "low" => Severity::Low,
                    "medium" => Severity::Medium,
                    "high" => Severity::High,
                    _ => continue,
                };
                let title = parts.next().unwrap_or("").to_string();
                let metrics: Vec<Metric> = parts.filter_map(parse_metric).take(MAX_METRICS).collect();
                if !key.is_empty() {
                    rec.findings.push(FindingRecord { key, severity, title, metrics });
                }
            }
            // Anything else comes from a newer build of the same format version: ignore it.
            _ => {}
        }
    }
    (seen_time && seen_machine).then_some(rec)
}

/// Reads a data file. Any problem at all (missing, unreadable, truncated, garbage, another
/// version) is simply "no baseline".
pub fn read(path: &Path) -> Option<RunRecord> {
    // A data file is a few kB; a huge one is not ours and is not worth reading into memory.
    if std::fs::metadata(path).ok()?.len() > 1_000_000 {
        return None;
    }
    parse(&std::fs::read_to_string(path).ok()?)
}

pub fn write(path: &Path, rec: &RunRecord) -> std::io::Result<()> {
    std::fs::write(path, to_text(rec))
}

/// `...\WTFIsStalling-20260920-163147.txt` -> `...\WTFIsStalling-20260920-163147.wtfis`
pub fn data_path_for(report: &str) -> PathBuf {
    PathBuf::from(report).with_extension(EXT)
}

/// The most recent data file in `dir` that was written by this same PC, is older than this run
/// and not older than 30 days. `skip` is this run's own file.
pub fn find_baseline(dir: &Path, now: &RunRecord, skip: &Path) -> Option<(PathBuf, RunRecord)> {
    let mut best: Option<(PathBuf, RunRecord)> = None;
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        if path == skip || !path.extension().is_some_and(|e| e.eq_ignore_ascii_case(EXT)) {
            continue;
        }
        let Some(rec) = read(&path) else { continue };
        let age = now.unix_time - rec.unix_time;
        if rec.machine != now.machine || age <= 0 || age > MAX_AGE_DAYS * 86_400 {
            continue;
        }
        if best.as_ref().is_none_or(|(_, b)| rec.unix_time > b.unix_time) {
            best = Some((path, rec));
        }
    }
    best
}

// ---- which PC this is --------------------------------------------------------------------

/// FNV-1a, 64-bit (<http://www.isthe.com/chongo/tech/comp/fnv/index.html>): a few lines, stable
/// across builds and machines, and nothing here needs a cryptographic hash.
fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// A stable id for this PC built only from what the report header already prints: the processor
/// model, the board model and the amount of memory. Deliberately nothing that identifies a
/// person or a machine - no serial numbers, no user name, no computer name - and hashed so that
/// even those model names do not appear in the file.
pub fn machine_id() -> String {
    let bios = "HARDWARE\\DESCRIPTION\\System\\BIOS";
    let get = |key: &str, value: &str| crate::util::reg_str(key, value).unwrap_or_default();
    let text = format!(
        "{}|{}|{}|{}",
        get("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "ProcessorNameString"),
        get(bios, "BaseBoardManufacturer"),
        get(bios, "BaseBoardProduct"),
        // Rounded to whole GB: the reported total moves slightly between boots on some PCs.
        crate::util::total_ram_bytes() / (1 << 30)
    );
    format!("{:016x}", fnv1a(&text))
}

// ---- comparing two runs ------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Gone,
    New,
    Better,
    Worse,
    Same,
}

/// Ordinary run-to-run variation. A number has to move by more than this share of the larger of
/// the two values *and* by more than its unit's floor before it is called a change; otherwise it
/// reads "about the same".
const NOISE_SHARE: f64 = 0.20;

/// The floor is applied to the raw numbers, never to the per-minute ones: 5 stalls over 10
/// minutes becoming 0 is a real win even though it is only half a stall per minute.
fn noise_floor(unit: Unit) -> f64 {
    match unit {
        Unit::Count => 1.0,
        Unit::Ms => 0.5,
        Unit::Sec => 2.0,
    }
}

/// `scale` is the per-minute factor applied to each value (1.0 when the runs are comparable).
fn classify(before: f64, after: f64, unit: Unit, scale: (f64, f64)) -> Change {
    let (a, b) = (before * scale.0, after * scale.1);
    let raw_moved = (after - before).abs() > noise_floor(unit);
    let share_moved = (b - a).abs() > NOISE_SHARE * a.abs().max(b.abs());
    if !raw_moved || !share_moved {
        return Change::Same;
    }
    if b < a {
        Change::Better
    } else {
        Change::Worse
    }
}

fn fmt_value(value: f64, unit: Unit, per_minute: bool) -> String {
    match (unit, per_minute) {
        (Unit::Count, false) => format!("{value:.0}"),
        (Unit::Count, true) => format!("{value:.1} per minute"),
        (Unit::Sec, false) => format!("{value:.0} s"),
        (Unit::Sec, true) => format!("{value:.1} s per minute"),
        (Unit::Ms, _) if value < 1.0 => format!("{value:.2} ms"),
        (Unit::Ms, _) if value < 100.0 => format!("{value:.1} ms"),
        (Unit::Ms, _) => format!("{value:.0} ms"),
    }
}

fn mmss(seconds: f64) -> String {
    let s = seconds.max(0.0) as u64;
    format!("{:02}:{:02}", s / 60, s % 60)
}

fn ago_text(seconds: i64) -> String {
    match seconds.max(0) {
        s if s < 3600 => "less than an hour ago".to_string(),
        s if s < 86_400 => format!("{} hour(s) ago", s / 3600),
        s => format!("{} day(s) ago", s / 86_400),
    }
}

/// How much the two runs' per-time numbers have to be stretched to be comparable, and whether
/// they had to be at all. Runs within 25% of each other are compared as they are.
fn scales(prev: &RunRecord, now: &RunRecord) -> (bool, (f64, f64)) {
    let (a, b) = (prev.seconds.max(1.0), now.seconds.max(1.0));
    if (a - b).abs() <= 0.25 * a.max(b) {
        return (false, (1.0, 1.0));
    }
    (true, (60.0 / a, 60.0 / b))
}

fn primary(f: &FindingRecord) -> Option<&Metric> {
    f.metrics.first()
}

/// A finding whose only measure comes from the event log's 7-day look-back cannot react to a fix
/// made today, so it is never allowed to say "no change" as if the fix had failed.
fn looks_back(f: &FindingRecord) -> bool {
    primary(f).is_some_and(|m| m.scaling == Scaling::LooksBack)
}

/// The comparison block, ready to be indented and wrapped by the report. Lines starting with
/// "- " are bullets. A pure function of the two records: everything here is unit tested.
pub fn compare(prev: &RunRecord, now: &RunRecord) -> Vec<String> {
    let (normalized, scale) = scales(prev, now);
    let per_minute = |m: &Metric| normalized && m.scaling == Scaling::WithTime;
    let factor = |m: &Metric| if per_minute(m) { scale } else { (1.0, 1.0) };

    // Pair the findings by key: this run's first, then anything only the old run had.
    let mut pairs: Vec<(Option<&FindingRecord>, Option<&FindingRecord>)> = Vec::new();
    for f in &now.findings {
        pairs.push((prev.findings.iter().find(|p| p.key == f.key), Some(f)));
    }
    for p in &prev.findings {
        if !now.findings.iter().any(|f| f.key == p.key) {
            pairs.push((Some(p), None));
        }
    }

    let mut bullets: Vec<String> = Vec::new();
    let (mut better, mut worse, mut gone, mut fresh) = (0, 0, 0, 0);
    for (old, new) in &pairs {
        let title = new.or(*old).map(|f| f.title.clone()).unwrap_or_default();
        let worth_a_verdict = old.map_or(Severity::Low, |f| f.severity).max(new.map_or(Severity::Low, |f| f.severity)) >= Severity::Medium;
        let caveat = |f: &FindingRecord| if looks_back(f) { " (this one looks back 7 days, so a fix cannot show here yet)" } else { "" };
        match (old, new) {
            (Some(o), None) => {
                let was = primary(o).map_or(String::new(), |m| format!(" (last time: {} {})", fmt_value(m.value, m.unit, false), m.label));
                bullets.push(format!("- {title}: did not show up this time{was}.{}", caveat(o)));
                if worth_a_verdict && !looks_back(o) {
                    gone += 1;
                }
            }
            (None, Some(n)) => {
                let num = primary(n).map_or(String::new(), |m| format!(" ({} {})", fmt_value(m.value, m.unit, false), m.label));
                bullets.push(format!("- {title}: new since last time{num}.{}", caveat(n)));
                if worth_a_verdict && !looks_back(n) {
                    fresh += 1;
                }
            }
            (Some(o), Some(n)) => {
                let mut moves: Vec<(Change, String)> = Vec::new();
                for m in n.metrics.iter() {
                    let Some(before) = o.metrics.iter().find(|x| x.label == m.label) else { continue };
                    let change = classify(before.value, m.value, m.unit, factor(m));
                    let p = per_minute(m);
                    moves.push((
                        change,
                        format!(
                            "{} {} -> {}",
                            m.label,
                            fmt_value(before.value * factor(m).0, m.unit, p),
                            fmt_value(m.value * factor(m).1, m.unit, p)
                        ),
                    ));
                }
                let change = moves.first().map_or(Change::Same, |(c, _)| *c);
                let word = match change {
                    Change::Better => "better",
                    Change::Worse => "worse",
                    _ => "about the same",
                };
                let numbers = if moves.is_empty() {
                    "still here".to_string()
                } else {
                    moves.iter().map(|(_, t)| t.clone()).collect::<Vec<_>>().join(", ")
                };
                bullets.push(format!("- {title}: {word} - {numbers}.{}", caveat(n)));
                if worth_a_verdict && !looks_back(n) {
                    match change {
                        Change::Better => better += 1,
                        Change::Worse => worse += 1,
                        _ => {}
                    }
                }
            }
            (None, None) => {}
        }
    }

    // ---- the one line that answers "did my fix help?"
    let stalls = |r: &RunRecord| (r.stalls_kernel + r.stalls_starve) as f64;
    let stall_change = classify(stalls(prev), stalls(now), Unit::Count, if normalized { scale } else { (1.0, 1.0) });
    let (up, down) = (fresh + worse, gone + better);
    let verdict = match (down, up) {
        (0, 0) => match stall_change {
            Change::Better => "Better: fewer stalls than last time.",
            Change::Worse => "Worse: more stalls than last time.",
            _ => "No real change since last time.",
        },
        (_, 0) if gone > 0 => "Better: what was found last time did not show up this time.",
        (_, 0) => "Better than last time.",
        (0, _) if fresh > 0 => "Worse: something showed up that was not there last time.",
        (0, _) => "Worse than last time.",
        _ => "Mixed: some things improved and something else got worse.",
    };

    let mut out = vec![
        format!(
            "COMPARED WITH YOUR LAST RUN ({}, {})",
            if prev.when.is_empty() { "earlier".into() } else { prev.when.clone() },
            ago_text(now.unix_time - prev.unix_time)
        ),
        verdict.to_string(),
    ];
    if prev.machine != now.machine {
        out.push("That run was recorded on a different PC, so treat this comparison as a rough guide.".to_string());
    }
    if normalized {
        out.push(format!(
            "The runs were different lengths ({} then {}), so counts are compared per minute.",
            mmss(prev.seconds),
            mmss(now.seconds)
        ));
    }
    if prev.seconds < 60.0 || now.seconds < 60.0 {
        out.push("One of the two runs was shorter than a minute, so this is a rough guide, not proof.".to_string());
    }
    if prev.light != now.light {
        let (then, this) = if prev.light { ("did", "did not") } else { ("did not", "did") };
        out.push(format!("Last time {then} use light mode and this time {this}, so stalls shorter than about 2 ms are not comparable.",));
    }
    // Stall counts grow with the run, so they follow the same per-minute rule as the findings.
    let (a, b) = if normalized { (stalls(prev) * scale.0, stalls(now) * scale.1) } else { (stalls(prev), stalls(now)) };
    out.push(format!("Stalls: {} -> {}.", fmt_value(a, Unit::Count, normalized), fmt_value(b, Unit::Count, normalized)));
    out.push(format!(
        "Worst wake-up delay: {} -> {}.",
        fmt_value(prev.worst_kernel_ms, Unit::Ms, false),
        fmt_value(now.worst_kernel_ms, Unit::Ms, false)
    ));
    out.extend(bullets);
    out
}

// ---- putting it together for a finished run ------------------------------------------------

/// Which baseline this run compares itself with.
#[derive(Default)]
pub enum CompareMode {
    /// The newest data file from this PC next to the report.
    #[default]
    Auto,
    /// A file the person named.
    Path(String),
    Off,
}

/// Compares this run with the previous one and saves its numbers for the next one. Called with
/// the summary before it is printed, so the comparison is part of the report everywhere.
///
/// Nothing here may fail a run: every file operation is allowed to go wrong, and the most that
/// happens is one plain line in the report.
pub fn attach(summary: &mut Summary, mode: &CompareMode, report_path: Option<&str>) {
    let mine = report_path.map(data_path_for);
    let previous = match mode {
        CompareMode::Off => None,
        CompareMode::Path(p) => match read(Path::new(p)) {
            Some(rec) => Some(rec),
            None => {
                crate::say!("(--compare: {p} is not a run saved by this tool, so there is nothing to compare with)");
                None
            }
        },
        // The report's own folder, which is where the person's earlier reports are.
        CompareMode::Auto => mine
            .as_ref()
            .and_then(|p| Some((p.parent()?, p)))
            .and_then(|(dir, p)| find_baseline(dir, &summary.record, p))
            .map(|(_, rec)| rec),
    };
    if let Some(prev) = previous {
        summary.comparison = compare(&prev, &summary.record);
    }
    if let Some(path) = &mine {
        if write(path, &summary.record).is_err() {
            crate::say!("(this run's numbers could not be saved, so the next run will have nothing to compare with)");
        }
    }
}

/// The record a finished summary stores. Built in `summarize`, where the numbers are.
pub struct RunFacts {
    pub seconds: f64,
    pub light: bool,
    pub stalls_kernel: u32,
    pub stalls_starve: u32,
    pub worst_kernel_ms: f64,
    pub worst_sched_ms: f64,
    pub marks: u32,
    pub marks_clean: u32,
}

pub fn record_of(facts: &RunFacts, health: Health, findings: &[Finding]) -> RunRecord {
    RunRecord {
        tool: env!("CARGO_PKG_VERSION").to_string(),
        unix_time: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64),
        when: crate::util::local_stamp(),
        machine: machine_id(),
        seconds: facts.seconds,
        light: facts.light,
        stalls_kernel: facts.stalls_kernel,
        stalls_starve: facts.stalls_starve,
        worst_kernel_ms: facts.worst_kernel_ms,
        worst_sched_ms: facts.worst_sched_ms,
        marks: facts.marks,
        marks_clean: facts.marks_clean,
        health,
        findings: {
            // Most severe first (the order findings arrive in), so when two processes of one
            // program collapse onto the same stable key the more serious one is kept.
            let mut kept: Vec<FindingRecord> = Vec::new();
            for f in findings {
                let key = stable_key(&f.key);
                if !kept.iter().any(|k| k.key == key) {
                    kept.push(FindingRecord { key, severity: f.severity, title: f.title.clone(), metrics: f.metrics.clone() });
                }
            }
            kept
        },
    }
}

/// A finding's key as it has to be for two runs to be matched up. Inside one run the key may
/// carry a process ID ("process game.exe (1234)", "paging chrome.exe (88)"), which is different
/// every time the program starts; the next run would report the old finding as gone and a new
/// one as appearing. Everything else in a key (driver file, disk number, PCI address, GPU name)
/// already survives a restart.
pub fn stable_key(key: &str) -> String {
    match key.rsplit_once(" (") {
        Some((head, tail)) if tail.ends_with(')') && tail.len() > 1 && tail[..tail.len() - 1].bytes().all(|b| b.is_ascii_digit()) => {
            head.to_string()
        }
        _ => key.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_survive_a_program_being_restarted() {
        assert_eq!(stable_key("process game.exe (1234)"), "process game.exe");
        assert_eq!(stable_key("paging chrome.exe (88)"), "paging chrome.exe");
        assert_eq!(stable_key("process System (kernel threads)"), "process System (kernel threads)");
        assert_eq!(stable_key("driver nvlddmkm.sys"), "driver nvlddmkm.sys");
        assert_eq!(stable_key("whea pcie Some((0, 1, 1))"), "whea pcie Some((0, 1, 1))");
        assert_eq!(stable_key("odd ()"), "odd ()");
    }

    fn finding(key: &str, severity: Severity, metrics: Vec<Metric>) -> FindingRecord {
        FindingRecord { key: key.into(), severity, title: format!("{key}  -  something"), metrics }
    }

    fn run(seconds: f64, findings: Vec<FindingRecord>) -> RunRecord {
        RunRecord {
            unix_time: 1_800_000_000,
            when: "2026-09-14 19:02".into(),
            machine: "abc123".into(),
            seconds,
            stalls_kernel: 2,
            worst_kernel_ms: 7.5,
            health: Health::Warning,
            findings,
            ..Default::default()
        }
    }

    #[test]
    fn a_run_survives_the_round_trip_through_the_file() {
        let rec = RunRecord {
            tool: "9.9.9".into(),
            unix_time: 1_790_123_456,
            when: "2026-09-14 19:02".into(),
            machine: "0123456789abcdef".into(),
            seconds: 302.4,
            light: true,
            stalls_kernel: 14,
            stalls_starve: 3,
            worst_kernel_ms: 11.802,
            worst_sched_ms: 0.412,
            marks: 3,
            marks_clean: 1,
            health: Health::Problem,
            findings: vec![
                finding("driver rtwlane.sys", Severity::High, vec![Metric::count("stalls blamed", 14), Metric::ms("worst stall", 11.802)]),
                finding("whea memory", Severity::Medium, vec![Metric::logged("in the last 7 days", 2)]),
                finding("throttling", Severity::Low, vec![Metric::secs("seconds throttled", 44)]),
            ],
        };
        let text = to_text(&rec);
        assert!(text.starts_with("wtfis-run 1\r\n"), "{text}");
        assert_eq!(parse(&text), Some(rec), "what was written must read back identically");
        // Numbers are written with a dot whatever the PC's regional settings say.
        assert!(text.contains("worst_wake_kernel_ms=11.802") && text.contains("stalls blamed;14.000;count;time"), "{text}");
    }

    #[test]
    fn a_file_that_is_not_ours_is_ignored_without_a_fuss() {
        let good = to_text(&run(60.0, vec![finding("disk 1", Severity::High, vec![Metric::count("slow requests", 3)])]));
        assert!(parse(&good).is_some());
        assert!(parse("").is_none(), "empty");
        assert!(parse("hello\nworld\n").is_none(), "not our format");
        assert!(parse(&good.replace("wtfis-run 1", "wtfis-run 2")).is_none(), "another format version");
        assert!(parse(&good.replace("machine=abc123", "")).is_none(), "no machine id");
        assert!(parse(&good.replace("time=1800000000", "time=not-a-number")).is_none());
        assert!(parse(&good[..40]).is_none(), "truncated mid-file");
        assert!(parse(&format!("{good}\u{0}\u{1}garbage\n\u{feff}")).is_some(), "trailing garbage lines are skipped");

        // A newer build writing keys this one has never heard of must still be readable.
        let future = good.replace("health=", "brand_new_key=hello\r\nhealth=");
        assert_eq!(parse(&future).map(|r| r.findings.len()), Some(1));
        // ...including an unknown unit on a metric: the finding stays, the metric is dropped.
        let odd = good.replace("count;time", "furlongs;time");
        assert_eq!(parse(&odd).map(|r| r.findings[0].metrics.len()), Some(0));
    }

    #[test]
    fn the_newest_run_from_this_pc_is_the_baseline() {
        let dir = std::env::temp_dir().join(format!("wtfis-baseline-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let at = |name: &str, unix_time: i64, machine: &str| {
            let rec = RunRecord { unix_time, machine: machine.into(), ..run(60.0, vec![]) };
            let path = dir.join(name);
            write(&path, &rec).unwrap();
            path
        };
        let now = RunRecord { unix_time: 1_800_000_000, machine: "abc123".into(), ..run(60.0, vec![]) };
        let mine = at("WTFIsStalling-now.wtfis", now.unix_time, "abc123");
        at("WTFIsStalling-old.wtfis", now.unix_time - 4 * 86_400, "abc123");
        let newest = at("WTFIsStalling-newer.wtfis", now.unix_time - 3600, "abc123");
        at("WTFIsStalling-ancient.wtfis", now.unix_time - 40 * 86_400, "abc123");
        at("WTFIsStalling-otherpc.wtfis", now.unix_time - 60, "other!");
        std::fs::write(dir.join("WTFIsStalling-report.txt"), "not a data file").unwrap();
        std::fs::write(dir.join("WTFIsStalling-broken.wtfis"), "garbage").unwrap();

        let found = find_baseline(&dir, &now, &mine).expect("a baseline");
        assert_eq!(found.0, newest, "the newest same-PC file that is not this run's own");
        assert_eq!(found.1.unix_time, now.unix_time - 3600);

        // Nothing to compare with: only this run's own file, and one from another PC.
        let empty = dir.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        assert!(find_baseline(&empty, &now, &mine).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_fix_that_worked_reads_as_better_and_names_the_numbers() {
        let before = run(
            300.0,
            vec![finding("driver rtwlane.sys", Severity::High, vec![Metric::count("stalls blamed", 14), Metric::ms("worst stall", 11.0)])],
        );
        let after = RunRecord { stalls_kernel: 0, worst_kernel_ms: 0.3, health: Health::Ok, ..run(300.0, vec![]) };
        let lines = compare(&before, &after);
        assert!(lines[0].starts_with("COMPARED WITH YOUR LAST RUN (2026-09-14 19:02, less than an hour ago)"), "{lines:?}");
        assert_eq!(lines[1], "Better: what was found last time did not show up this time.");
        assert!(lines.iter().any(|l| l == "Stalls: 2 -> 0."), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("Worst wake-up delay: 7.5 ms -> 0.30 ms")), "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("- driver rtwlane.sys") && l.contains("did not show up this time (last time: 14 stalls blamed)")),
            "{lines:?}"
        );
        assert!(!lines.iter().any(|l| l.contains("fixed")), "one short run cannot prove a fix: {lines:?}");
    }

    #[test]
    fn the_same_problem_with_a_slightly_different_number_is_not_a_change() {
        let m = |n, worst| vec![Metric::count("stalls blamed", n), Metric::ms("worst stall", worst)];
        let before = run(300.0, vec![finding("driver x.sys", Severity::High, m(10, 11.0))]);
        let after = run(300.0, vec![finding("driver x.sys", Severity::High, m(11, 10.2))]);
        let lines = compare(&before, &after);
        assert_eq!(lines[1], "No real change since last time.");
        assert!(lines.iter().any(|l| l.contains("about the same - stalls blamed 10 -> 11, worst stall 11.0 ms -> 10.2 ms")), "{lines:?}");

        // A small absolute move is noise even when the share is large: 1 stall -> 2 is not "worse".
        let before = run(300.0, vec![finding("driver x.sys", Severity::High, m(1, 5.0))]);
        let after = run(300.0, vec![finding("driver x.sys", Severity::High, m(2, 5.2))]);
        assert_eq!(compare(&before, &after)[1], "No real change since last time.");
    }

    #[test]
    fn something_new_and_something_gone_reads_as_mixed() {
        let before = run(300.0, vec![finding("driver x.sys", Severity::High, vec![Metric::count("stalls blamed", 9)])]);
        let after = run(300.0, vec![finding("disk 1", Severity::Medium, vec![Metric::count("slow requests", 4)])]);
        let lines = compare(&before, &after);
        assert_eq!(lines[1], "Mixed: some things improved and something else got worse.");
        assert!(lines.iter().any(|l| l.contains("new since last time (4 slow requests)")), "{lines:?}");

        // A worse number on its own says so.
        let before = run(300.0, vec![finding("disk 1", Severity::Medium, vec![Metric::count("slow requests", 3)])]);
        let after = run(300.0, vec![finding("disk 1", Severity::High, vec![Metric::count("slow requests", 12)])]);
        let lines = compare(&before, &after);
        assert_eq!(lines[1], "Worse than last time.");
        assert!(lines.iter().any(|l| l.contains("worse - slow requests 3 -> 12")), "{lines:?}");
    }

    #[test]
    fn informational_findings_never_decide_the_verdict() {
        let low = |key: &str, n| finding(key, Severity::Low, vec![Metric::count("stalls blamed", n)]);
        let before = run(300.0, vec![low("tool overhead", 40)]);
        let after = run(300.0, vec![low("clean marks", 1)]);
        let lines = compare(&before, &after);
        assert_eq!(lines[1], "No real change since last time.", "a Low finding coming and going is not a verdict: {lines:?}");
        assert!(lines.iter().any(|l| l.contains("- clean marks")), "but it is still listed: {lines:?}");
    }

    #[test]
    fn runs_of_different_lengths_are_compared_per_minute() {
        let before = run(600.0, vec![finding("driver x.sys", Severity::High, vec![Metric::count("stalls blamed", 60)])]);
        let after = RunRecord {
            stalls_kernel: 8,
            ..run(60.0, vec![finding("driver x.sys", Severity::High, vec![Metric::count("stalls blamed", 8)])])
        };
        let lines = compare(&before, &after);
        assert!(lines.iter().any(|l| l.contains("different lengths (10:00 then 01:00), so counts are compared per minute")), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("stalls blamed 6.0 per minute -> 8.0 per minute")), "{lines:?}");
        assert_eq!(lines[1], "Worse than last time.");

        // Same numbers per minute: the shorter run must not read as a big improvement.
        let after = run(60.0, vec![finding("driver x.sys", Severity::High, vec![Metric::count("stalls blamed", 6)])]);
        let lines = compare(&before, &after);
        assert_eq!(lines[1], "No real change since last time.", "{lines:?}");
    }

    #[test]
    fn a_short_run_and_a_change_of_mode_are_said_out_loud() {
        let before = RunRecord { light: true, ..run(40.0, vec![]) };
        let after = run(45.0, vec![]);
        let lines = compare(&before, &after);
        assert!(lines.iter().any(|l| l.starts_with("One of the two runs was shorter than a minute")), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("Last time did use light mode and this time did not")), "{lines:?}");

        let lines = compare(&run(300.0, vec![]), &RunRecord { light: true, ..run(300.0, vec![]) });
        assert!(lines.iter().any(|l| l.contains("Last time did not use light mode and this time did")), "{lines:?}");
        assert!(!lines.iter().any(|l| l.starts_with("One of the two runs")), "{lines:?}");

        let other_pc = RunRecord { machine: "zzz".into(), ..run(300.0, vec![]) };
        assert!(compare(&other_pc, &run(300.0, vec![])).iter().any(|l| l.contains("recorded on a different PC")));
    }

    /// End to end, without a capture: a run saves its numbers, the next run in the same folder
    /// finds them, and nothing here can fail the run.
    #[test]
    fn the_next_run_in_the_same_folder_picks_the_saved_numbers_up() {
        use crate::summary::{Health, Summary};

        let dir = std::env::temp_dir().join(format!("wtfis-attach-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let report = |name: &str| dir.join(name).display().to_string();

        // A first run, an hour ago, that blamed the Wi-Fi driver.
        let mut first = Summary::demo(Health::Problem);
        first.record.unix_time -= 3600;
        write(&data_path_for(&report("WTFIsStalling-1.txt")), &first.record).unwrap();

        // The second run finds nothing, and says so against the first.
        let mut second = Summary::demo(Health::Ok);
        second.comparison.clear();
        attach(&mut second, &CompareMode::Auto, Some(&report("WTFIsStalling-2.txt")));
        assert_eq!(second.comparison[1], "Better: what was found last time did not show up this time.");
        assert!(second.comparison.iter().any(|l| l.contains("rtwlane.sys")), "{:?}", second.comparison);
        let saved = read(&data_path_for(&report("WTFIsStalling-2.txt"))).expect("this run was saved too");
        assert_eq!(saved.findings.len(), 0, "an all-clear run is a baseline as well");

        // --no-compare still saves, and --compare names a file directly.
        let mut third = Summary::demo(Health::Ok);
        third.comparison.clear();
        attach(&mut third, &CompareMode::Off, Some(&report("WTFIsStalling-3.txt")));
        assert!(third.comparison.is_empty());
        assert!(read(&data_path_for(&report("WTFIsStalling-3.txt"))).is_some());
        attach(&mut third, &CompareMode::Path(data_path_for(&report("WTFIsStalling-1.txt")).display().to_string()), None);
        assert!(!third.comparison.is_empty(), "an explicitly named baseline is used even with no report file");

        // Nowhere to write and nothing to read: no comparison, no panic, no failed run.
        let mut lonely = Summary::demo(Health::Ok);
        lonely.comparison.clear();
        attach(&mut lonely, &CompareMode::Auto, Some(&report("no-such-folder\\x.txt")));
        assert!(lonely.comparison.is_empty());
        attach(&mut lonely, &CompareMode::Path("nothing.wtfis".into()), None);
        assert!(lonely.comparison.is_empty());
        attach(&mut lonely, &CompareMode::Auto, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn event_log_findings_cannot_pretend_to_answer_yet() {
        let whea = |n| finding("whea memory", Severity::Medium, vec![Metric::logged("in the last 7 days", n)]);
        let before = run(300.0, vec![whea(4)]);
        let after = run(300.0, vec![whea(4)]);
        let lines = compare(&before, &after);
        assert_eq!(lines[1], "No real change since last time.");
        assert!(lines.iter().any(|l| l.contains("looks back 7 days, so a fix cannot show here yet")), "{lines:?}");

        // Even when such a finding disappears, it must not turn the verdict green by itself.
        let lines = compare(&run(300.0, vec![whea(4)]), &run(300.0, vec![]));
        assert_eq!(lines[1], "No real change since last time.", "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("did not show up this time")), "{lines:?}");

        // What happened *while monitoring* is compared normally.
        let during = |n, total| {
            finding(
                "whea memory",
                Severity::High,
                vec![Metric::flat("errors while monitoring", n), Metric::logged("in the last 7 days", total)],
            )
        };
        let lines = compare(&run(300.0, vec![during(6, 9)]), &run(300.0, vec![during(0, 9)]));
        assert_eq!(lines[1], "Better than last time.");
        assert!(lines.iter().any(|l| l.contains("better - errors while monitoring 6 -> 0, in the last 7 days 9 -> 9")), "{lines:?}");
    }
}
