//! Before and after: every run leaves a small file of its numbers next to the report, and the
//! next run on the same PC compares itself with it. That turns "update this driver" into
//! something checkable ("stalls 14 -> 0") instead of two walls of text to diff by eye.
//!
//! This file is the record and its on-disk format; `compare.rs` next to it is what two records
//! are made to say.
//!
//! The file is a plain `key=value` text format, one line per key, numbers written with Rust's
//! own `Display` (always a `.`, never a locale comma). It is deliberately not JSON: the record
//! is a handful of scalars plus one line per finding, and a serde dependency would cost the
//! single-file exe more than the format is worth. Unknown keys are ignored, malformed or
//! foreign files are ignored quietly, and nothing here may ever fail or delay a run.

mod compare;

pub use compare::{attach, compare, Change, CompareMode};

use std::path::{Path, PathBuf};

use crate::summary::{Finding, Health, Severity};

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
///
/// Two PCs of the same model with the same RAM share an id, on purpose. Mixing in something unique
/// (the Windows MachineGuid) would make this a stable pseudonym for one PC inside a file people may
/// pass around with their report; a wrong baseline between twin PCs sharing one folder is the
/// smaller harm, and the comparison block prints the baseline's date so it can be noticed.
pub fn machine_id() -> String {
    let bios = "HARDWARE\\DESCRIPTION\\System\\BIOS";
    let get = |key: &str, value: &str| crate::reg::hklm_str(key, value).unwrap_or_default();
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
        unix_time: crate::util::unix_now(),
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
///
/// Deliberately stricter than `procs::process_name`, which does the same job for a process
/// label: this one requires a closing parenthesis with at least one digit inside, so a key that
/// happens to end in "()" or in an unclosed "(" is left alone rather than silently shortened.
pub fn stable_key(key: &str) -> String {
    match key.rsplit_once(" (") {
        Some((head, tail)) if tail.ends_with(')') && tail.len() > 1 && tail[..tail.len() - 1].bytes().all(|b| b.is_ascii_digit()) => {
            head.to_string()
        }
        _ => key.to_string(),
    }
}

#[cfg(test)]
pub(crate) mod tests {
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

    pub(crate) fn finding(key: &str, severity: Severity, metrics: Vec<Metric>) -> FindingRecord {
        FindingRecord { key: key.into(), severity, title: format!("{key}  -  something"), metrics }
    }

    pub(crate) fn run(seconds: f64, findings: Vec<FindingRecord>) -> RunRecord {
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
}
