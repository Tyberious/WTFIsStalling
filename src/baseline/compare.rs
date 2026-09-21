//! What two runs are made to say to each other: which findings are gone, new, better or worse,
//! and the block of plain sentences the report prints under the overview.
//!
//! The one thing this must never do is claim a fix that has not been shown: a number that moved
//! less than ordinary run-to-run variation reads "about the same", a short run says so, and a
//! finding read out of the Windows event log cannot answer yet at all.

use std::path::Path;

use crate::summary::{Severity, Summary};

use super::{data_path_for, find_baseline, read, write, FindingRecord, Metric, RunRecord, Scaling, Unit};

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
    // The floor is in raw units, but raw numbers from runs of different lengths cannot be set
    // side by side: 14 stalls in 5 minutes and 14 stalls in an hour are not "the same". So the
    // earlier number is first projected onto this run's length (what it would have been had
    // nothing changed), and with comparable runs that is simply the earlier number.
    let expected = if scale.1 > 0.0 { before * scale.0 / scale.1 } else { before };
    let raw_moved = (after - expected).abs() > noise_floor(unit);
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
                // The same subject can be measured by different numbers in two runs (a disk that was
                // slow last time and logged errors this time). With nothing in common to compare, the
                // rating is what is left; calling that "about the same" would hide a real change.
                let change = match moves.first() {
                    Some((c, _)) => *c,
                    None if n.severity > o.severity => Change::Worse,
                    None if n.severity < o.severity => Change::Better,
                    None => Change::Same,
                };
                let word = match change {
                    Change::Better => "better",
                    Change::Worse => "worse",
                    _ if moves.is_empty() => "still here",
                    _ => "about the same",
                };
                let numbers = if moves.is_empty() {
                    "it shows up differently this time, so there are no like-for-like numbers".to_string()
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

#[cfg(test)]
mod tests {
    use super::super::tests::{finding, run};
    use super::*;
    use crate::summary::Health;

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

    /// Found in the demo report: 14 stalls in 5 minutes, then 14 in an hour, read "about the same".
    #[test]
    fn the_same_count_over_a_much_longer_run_is_an_improvement() {
        let per_min = |secs: f64| 60.0 / secs;
        assert_eq!(classify(14.0, 14.0, Unit::Count, (per_min(300.0), per_min(3540.0))), Change::Better);
        assert_eq!(classify(14.0, 14.0, Unit::Count, (per_min(3540.0), per_min(300.0))), Change::Worse);
        // One stall in an hour, then one in five minutes, is one stall: not evidence of anything.
        assert_eq!(classify(1.0, 1.0, Unit::Count, (per_min(3600.0), per_min(300.0))), Change::Same);
        assert_eq!(classify(14.0, 14.0, Unit::Count, (1.0, 1.0)), Change::Same);
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

        // Same numbers per minute: the shorter run must not read as a big improvement. (The run's
        // own stall count has to be in proportion too: the same count in a tenth of the time is worse.)
        let before = RunRecord { stalls_kernel: before.stalls_kernel * 10, ..before };
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
