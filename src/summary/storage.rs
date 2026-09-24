//! Disks and memory: slow requests and why they were slow, which files did the waiting, what
//! Windows logged about storage, and what each drive reports about its own health.

use std::collections::HashMap;

use crate::disks::{fmt_size, DiskInfo};
use crate::diskstuck::{top_counts, DiskBehind, Kind, STACK_KEYS_CAP};
use crate::diskwhy::{Cause, DiskWhy};
use crate::evlog;
use crate::files;
use crate::health::{self, DriveHealth};
use crate::procs::process_name;
use crate::procs::{known_worker, windows_part};
use crate::stacks;
use crate::state::LatStat;
use crate::storport::split::{self as storsplit, SplitTotals};
use crate::storport::{AddrTotals, ResetRec, StorageReport};
use crate::util::{fmt_dur, ms_to_ticks, plural, ticks_to_ms};

use super::ctx::{when_text, Ctx};
use super::{Metric, Severity};

const CONTROLLER_RESET_ADVICE: &str = "Every program waits, often for many seconds, while Windows resets a drive. Usual causes: a \
    loose or bad SATA/M.2 connection, drive firmware, or link power saving. Reseat or replace cables, update SSD firmware and the \
    chipset/storage driver, and set Power Options > PCI Express > Link State Power Management to Off. Event Viewer > Windows Logs > \
    System (event 129) shows which controller.";

/// One row of "which files waited on disk": (path already made public-safe, disk, requests,
/// total wait, worst wait).
pub(super) type FileRow = (String, u32, u64, i64, i64);

/// One program's share of the waiting on one file, all its processes together: (image name, how
/// many processes of it, requests, total wait). See `Ctx::file_programs`.
pub(super) type ProgramRow = (String, u32, u64, i64);

/// The programs behind one file's waiting, for DETAILS: "powershell.exe 2 copies, 53 s; Windows
/// itself (System) 1.20 s". Image names only, and Windows' own parts marked (`shown`), because
/// "System" issuing a request is the file cache writing on everyone's behalf, not a program.
pub(super) fn programs_text(rows: &[ProgramRow], max: usize) -> Option<String> {
    let parts: Vec<String> = rows
        .iter()
        .take(max)
        .map(|(name, copies, _, total)| {
            let copies = if *copies > 1 { format!(" {copies} copies") } else { String::new() };
            format!("{}{copies}, {}", shown(name), fmt_dur(*total))
        })
        .collect();
    (!parts.is_empty()).then(|| parts.join("; "))
}

/// "issued by powershell.exe (2 copies)", for the sentence in a disk's finding: the one or two
/// programs that did most of that file's waiting.
fn issued_by(rows: &[ProgramRow]) -> Option<String> {
    let names: Vec<String> = rows
        .iter()
        .take(2)
        .map(|(name, copies, ..)| if *copies > 1 { format!("{} ({copies} copies)", shown(name)) } else { shown(name) })
        .collect();
    (!names.is_empty()).then(|| format!("issued by {}", and_list(&names)))
}

/// What the files that waited on one disk change about the advice. Which file waited says
/// something no latency number can: the paging file means memory, game data means the game.
#[derive(Default, Clone, Copy)]
struct FileHint {
    paging: bool,
    game: bool,
}

fn file_hint(rows: &[FileRow]) -> FileHint {
    FileHint { paging: rows.iter().any(|r| files::is_paging_file(&r.0)), game: rows.iter().any(|r| files::is_game_asset(&r.0)) }
}

/// "Most of the waiting was for ...", naming the files that waited longest on one disk and, where
/// the trace says, which program issued the requests.
fn files_sentence(rows: &[FileRow], programs: &HashMap<(String, u32), Vec<ProgramRow>>) -> Option<String> {
    let top = files::rank(rows, 3);
    if top.is_empty() {
        return None;
    }
    let list: Vec<String> = top
        .iter()
        .map(|(name, disk, count, total, _)| {
            let by = programs.get(&(name.clone(), *disk)).and_then(|p| issued_by(p)).map(|b| format!(", {b}")).unwrap_or_default();
            format!("{name} ({count} request{}, {}{by})", plural(*count), fmt_dur(*total))
        })
        .collect();
    let mut sentence = format!("Most of the waiting was for: {}.", list.join(", "));
    // Name what the worst one actually is; almost nobody knows what $Mft or pagefile.sys are.
    if let Some(what) = files::explain(&top[0].0) {
        sentence.push_str(&format!(" {} is {what}.", top[0].0));
    }
    Some(sentence)
}

/// What to try for a slow disk, based on why it seemed slow, what kind of disk it is, and which
/// files did the waiting.
fn disk_advice(disk: &DiskInfo, why: Option<&DiskWhy>, logged_errors: bool, hint: FileHint) -> String {
    let mut advice = String::from("Anything that touches this disk freezes while it answers. ");
    let main = if logged_errors { None } else { why.and_then(|w| w.main_cause()) };
    match main {
        Some(Cause::Busy) => {
            let who = why.and_then(|w| w.top_movers(1).into_iter().next()).map(|m| m.0);
            advice.push_str("It was slow because it was busy, so deal with the traffic first. ");
            match (&who, who.as_deref().and_then(known_worker)) {
                // Part of Windows: there is nothing to close or pause, only a setting or patience.
                (Some(who), Some(w)) if w.windows => {
                    advice.push_str(&format!("{who} is part of Windows ({}), not something you can close. {} ", w.what, w.tip))
                }
                (Some(who), Some(w)) => advice.push_str(&format!("{who}: {} ", w.tip)),
                (Some(who), None) => {
                    advice.push_str(&format!("Let {who} finish, pause it, or schedule it for when you are not using the PC. "))
                }
                (None, _) => {}
            }
            advice.push_str("Keeping heavy disk work and your game on different drives also fixes it. ");
        }
        Some(Cause::WokeUp) => advice.push_str(
            "It had gone to sleep and needed time to wake up. Stop it from sleeping: Control Panel > Power Options > Change plan \
             settings > Advanced > Hard disk > 'Turn off hard disk after' = 0 (never), and for a USB drive also set 'USB selective \
             suspend' to Disabled there. Or keep files you use while gaming off this drive. ",
        ),
        Some(Cause::Flush) => advice.push_str(
            "A program kept forcing its writes out to the drive, which budget SSDs without their own memory handle badly. See which \
             program issued the slow flushes in the event log below. ",
        ),
        _ => {}
    }
    // Which file waited can change the answer completely, so it goes before the generic checks.
    if hint.paging {
        advice.push_str(
            "Most of the waiting was for Windows' paging file, which means the PC ran out of memory and had to read programs back \
             off this disk. Close memory-hungry programs (a browser with many tabs is the usual one) or add RAM; that helps more \
             than anything you can do to the drive. ",
        );
        if disk.spinning == Some(true) {
            advice.push_str(
                "The paging file is on a hard drive, the slowest place it can be: if this PC has an SSD, put the paging file there \
                 (search Windows for 'Adjust the appearance and performance of Windows' > Advanced > Virtual memory > Change). ",
            );
        }
    }
    if hint.game && disk.spinning == Some(true) {
        advice.push_str(
            "A game's own data files were waiting on a hard drive. Games stream textures and levels while you play, and a hard \
             drive cannot keep up: move that game to an SSD (in Steam: right-click the game > Properties > Installed Files > Move \
             install folder). ",
        );
    }
    let full = disk.nearly_full();
    if !full.is_empty() {
        let letters: Vec<String> = full.iter().map(|l| format!("{l}:")).collect();
        let (list, verb) = match letters.split_last() {
            Some((last, rest)) if !rest.is_empty() => (format!("{} and {last}", rest.join(", ")), "are"),
            _ => (letters.join(""), "is"),
        };
        advice.push_str(&format!("{list} {verb} nearly full, which by itself makes drives slow: free up space. "));
    }
    if logged_errors {
        advice.push_str(
            "Windows logged errors for this drive, which is not normal: back up what matters now. Then reseat or replace its cable \
             (or move an M.2 drive to another slot), update its firmware, and check its health (SMART) with the maker's tool or \
             CrystalDiskInfo.",
        );
    } else if matches!(main, Some(Cause::Busy | Cause::WokeUp)) {
        advice.push_str("If it stays slow without that, check its health (SMART) with the maker's tool or CrystalDiskInfo.");
    } else {
        advice.push_str("Check its health (SMART) with the maker's tool or CrystalDiskInfo");
        advice.push_str(match (disk.bus, disk.spinning) {
            ("USB", _) => ", and try another USB port or cable, plugged straight into the PC rather than a hub.",
            (_, Some(true)) => {
                ". A hard drive that takes this long with little to do is often failing: back up what matters, reseat or replace its \
                 cable, and move games and programs to an SSD."
            }
            ("NVMe", _) => ", update its firmware, and make sure it isn't overheating (a heatsink helps).",
            ("SATA" | "ATA", _) => ", update its firmware, and reseat or replace its SATA cable.",
            _ => ", update SSD firmware, and reseat or replace the cable on SATA drives.",
        });
    }
    if disk.model.is_empty() && disk.volumes.is_empty() {
        advice.push_str(&format!(" Disk {} is the number shown in Windows Disk Management.", disk.number));
    }
    advice
}

/// The one file a process did most of its paging waiting on, with its share, when a single file
/// really does dominate. Below half it is a mix and naming one file would mislead.
fn dominant_file(per_file: &[(String, u64, i64)]) -> Option<(String, f64)> {
    let total: i64 = per_file.iter().map(|f| f.2).sum();
    if total <= 0 {
        return None;
    }
    let mut by_name: HashMap<&str, i64> = HashMap::new();
    for (name, _, wait) in per_file {
        *by_name.entry(name.as_str()).or_default() += wait;
    }
    // Ties resolve by name so two runs on the same data say the same thing.
    let (name, best) = by_name.into_iter().max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(a.0)))?;
    let share = best as f64 / total as f64;
    (share >= 0.5).then(|| (name.to_string(), share))
}

/// One sentence per reason the disk's slow requests were slow, most common first.
fn why_sentences(why: &DiskWhy, spinning: bool) -> Vec<String> {
    let mut causes = [Cause::Busy, Cause::WokeUp, Cause::IdleSlow, Cause::Flush].map(|c| (c, why.count(c)));
    causes.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    let of = |n: u32| if n == why.total() { "every time".to_string() } else { format!("{n} of {} times", why.total()) };
    let mut out = Vec::new();
    for (cause, n) in causes.into_iter().filter(|(_, n)| *n > 0) {
        out.push(match cause {
            Cause::Busy => {
                let movers: Vec<String> = why
                    .top_movers(2)
                    .into_iter()
                    .filter(|m| m.2 >= 0.15)
                    .map(|(name, bytes, share)| {
                        let what = known_worker(&name).map_or(String::new(), |w| format!(": {}", w.what));
                        format!("{name} ({}, {:.0}% of the traffic{what})", fmt_size(bytes), share * 100.0)
                    })
                    .collect();
                let who = if movers.is_empty() { String::new() } else { format!(" The traffic came from {}.", movers.join(" and ")) };
                // On a hard drive "busy" is usually many requests rather than much data: each
                // one moves the head.
                let what = if spinning {
                    "busy: other requests kept it seeking back and forth, which for a hard drive costs as much as moving a lot of data"
                } else {
                    "busy moving a lot of data"
                };
                format!("Why: the disk was {what} ({}).{who}", of(n))
            }
            Cause::WokeUp => format!(
                "Why: the drive had gone to sleep ({}). The slow request was the first after up to {:.0} s of silence.",
                of(n),
                why.longest_sleep_ms / 1000.0
            ),
            Cause::IdleSlow => format!(
                "Why: not traffic. The disk had little else to do and still took that long ({}), which points at the drive itself, \
                 its cable or its firmware.",
                of(n)
            ),
            Cause::Flush => format!("Why: a program forced its writes out to the drive and the drive took its time ({}).", of(n)),
        });
    }
    out
}

const DRIVE_FAILING_ADVICE: &str = "The drive itself reports damage. Back up everything on it now, before doing anything else, then \
    replace it; drives in this state fail without further warning, and every retry on a bad spot is a freeze.";

const DRIVE_HOT_ADVICE: &str = "The drive is hot enough to slow itself down, which shows up as hitches during loading and saving. Fit \
    an M.2 heatsink (many motherboards ship one that is easy to leave off), improve case airflow, and if it sits directly under the \
    graphics card consider another M.2 slot.";

const DRIVE_CABLE_ADVICE: &str = "CRC errors mean data was damaged between the drive and the motherboard, not on the drive: replace \
    the SATA cable (they do go bad), make sure both ends click in, and try another SATA port.";

/// What a drive's own health data says, as (severity, sentence, what to try).
fn health_findings(spinning: bool, start: Option<&DriveHealth>, end: &DriveHealth) -> Vec<(Severity, String, &'static str)> {
    let mut out = Vec::new();
    if let Some(n) = &end.nvme {
        let before = start.and_then(|s| s.nvme.as_ref());
        let problems: Vec<&str> = [
            (1, "its spare capacity is running out"),
            (2, "it is over (or under) its temperature limit"),
            (4, "its reliability is degraded by media errors"),
            (8, "it has switched to read-only mode"),
            (16, "its power-loss protection has failed"),
        ]
        .iter()
        .filter(|(bit, _)| n.critical_warning & bit != 0)
        .map(|(_, text)| *text)
        .collect();
        if !problems.is_empty() {
            let advice = if n.critical_warning & !2 != 0 { DRIVE_FAILING_ADVICE } else { DRIVE_HOT_ADVICE };
            out.push((
                Severity::High,
                format!("Drive health: the drive has raised its own critical warning: {}.", problems.join("; ")),
                advice,
            ));
        }
        if n.media_errors > 0 {
            out.push((
                Severity::Medium,
                format!("Drive health: {} unrecoverable media error(s) recorded over its life.", n.media_errors),
                DRIVE_FAILING_ADVICE,
            ));
        }
        if n.percent_used >= 100 {
            out.push((
                Severity::Medium,
                format!("Drive health: it has used {}% of its rated write endurance, so it is past its designed life.", n.percent_used),
                DRIVE_FAILING_ADVICE,
            ));
        }
        let throttled = before.map_or(0, |b| n.throttle_seconds.saturating_sub(b.throttle_seconds));
        let over_temp = before.map_or(0, |b| n.warning_temp_minutes.saturating_sub(b.warning_temp_minutes));
        if throttled > 0 || over_temp > 0 {
            let what = if throttled > 0 {
                format!("spent {throttled} s slowed down by heat")
            } else {
                "was over its warning temperature".to_string()
            };
            out.push((Severity::High, format!("Drive health: it {what} while monitoring (now {} °C).", n.temperature_c), DRIVE_HOT_ADVICE));
        } else if n.temperature_c >= 70 {
            out.push((
                Severity::Medium,
                format!("Drive health: it is at {} °C. NVMe drives slow themselves down from roughly 70-80 °C.", n.temperature_c),
                DRIVE_HOT_ADVICE,
            ));
        } else if n.warning_temp_minutes > 0 || n.throttle_seconds >= 600 {
            out.push((
                Severity::Low,
                format!(
                    "Drive health: over its life it has spent {} min above its warning temperature and {} min slowed down by heat (now {} °C).",
                    n.warning_temp_minutes,
                    n.throttle_seconds / 60,
                    n.temperature_c
                ),
                DRIVE_HOT_ADVICE,
            ));
        }
    }
    if let Some(sata) = &end.sata {
        let before = start.and_then(|s| s.sata.as_ref());
        let damaged: Vec<String> =
            [(sata.reallocated, "reallocated"), (sata.pending, "pending (unreadable)"), (sata.uncorrectable, "uncorrectable")]
                .iter()
                .filter_map(|(v, name)| v.filter(|v| *v > 0).map(|v| format!("{v} {name}")))
                .collect();
        if !damaged.is_empty() {
            let total: u64 = [sata.reallocated, sata.pending, sata.uncorrectable].iter().flatten().sum();
            let sev = if total >= 50 || sata.pending.unwrap_or(0) > 0 { Severity::High } else { Severity::Medium };
            out.push((sev, format!("Drive health (SMART): bad sectors: {}.", damaged.join(", ")), DRIVE_FAILING_ADVICE));
        }
        if let Some(crc) = sata.crc_errors.filter(|c| *c > 0) {
            let new = before.and_then(|b| b.crc_errors).map_or(0, |b| crc.saturating_sub(b));
            if new > 0 {
                out.push((
                    Severity::High,
                    format!("Drive health (SMART): {new} new CRC error(s) while monitoring ({crc} in total)."),
                    DRIVE_CABLE_ADVICE,
                ));
            } else {
                out.push((
                    Severity::Low,
                    format!("Drive health (SMART): {crc} CRC error(s) over its life; none while monitoring. Only a problem if the number keeps rising."),
                    DRIVE_CABLE_ADVICE,
                ));
            }
        }
    }
    if end.nvme.is_none() {
        let limit = if spinning { 55 } else { 70 };
        if let Some(t) = end.temperature().filter(|t| *t >= limit) {
            out.push((Severity::Medium, format!("Drive health: it is at {t} °C, which is hot for this kind of drive."), DRIVE_HOT_ADVICE));
        }
    }
    out
}

/// "56 °C  |  1% of rated life used  |  spare 100%  |  0 media errors  |  16169 h powered on"
fn health_line(h: &DriveHealth) -> String {
    let mut parts = Vec::new();
    if let Some(t) = h.temperature() {
        parts.push(format!("{t} °C"));
    }
    if let Some(n) = &h.nvme {
        parts.push(format!("{}% of rated life used", n.percent_used));
        // Spare 0% with a threshold of 0% and no "spare low" warning bit is a drive (or a USB
        // bridge in front of it) that does not fill the field in, not a drive out of spare blocks.
        if n.spare_percent > 0 || n.spare_threshold > 0 || n.critical_warning & 1 != 0 {
            parts.push(format!("spare {}%", n.spare_percent));
        } else {
            parts.push("spare not reported".to_string());
        }
        parts.push(format!("{} media errors", n.media_errors));
        parts.push(format!("{} min over temperature", n.warning_temp_minutes + n.critical_temp_minutes));
        parts.push(format!("{} h powered on", n.power_on_hours));
    }
    if let Some(s) = &h.sata {
        let show = |v: Option<u64>| v.map_or("n/a".to_string(), |v| v.to_string());
        parts.push(format!("reallocated {}", show(s.reallocated)));
        parts.push(format!("pending {}", show(s.pending)));
        parts.push(format!("uncorrectable {}", show(s.uncorrectable)));
        parts.push(format!("CRC errors {}", show(s.crc_errors)));
    }
    parts.join("  |  ")
}

/// How much a program's waiting for paged-out memory matters.
///
/// A total inflates with the run: 6.7 s of waiting spread over 59 minutes is 0.2% of the time and
/// nobody feels it, while the same 6.7 s inside five minutes is a program that visibly stutters.
/// So judge by the share of the run - 2% is where a program stops feeling smooth, half a percent
/// is where it shows during loading - plus the single worst wait, because a fifth of a second in
/// one go is felt however rarely it happens.
fn paging_severity(total: i64, max: i64, run_s: f64) -> Severity {
    let share = ticks_to_ms(total) / (run_s.max(1.0) * 1000.0);
    if share >= 0.02 {
        Severity::High
    } else if share >= 0.005 || max >= ms_to_ticks(200.0) {
        Severity::Medium
    } else {
        Severity::Low
    }
}

/// Programs frozen while memory was read back from disk.
pub(super) fn paging(cx: &mut Ctx) {
    let faults = std::mem::take(&mut cx.faults);
    let fault_files = std::mem::take(&mut cx.fault_files);
    let mut faults_named: HashMap<String, LatStat> = HashMap::new();
    for (pid, st) in faults {
        // Per program, not per process: see `stalls::tally`.
        let e = faults_named.entry(process_name(&cx.az.procs.label(pid, 0))).or_default();
        e.count += st.count;
        e.total += st.total;
        e.max = e.max.max(st.max);
    }
    let mut faults_named: Vec<_> = faults_named.into_iter().collect();
    faults_named.sort_by_key(|(_, s)| std::cmp::Reverse(s.total));
    let mem = crate::util::memory_load();
    for (name, s) in &faults_named {
        if s.total < ms_to_ticks(1000.0) && s.max < ms_to_ticks(200.0) {
            continue;
        }
        let share = ticks_to_ms(s.total) / (cx.run.elapsed_s.max(1.0) * 1000.0);
        let sev = paging_severity(s.total, s.max, cx.run.elapsed_s);
        let advice = if mem >= crate::util::MEMORY_TIGHT_PCT {
            format!(
                "Memory is {mem}% full, so Windows keeps pushing programs out to disk. Close memory-hungry programs \
                 (browsers with many tabs are the usual one) or add RAM."
            )
        } else {
            format!(
                "Memory is only {mem}% full, so this is more likely the program starting up or loading data than a RAM \
                 shortage. It matters only if this is the program that hitches; if so, move it to a faster drive (SSD)."
            )
        };
        let key = format!("paging {name}");
        // Which file the memory came back from turns a number into something to act on.
        let mostly = match fault_files.get(name).and_then(|f| dominant_file(f)) {
            Some((file, share)) => {
                let what = files::explain(&file).map(|w| format!(" That is {w}.")).unwrap_or_default();
                format!(" Mostly reading back {file} ({:.0}% of the waiting).{what}", share * 100.0)
            }
            None => String::new(),
        };
        cx.found.add(
            &key,
            sev,
            format!("{name}  -  waiting for memory to be read back from disk"),
            format!(
                "Frozen by {} hard page faults for {} in total, which is {:.1}% of this run (longest single wait {}).{mostly}",
                s.count,
                fmt_dur(s.total),
                share * 100.0,
                fmt_dur(s.max)
            ),
            advice,
            s.total,
        );
        cx.found.measure(&key, Metric::secs("frozen waiting for memory", ticks_to_ms(s.total) / 1000.0));
        cx.found.measure(&key, Metric::ms("longest wait", ticks_to_ms(s.max)));
    }
    cx.faults_named = faults_named;
    cx.fault_files = fault_files;
    cx.mem = mem;
}

/// How many of a disk's slow requests were the disk's own doing, and how bad the worst of those
/// was. A request that began only after the whole machine had already stopped waited because
/// everything waited; counting it against its drive turns one problem into two (see `diskwait`).
/// Falls back to the raw totals unless every slow request on that disk was actually seen.
fn discount_victims(seen: Option<&Vec<crate::analyze::SlowSeen>>, slow: u64, max: i64) -> (u64, i64) {
    let Some(seen) = seen.filter(|v| v.len() as u64 == slow) else { return (slow, max) };
    let kept: Vec<i64> = seen.iter().filter(|s| !s.victim).map(|s| s.dur).collect();
    (kept.len() as u64, kept.into_iter().max().unwrap_or(0))
}

/// Disks that took too long to answer.
pub(super) fn slow_disks(cx: &mut Ctx) {
    let io_warn = cx.run.io_warn;
    let run_s = cx.run.elapsed_s.max(1.0);
    let disks = cx.disk_stats.clone();
    // Read from the registry once, and only if some disk has call stacks to talk about.
    let mut filters: Option<HashMap<String, String>> = None;
    for (n, s) in &disks {
        if s.slow == 0 {
            continue;
        }
        let (slow, worst) = discount_victims(cx.az.disk_slow.get(n), s.slow, s.max);
        if slow == 0 {
            // Every one of them is explained by a whole-PC freeze; the freeze finding says so.
            continue;
        }
        let (storage_log, file_waits) = (&cx.storage_log, &cx.file_waits);
        // A one-second wait is felt by anything that touches the drive, whenever it happens; below
        // that, what matters is how often. One every five minutes is a drive to look at.
        let per_hour = slow as f64 * 3600.0 / run_s;
        let sev = if worst >= ms_to_ticks(1000.0) || per_hour >= 12.0 { Severity::High } else { Severity::Medium };
        let disk = cx.az.disks.get(*n).clone();
        let victims = s.slow - slow;
        let discounted = if victims > 0 {
            format!(
                " {victims} more were slowed down by a whole-PC freeze: they began after the PC had already stopped, so they are                  not counted against this drive."
            )
        } else {
            String::new()
        };
        let mut evidence =
            format!("{slow} request{} took longer than {} (worst {}).{discounted}", plural(slow), fmt_dur(io_warn), fmt_dur(worst));
        for extra in [disk.hardware(), disk.fullness()] {
            if !extra.is_empty() {
                evidence.push_str(&format!(" {}{}.", extra[..1].to_uppercase(), &extra[1..]));
            }
        }
        let key = format!("disk {n}");
        let why = cx.az.disk_why.get(n);
        let busy = why.is_some_and(|w| w.main_cause() == Some(Cause::Busy));
        let logged = storage_log.iter().any(|e| e.disk == Some(*n));
        let on_disk: Vec<FileRow> = file_waits.iter().filter(|r| r.1 == *n).cloned().collect();
        let advice = disk_advice(&disk, why, logged, file_hint(&files::rank(&on_disk, 3)));
        cx.found.add(&key, sev, format!("{}  -  responding slowly", disk.title()), evidence, advice, worst * slow as i64);
        cx.found.measure(&key, Metric::count("slow requests", slow as f64));
        cx.found.measure(&key, Metric::ms("worst wait", ticks_to_ms(worst)));
        for sentence in why.map(|w| why_sentences(w, disk.spinning == Some(true))).unwrap_or_default() {
            cx.found.note(&key, sentence);
        }
        if let Some(sentence) = files_sentence(&on_disk, &cx.file_programs) {
            cx.found.note(&key, sentence);
        }
        if let Some(sentence) = freeze_sentence(&cx.az.incidents, *n) {
            cx.found.note(&key, sentence);
        }
        if let Some(behind) = cx.az.disk_behind.get(n).cloned() {
            for sentence in behind_sentences(&behind, cx.scheduler_usable()) {
                cx.found.note(&key, sentence);
            }
            for advice in behind_advice(&behind, disk.spinning == Some(true)) {
                cx.found.advise(&key, &advice);
            }
            // What the call stacks said: which drivers the slow requests went through, and where
            // the threads stuck behind them were blocked.
            if behind.stack_found + behind.stack_missing + behind.wait_stacks > 0 {
                let filters = filters.get_or_insert_with(stacks::filesystem_filters);
                let names = StackNames::of(&behind, filters, &mut cx.az.modules);
                for sentence in stack_sentences(&behind, filters, &names) {
                    cx.found.note(&key, sentence);
                }
                for advice in stack_advice(&behind, filters, &names) {
                    cx.found.advise(&key, &advice);
                }
                let lines = stack_lines(&disk.short(), &behind);
                cx.stack_lines.extend(lines);
            }
        }
        // Where the slow time went, inside the drive or in Windows, from the storage port driver.
        if cx.run.storage_trace.available {
            let split = cx.az.disk_split.get(n).copied().unwrap_or_default();
            let addr = cx.az.scsi_addr(*n);
            let sentence = match storsplit::finding_sentence(&split, busy) {
                Some(s) => Some(s),
                None if cx.run.storage_trace.on_storport(addr, split.matched(), split.unmatched) == Some(false) => {
                    Some(storsplit::NOT_MEASURED.to_string())
                }
                None => None,
            };
            if let Some(s) = sentence {
                cx.found.note(&key, s);
            }
        }
    }
}

/// The whole-PC freezes that coincided with a slow request to disk `n`, said on the DISK's own
/// finding too (issue #19), in the same correlation language as the freeze finding. Only requests
/// that were already outstanding, or that merely overlapped: one that began after the PC had
/// already stopped was slowed down BY the freeze (`diskwait::Role::Victim`), is not held against
/// the drive, and is accounted for in the evidence line about discounted requests instead.
fn freeze_sentence(incidents: &[crate::analyze::IncidentSummary], n: u32) -> Option<String> {
    let mut count = 0usize;
    let (mut waited, mut woke) = (0i64, false);
    for c in incidents
        .iter()
        .filter(|i| !i.marked && i.class == crate::analyze::IncidentClass::Freeze)
        .filter_map(|i| i.freeze.as_ref()?.coincided.as_ref())
        .filter(|c| c.disk == Some(n) && c.role != crate::diskwait::Role::Victim)
    {
        count += 1;
        waited = waited.max(c.waited);
        woke |= c.woke;
    }
    if count == 0 {
        return None;
    }
    let asleep = if woke { ", after it had been asleep" } else { "" };
    Some(format!(
        "The whole PC froze {count} time{} while a slow request to this drive was outstanding{asleep} (taking up to {}).          'Coincided' is all this says: this tool cannot tell which caused which. See the whole-PC freeze finding.",
        plural(count as u64),
        fmt_dur(waited)
    ))
}

/// Resets past this many are counted rather than each given a time.
const RESET_TIMES_SHOWN: usize = 3;

/// What the storage port driver saw one drive go through while monitoring: requests it had to
/// retry, reads and writes that came back failed, and resets. `None` when there was none of it.
fn live_sentence(t: AddrTotals, resets: &[ResetRec], time: &dyn Fn(i64) -> String) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    if t.retried > 0 {
        parts.push(format!(
            "Windows had to retry {} request{} to it ({} retr{} in all)",
            t.retried,
            plural(t.retried),
            t.retries,
            if t.retries == 1 { "y" } else { "ies" }
        ));
    }
    if t.failed > 0 {
        parts.push(format!("{} read{} or write{} came back failed", t.failed, plural(t.failed), plural(t.failed)));
    }
    if !resets.is_empty() {
        let mut at: Vec<String> = resets.iter().take(RESET_TIMES_SHOWN).map(|r| time(r.ts)).collect();
        if resets.len() > RESET_TIMES_SHOWN {
            at.push(format!("{} more", resets.len() - RESET_TIMES_SHOWN));
        }
        parts.push(format!(
            "Windows reset the drive {} time{} (at {}), and every request to it waits while that happens",
            resets.len(),
            plural(resets.len() as u64),
            and_list(&at)
        ));
    }
    (!parts.is_empty()).then(|| format!("Seen live by Windows' storage driver while monitoring: {}.", parts.join("; ")))
}

const RETRY_ADVICE: &str = "A drive that needs requests sent again did not answer correctly the first time, which is an early \
    warning sign. Check its health (SMART) with the maker's tool or CrystalDiskInfo, reseat or replace its cable (or move an M.2 \
    drive to another slot), and update its firmware.";

/// Retries, failed requests and resets the storage port driver's trace saw live, per drive
/// (`storport`). Runs after `event_log`: a reset Windows also logged as event 129 is added to the
/// finding that event already made instead of becoming a second one.
///
/// Severity: a reset while monitoring raises the drive to High, the same rule `event_log` applies
/// to an event 129 during the run, because every program touching the drive waits through it.
/// Retries and failed requests change nothing on a drive that is already a finding; on their own
/// they are a Low lead (a warning sign, not a proven cause of anything felt).
pub(super) fn seen_live(cx: &mut Ctx) {
    let report = &cx.run.storage_trace;
    if !report.available {
        return;
    }
    let (resets_all, per_addr) = (report.resets.clone(), report.per_addr.clone());
    // Event 129 names a controller, not a disk (see `evlog`), so a 129 logged during the run is
    // taken as the same reset rather than as a second, separate problem.
    let logged_129 = cx.storage_log.iter().any(|e| e.id == 129 && e.unix_time >= cx.run_start_unix);
    for n in cx.az.disks.present() {
        let Some(addr) = cx.az.scsi_addr(n) else { continue };
        let totals = per_addr.iter().find(|(a, _)| *a == addr).map(|(_, t)| *t).unwrap_or_default();
        let mut resets: Vec<ResetRec> = resets_all.iter().filter(|r| r.hits(addr)).copied().collect();
        resets.sort_by_key(|r| r.ts);
        let Some(mut text) = live_sentence(totals, &resets, &|ts| crate::util::clock().fmt(ts)) else { continue };
        if !resets.is_empty() && logged_129 {
            text.push_str(" Windows also logged a reset in its event log while monitoring (event 129).");
        }
        let key = format!("disk {n}");
        let disk = cx.az.disks.get(n).clone();
        if cx.found.note(&key, text.clone()) {
            if !resets.is_empty() {
                cx.found.raise(&key, Severity::High);
                cx.found.advise(&key, CONTROLLER_RESET_ADVICE);
            }
        } else if !resets.is_empty() {
            // Windows logged the same reset as event 129 against the controller: one finding.
            if cx.found.note("storage controller", format!("{}: {text}", disk.title())) {
                cx.found.raise("storage controller", Severity::High);
            } else {
                let title = format!("{}  -  Windows reset the drive while monitoring", disk.title());
                cx.found.add(&key, Severity::High, title, text, CONTROLLER_RESET_ADVICE.to_string(), 0);
            }
        } else if totals.retried > 0 {
            cx.found.add(
                &key,
                Severity::Low,
                format!("{}  -  Windows had to retry requests to it", disk.title()),
                text,
                RETRY_ADVICE.into(),
                0,
            );
        }
        if !resets.is_empty() {
            cx.found.measure(&key, Metric::flat("resets seen live", resets.len() as u32));
        }
    }
}

/// Disks the storage port driver never reported on, for DETAILS: "not measured", never "zero".
pub(super) fn not_on_storport(az: &mut crate::analyze::Analyzer, report: &StorageReport, disks: &[u32]) -> Vec<u32> {
    if !report.available {
        return Vec::new();
    }
    let mut out = Vec::new();
    for n in disks {
        let split: SplitTotals = az.disk_split.get(n).copied().unwrap_or_default();
        let addr = az.scsi_addr(*n);
        if report.on_storport(addr, split.matched(), split.unmatched) == Some(false) {
            out.push(*n);
        }
    }
    out
}

/// A process as the disk finding names it: parts of Windows marked as such, so that nothing
/// reads as "this program is the problem, close it".
pub(super) fn shown(name: &str) -> String {
    if name.starts_with("System") {
        "Windows itself (System)".to_string()
    } else if windows_part(name) {
        format!("{name} (part of Windows)")
    } else {
        name.to_string()
    }
}

fn and_list(items: &[String]) -> String {
    match items.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} and {last}", rest.join(", ")),
        _ => items.join(""),
    }
}

/// Evidence about what a disk's slow requests were and who was stuck behind them (issue #20).
/// `sched` is whether anything may be read from the thread-switch trace at all
/// (`Ctx::scheduler_usable`); without it only what the requests themselves carry is said.
fn behind_sentences(b: &DiskBehind, sched: bool) -> Vec<String> {
    let mut out = Vec::new();
    let paging = b.count(Kind::is_paging);
    let mut parts: Vec<String> = Vec::new();
    if paging > 0 {
        let mut detail: Vec<String> = Vec::new();
        let from_pagefile = b.count(|k| k == Kind::PagingFile);
        let code = b.count(|k| k == Kind::ProgramCode);
        if from_pagefile > 0 {
            detail.push(format!("{from_pagefile} to or from the paging file"));
        }
        if code > 0 {
            detail.push(format!("{code} loading program code"));
        }
        let detail = if detail.is_empty() { String::new() } else { format!(": {}", detail.join(", ")) };
        parts.push(format!("{paging} paging (Windows moving program code or memory between RAM and the drive{detail})"));
    }
    for (kind, what) in [
        (Kind::PagedFile, "through the file cache (Windows fetching a file for a program, or writing its changes out)"),
        (Kind::Bookkeeping, "file-system bookkeeping ($Mft and the like)"),
        (Kind::FileData, "a file's contents"),
    ] {
        let n = b.count(|k| k == kind);
        if n > 0 {
            parts.push(format!("{n} {what}"));
        }
    }
    let flushes = b.count(|k| k == Kind::Flush);
    if flushes > 0 {
        parts.push(format!("{flushes} flush{}", if flushes == 1 { "" } else { "es" }));
    }
    if !parts.is_empty() {
        out.push(format!("What the slow requests were: {}.", parts.join(", ")));
    }
    if sched {
        let top = b.top_stuck(3);
        if !top.is_empty() {
            // The program the person was looking at comes first and is called that, however much
            // longer something in the background waited (`DiskBehind::top_stuck`).
            let list: Vec<String> = top
                .iter()
                .map(|(name, times, total, front)| {
                    let was = if *front > 0 { format!(" ({}, at {front} of them)", crate::foreground::role(name)) } else { String::new() };
                    format!("{}{was}: behind {times}, {} in total", shown(name), fmt_dur(*total))
                })
                .collect();
            out.push(format!("Stuck behind them (waiting until they completed): {}.", list.join("; ")));
        } else if b.checked > 0 {
            out.push(format!("No program was seen stopped waiting for any of the {} that could be checked.", b.checked));
        }
        for (waiter, holder, times, longest) in b.top_chains(2) {
            out.push(format!(
                "{} waited up to {} on a lock held by {}, which was itself waiting on this drive ({} time{}).",
                shown(&waiter),
                fmt_dur(longest),
                shown(&holder),
                times,
                plural(times as u64)
            ));
        }
        if b.uncovered > 0 {
            out.push(format!(
                "{} of them could not be checked for who was stuck behind them: the thread-switch history no longer reached back that far.",
                b.uncovered
            ));
        }
    }
    if b.thrash > 0 {
        let names: Vec<String> = b.top_thrashers(3).iter().map(|(n, _)| shown(n)).collect();
        out.push(format!(
            "During {} of them the drive's head kept jumping between far-apart places for {} at the same time, so each got a fraction \
             of the drive.",
            b.thrash,
            and_list(&names)
        ));
    }
    out
}

/// What to try, from what the slow requests were. Only where it is actionable, and never
/// "run it one at a time" for a part of Windows.
fn behind_advice(b: &DiskBehind, spinning: bool) -> Vec<String> {
    let mut out = Vec::new();
    if spinning && b.count(|k| k == Kind::ProgramCode) > 0 {
        out.push(
            "Some slow requests were Windows loading program code from this hard drive: a program installed on it waits for the drive \
             whenever it needs a part of itself that is not in memory yet. Moving the programs you use most to an SSD fixes that."
                .to_string(),
        );
    }
    if b.thrash > 0 {
        let top = b.top_thrashers(3);
        let (win, own): (Vec<String>, Vec<String>) = top.into_iter().map(|(n, _)| n).partition(|n| windows_part(n));
        match (own.len(), win.first()) {
            (0, _) => {}
            (1, Some(w)) => {
                // "powershell.exe (2 copies)" names the fight; the advice names the program.
                let program = own[0].split(" (").next().unwrap_or(&own[0]);
                // `shown` may already say "Windows itself (...)": do not say Windows twice.
                let with = shown(w);
                let with = if with.starts_with("Windows") { with } else { format!("Windows' own work ({with})") };
                out.push(format!(
                    "{} was using this hard drive at the same time as {with}, far apart on the disk. Pause {program} while you use \
                     the PC, or move what it works on to another drive.",
                    own[0]
                ))
            }
            (1, None) => {}
            _ => out.push(format!(
                "{} were using this hard drive at the same time, far apart on the disk, so its head kept jumping between them. Run \
                 them one at a time, or move one of them to another drive.",
                and_list(&own)
            )),
        }
    }
    out
}

/// Names and owners of the file-system filters a disk's call stacks mention, looked up once, so
/// the wording below is a pure function of data (and testable without a live module list).
#[derive(Default)]
struct StackNames {
    /// driver -> "WdFilter.sys (Microsoft Defender Antivirus, antivirus scanning)"
    label: HashMap<String, String>,
    /// driver -> whether its own version resource says Microsoft wrote it
    microsoft: HashMap<String, Option<bool>>,
}

impl StackNames {
    fn of(b: &DiskBehind, filters: &HashMap<String, String>, modules: &mut crate::modules::ModuleMap) -> StackNames {
        let mut out = StackNames::default();
        for m in b.in_path.keys().chain(b.waited_in.keys()) {
            if !stacks::is_filter(filters, m) || out.label.contains_key(m) {
                continue;
            }
            let described = modules.describe_short(m);
            let described = (described != "unidentified driver").then_some(described);
            let group = filters.get(&m.to_ascii_lowercase()).map(String::as_str);
            out.label.insert(m.clone(), stacks::filter_label(m, group, described.as_deref()));
            out.microsoft.insert(m.clone(), modules.is_microsoft(m));
        }
        out
    }

    fn name(&self, m: &str) -> String {
        self.label.get(m).cloned().unwrap_or_else(|| m.to_string())
    }
}

fn percent(n: u32, of: u32) -> String {
    format!("{:.0}%", 100.0 * n as f64 / of.max(1) as f64)
}

/// A filter counts as "most of the time" in the path of a disk's slow requests from this many
/// stacks on, and at least half of them. Rule of thumb: one or two stacks are an anecdote.
const MOSTLY_MIN: u32 = 3;

/// The filters in the path of a disk's slow requests, most often first: (driver, how many stacks).
fn filters_in_path(b: &DiskBehind, filters: &HashMap<String, String>) -> Vec<(String, u32)> {
    top_counts(&b.in_path, STACK_KEYS_CAP).into_iter().filter(|(m, _)| stacks::is_filter(filters, m)).collect()
}

/// What the call stacks said about one disk's slow requests (see `stacks`). Facts only: a filter
/// being in the path of a request is never called its cause, because every file access on Windows
/// passes through several of them.
fn stack_sentences(b: &DiskBehind, filters: &HashMap<String, String>, names: &StackNames) -> Vec<String> {
    let mut out = Vec::new();
    if b.stack_found > 0 {
        let asked = b.stack_found + b.stack_missing;
        let of = if b.stack_missing > 0 { format!(" ({} of the {asked} checked had one)", b.stack_found) } else { String::new() };
        let found = filters_in_path(b, filters);
        if found.is_empty() {
            out.push(format!("The call stacks of the slow requests{of} show no file-system filter's own code in their path."));
        } else {
            let list: Vec<String> =
                found.iter().take(4).map(|(m, n)| format!("{} in {}", names.name(m), percent(*n, b.stack_found))).collect();
            out.push(format!(
                "The call stacks of the slow requests{of} show these file-system filters in their path: {}. In the path is not the \
                 same as the cause: every file access on Windows passes through several filters.",
                and_list(&list)
            ));
        }
    } else if b.stack_missing > 0 {
        out.push(format!(
            "Call stacks were asked for, but none arrived for the {} slow request{} checked (Windows cannot walk every kernel stack), \
             so which drivers were in their path is not known.",
            b.stack_missing,
            plural(b.stack_missing as u64)
        ));
    }
    if b.wait_stacks > 0 {
        let list: Vec<String> =
            top_counts(&b.waited_in, 3).iter().map(|(m, n)| format!("inside {} in {n} of {}", names.name(m), b.wait_stacks)).collect();
        out.push(format!("Where the programs stuck behind them were blocked, from their call stacks: {}.", list.join(", ")));
    }
    out
}

/// What to try from the call stacks, only when one filter was in the path of most slow requests or
/// most waits. Never "turn it off" or "uninstall" for anything, and for Microsoft Defender only
/// what Microsoft documents: an exclusion for a folder the person trusts, with Microsoft's warning.
fn stack_advice(b: &DiskBehind, filters: &HashMap<String, String>, names: &StackNames) -> Vec<String> {
    let mostly = |n: u32, of: u32| n >= MOSTLY_MIN && 2 * n >= of;
    let mut out = Vec::new();
    for (m, n) in filters_in_path(b, filters) {
        let blocked = b.waited_in.get(&m).copied().unwrap_or(0);
        if !mostly(n, b.stack_found) && !mostly(blocked, b.wait_stacks) {
            continue;
        }
        if stacks::known_filter(&m) == Some("Microsoft Defender Antivirus") {
            // Menu path and warning: https://support.microsoft.com/en-us/windows/add-an-exclusion-to-windows-security-811816c0-4dfd-af4a-47e4-c301afe13b26
            // ("Adding an exclusion to Windows Security means that Microsoft Defender Antivirus will
            // no longer check those types of files for threats, which could leave your device and
            // data vulnerable.")
            out.push(format!(
                "{} was in the path of most of this drive's slow requests. That alone does not make it the cause, and it is part of \
                 Windows' protection. If it keeps showing up, Microsoft documents excluding a folder you trust from its scanning \
                 (Windows Security > Virus & threat protection settings > Manage settings > Exclusions); Microsoft warns that files \
                 there are then no longer checked for threats, so only exclude something like a game library, never Downloads.",
                names.name(&m)
            ));
        } else if names.microsoft.get(&m).copied().flatten() == Some(false) {
            let av = filters.get(&m.to_ascii_lowercase()).is_some_and(|g| g.eq_ignore_ascii_case("FSFilter Anti-Virus"));
            let one = if av { " Only one antivirus product should be scanning files at a time." } else { "" };
            out.push(format!(
                "{} was in the path of most of this drive's slow requests. That alone does not make it the cause. If it keeps \
                 showing up, look in that product's settings for exclusions or a performance or gaming mode.{one}",
                names.name(&m)
            ));
        }
    }
    out
}

/// The DETAILS block for one disk: the commonest issuing paths and where the stuck threads waited.
fn stack_lines(drive: &str, b: &DiskBehind) -> Vec<String> {
    let mut out = Vec::new();
    for (path, n) in top_counts(&b.issue_paths, 3) {
        out.push(format!("  {drive}: slow requests issued through {path}  ({n} of {})", b.stack_found));
    }
    for ((program, path), n) in top_counts(&b.wait_paths, 4) {
        out.push(format!("  {drive}: {program} was blocked in {path}  ({n} time{})", plural(n as u64)));
    }
    out
}

/// What Windows itself logged about storage: resets, retries, bad blocks.
pub(super) fn event_log(cx: &mut Ctx) {
    let (now_unix, run_start_unix) = (cx.now_unix, cx.run_start_unix);
    let (storage_log, file_waits) = (&cx.storage_log, &cx.file_waits);
    let mut logged: Vec<(Option<u32>, u32)> = storage_log.iter().map(|e| (e.disk, e.id)).collect();
    logged.sort();
    logged.dedup();
    for (disk_n, id) in logged {
        let times: Vec<i64> = storage_log.iter().filter(|e| e.disk == disk_n && e.id == id).map(|e| e.unix_time).collect();
        let during = times.iter().any(|t| *t >= run_start_unix);
        let text = format!("Windows event log: {} (event {id}), {}.", evlog::meaning(id), when_text(&times, now_unix, run_start_unix));
        let (key, title, advice) = match disk_n {
            Some(n) => {
                let disk = cx.az.disks.get(n).clone();
                let hint = file_hint(&files::rank(&file_waits.iter().filter(|r| r.1 == n).cloned().collect::<Vec<_>>(), 3));
                (format!("disk {n}"), format!("{}  -  errors in the Windows event log", disk.title()), disk_advice(&disk, None, true, hint))
            }
            None => (
                "storage controller".to_string(),
                "Storage controller  -  a drive stopped answering and was reset".to_string(),
                CONTROLLER_RESET_ADVICE.to_string(),
            ),
        };
        if !cx.found.note(&key, text.clone()) {
            // Old entries alone are a lead, not a verdict.
            let sev = if during {
                Severity::High
            } else if times.len() >= 3 {
                Severity::Medium
            } else {
                Severity::Low
            };
            cx.found.add(&key, sev, title, text, advice, 0);
        }
        // The 7-day look-back cannot react to a fix made today, so what happened *while
        // monitoring* is the number two runs are compared by.
        cx.found.measure(&key, Metric::flat("errors while monitoring", times.iter().filter(|t| **t >= run_start_unix).count() as u32));
        cx.found.measure(&key, Metric::logged("in the last 7 days", times.len() as u32));
    }
}

/// What each drive says about itself (SMART / NVMe health).
pub(super) fn drive_health(cx: &mut Ctx) {
    let mut health_lines: Vec<String> = Vec::new();
    for n in cx.az.disks.present() {
        let disk = cx.az.disks.get(n).clone();
        let now = health::read(n, disk.bus);
        if now.is_empty() {
            health_lines.push(format!(
                "  disk {n:<3} not readable ({})",
                if disk.bus == "USB" { "USB enclosures usually block it" } else { "driver refused" }
            ));
            continue;
        }
        health_lines.push(format!("  disk {n:<3} {}", health_line(&now)));
        let key = format!("disk {n}");
        for (sev, text, advice) in health_findings(disk.spinning == Some(true), cx.az.health_at_start.get(&n), &now) {
            if cx.found.note(&key, text.clone()) {
                cx.found.raise(&key, sev);
                cx.found.advise(&key, advice);
            } else {
                cx.found.add(&key, sev, format!("{}  -  drive health warning", disk.title()), text, advice.to_string(), 0);
            }
        }
    }
    cx.health_lines = health_lines;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usb_hdd() -> DiskInfo {
        DiskInfo { number: 4, model: "Seagate FireCuda Dock".into(), bus: "USB", spinning: Some(true), ..Default::default() }
    }

    #[test]
    fn a_busy_disk_names_the_program_and_does_not_blame_the_drive() {
        let mut why = DiskWhy::default();
        why.causes.insert(Cause::Busy, 9);
        why.causes.insert(Cause::IdleSlow, 1);
        why.movers.insert("steam.exe".into(), 3_000_000_000);
        why.movers.insert("chrome.exe".into(), 100_000_000);
        let s = why_sentences(&why, false);
        assert!(
            s[0].contains("busy") && s[0].contains("9 of 10 times") && s[0].contains("steam.exe (3 GB, 97% of the traffic: Steam"),
            "{s:?}"
        );
        assert!(!s[0].contains("chrome"), "minor movers stay out: {s:?}");
        assert!(s[1].contains("not traffic"), "{s:?}");
        let advice = disk_advice(&usb_hdd(), Some(&why), false, FileHint::default());
        assert!(advice.contains("steam.exe: Pause the download") && !advice.contains("failing"), "{advice}");

        // Windows' own work cannot be paused or closed, so the advice must not say so.
        let mut win = DiskWhy::default();
        win.causes.insert(Cause::Busy, 3);
        win.movers.insert("backgroundTaskHost.exe".into(), 50_000_000);
        let advice = disk_advice(&usb_hdd(), Some(&win), false, FileHint::default());
        assert!(advice.contains("part of Windows") && advice.contains("run in background"), "{advice}");
        assert!(!advice.contains("pause it") && !advice.contains("Let backgroundTaskHost"), "{advice}");
    }

    #[test]
    fn a_sleeping_drive_gets_power_settings_and_logged_errors_override_everything() {
        let mut why = DiskWhy { longest_sleep_ms: 42_000.0, ..Default::default() };
        why.causes.insert(Cause::WokeUp, 2);
        assert!(why_sentences(&why, false)[0].contains("every time") && why_sentences(&why, false)[0].contains("42 s"));
        assert!(disk_advice(&usb_hdd(), Some(&why), false, FileHint::default()).contains("Turn off hard disk after"));
        let logged = disk_advice(&usb_hdd(), Some(&why), true, FileHint::default());
        assert!(logged.contains("back up what matters now") && !logged.contains("Turn off hard disk"), "{logged}");
    }

    fn row(name: &str, disk: u32, count: u64, total_ms: f64, worst_ms: f64) -> FileRow {
        (name.to_string(), disk, count, ms_to_ticks(total_ms), ms_to_ticks(worst_ms))
    }

    #[test]
    fn the_files_that_waited_longest_are_named_in_plain_words() {
        let rows = vec![
            row("C:\\pagefile.sys", 0, 1204, 3200.0, 480.0),
            row("D:\\SteamLibrary\\steamapps\\common\\Game\\game.pak", 1, 40, 910.0, 300.0),
            row("C:\\...\\notes.txt", 0, 1, 5.0, 5.0),
        ];
        let s = files_sentence(&rows, &HashMap::new()).expect("a sentence");
        assert!(s.starts_with("Most of the waiting was for: C:\\pagefile.sys (1204 requests,"), "{s}");
        assert!(s.contains("game.pak (40 requests"), "{s}");
        assert!(s.contains("short of memory"), "the worst one is explained: {s}");
        assert_eq!(files_sentence(&[], &HashMap::new()), None);
    }

    /// Issue #19: which program waited on which file. Two copies of one program add up under its
    /// image name, and Windows' own file-cache writer is named as Windows, never as a program.
    #[test]
    fn the_program_behind_a_files_waiting_is_named_by_image_name_only() {
        let image = r"G:\...\(a .mrimg file)";
        let rows = vec![row(image, 0, 412, 53_000.0, 900.0), row(r"C:\pagefile.sys", 0, 10, 100.0, 20.0)];
        let mut programs: HashMap<(String, u32), Vec<ProgramRow>> = HashMap::new();
        programs.insert((image.to_string(), 0), vec![("powershell.exe".into(), 2, 400, ms_to_ticks(52_000.0))]);
        programs.insert((r"C:\pagefile.sys".to_string(), 0), vec![("System (kernel threads)".into(), 1, 10, ms_to_ticks(100.0))]);
        let s = files_sentence(&rows, &programs).expect("a sentence");
        assert!(s.contains("(a .mrimg file) (412 requests, 53.0 s, issued by powershell.exe (2 copies))"), "{s}");
        assert!(s.contains("pagefile.sys (10 requests, 100 ms, issued by Windows itself (System))"), "{s}");
        assert!(!s.contains("pid"), "no process IDs: {s}");
        assert_eq!(programs_text(&programs[&(image.to_string(), 0)], 3).as_deref(), Some("powershell.exe 2 copies, 52.0 s"));
        assert_eq!(programs_text(&[], 3), None);
    }

    /// Issue #19: a freeze that coincided with a slow request on a disk is evidence on the DISK's
    /// finding too, but one whose request only began once the PC had stopped is not.
    #[test]
    fn a_freeze_is_said_on_the_disk_it_coincided_with_but_never_blamed_on_a_victim() {
        use crate::analyze::{Coincided, FreezeFacts, IncidentClass, IncidentSummary};
        use crate::diskwait::Role;
        let freeze = |disk, role| IncidentSummary {
            class: IncidentClass::Freeze,
            start: 0,
            dur: ms_to_ticks(900.0),
            culprit: "whole-PC freeze".into(),
            marked: false,
            cpus: (0..8).collect(),
            on_cpu: None,
            freeze: Some(FreezeFacts {
                coincided: Some(Coincided { disk: Some(disk), role, waited: ms_to_ticks(2173.0), woke: true }),
                ..FreezeFacts::default()
            }),
            busy_core: None,
        };
        let incidents = vec![freeze(6, Role::Trigger), freeze(6, Role::Overlap), freeze(2, Role::Victim), freeze(6, Role::Victim)];
        let s = freeze_sentence(&incidents, 6).expect("disk 6 was outstanding during two freezes");
        assert!(
            s.starts_with("The whole PC froze 2 times while a slow request to this drive was outstanding, after it had been asleep"),
            "{s}"
        );
        assert!(s.contains("up to 2173 ms") && s.contains("'Coincided' is all this says"), "{s}");
        assert_eq!(freeze_sentence(&incidents, 2), None, "a request slowed down by the freeze is not the drive's doing");
        assert_eq!(freeze_sentence(&incidents, 5), None);
    }

    /// Which file waited changes the answer: the paging file means memory, game data means the
    /// game. Neither may push out the drive checks that were there before.
    #[test]
    fn the_file_that_waited_changes_the_advice() {
        let hdd = usb_hdd();
        let plain = disk_advice(&hdd, None, false, FileHint::default());
        assert!(!plain.contains("paging file"), "{plain}");

        let paging = disk_advice(&hdd, None, false, file_hint(&[row("C:\\pagefile.sys", 0, 9, 100.0, 50.0)]));
        assert!(paging.contains("ran out of memory") && paging.contains("add RAM"), "{paging}");
        assert!(paging.contains("slowest place it can be"), "a paging file on a hard drive is its own problem: {paging}");
        assert!(paging.contains("CrystalDiskInfo"), "the drive checks still follow: {paging}");

        let game = disk_advice(&hdd, None, false, file_hint(&[row("D:\\Games\\x\\data.pak", 1, 9, 100.0, 50.0)]));
        assert!(game.contains("move that game to an SSD"), "{game}");
        // The same files on an SSD are not a reason to move anything.
        let mut ssd = usb_hdd();
        ssd.spinning = Some(false);
        let on_ssd = disk_advice(&ssd, None, false, file_hint(&[row("D:\\Games\\x\\data.pak", 1, 9, 100.0, 50.0)]));
        assert!(!on_ssd.contains("move that game"), "{on_ssd}");
    }

    #[test]
    fn paging_names_one_file_only_when_one_file_really_dominates() {
        let mixed = [("a.dll".to_string(), 1u64, 100i64), ("b.dll".to_string(), 1, 90), ("c.dll".to_string(), 1, 80)];
        assert_eq!(dominant_file(&mixed), None, "a mix must not be reported as one file");
        let clear = [("C:\\pagefile.sys".to_string(), 9u64, 900i64), ("a.dll".to_string(), 1, 100)];
        let (name, share) = dominant_file(&clear).unwrap();
        assert_eq!(name, "C:\\pagefile.sys");
        assert!((share - 0.9).abs() < 1e-9);
        // Several handles to the same file add up to one file.
        let split = [("g.pak".to_string(), 1u64, 300i64), ("g.pak".to_string(), 1, 300), ("x".to_string(), 1, 200)];
        assert_eq!(dominant_file(&split).map(|d| d.0), Some("g.pak".to_string()));
        assert_eq!(dominant_file(&[]), None);
        assert_eq!(dominant_file(&[("a".to_string(), 1, 0)]), None, "no waiting at all is not a dominant file");
    }

    /// The DETAILS tables are printed as-is, with no wrapping to save them, so the widest
    /// possible file name still has to fit the report.
    #[test]
    fn the_file_table_fits_the_report_width() {
        let widest = "C:\\Program Files\\".to_string() + &"w".repeat(80) + ".bundle";
        let name = crate::files::public_path(&widest);
        let line = format!("  {name:<64} {:>5} {:>9} {:>12} {:>10}", 11, 999_999, fmt_dur(ms_to_ticks(9999.0)), fmt_dur(1));
        assert!(line.chars().count() <= 118, "{} chars: {line}", line.chars().count());
    }

    /// The field numbers: 6.7 s of page-fault waiting spread over 59 minutes is 0.2% of the run
    /// and must not be HIGH; the same 6.7 s inside five minutes is 2% and is.
    #[test]
    fn paging_is_judged_by_its_share_of_the_run() {
        let ms = ms_to_ticks;
        assert_eq!(paging_severity(ms(6718.0), ms(29.26), 3561.0), Severity::Low);
        assert_eq!(paging_severity(ms(6718.0), ms(29.26), 300.0), Severity::High);
        // One wait of a fifth of a second is felt whenever it happened.
        assert_eq!(paging_severity(ms(1486.0), ms(219.0), 3561.0), Severity::Medium);
    }

    /// A slow request that only began once the whole PC had already stopped is explained by the
    /// freeze. Counting it against its drive turns one problem into two, and in the field log it
    /// gave a healthy internal NVMe its own "responding slowly" finding.
    #[test]
    fn requests_a_freeze_explains_do_not_count_against_a_healthy_drive() {
        use crate::analyze::SlowSeen;
        let seen = |durs: &[(f64, bool)]| -> Vec<SlowSeen> {
            durs.iter().enumerate().map(|(i, (d, v))| SlowSeen { end: i as i64, dur: ms_to_ticks(*d), victim: *v }).collect()
        };
        // Both of this disk's slow requests sat inside freezes: nothing is left to report.
        let all_victims = seen(&[(976.0, true), (878.0, true)]);
        assert_eq!(discount_victims(Some(&all_victims), 2, ms_to_ticks(976.0)), (0, 0));
        // One was, one was not: the drive keeps the one that is really its own.
        let mixed = seen(&[(976.0, true), (300.0, false)]);
        assert_eq!(discount_victims(Some(&mixed), 2, ms_to_ticks(976.0)), (1, ms_to_ticks(300.0)));
        // Nothing was seen, or not all of it: fall back to the raw totals rather than guess.
        assert_eq!(discount_victims(None, 6, ms_to_ticks(2173.0)), (6, ms_to_ticks(2173.0)));
        assert_eq!(discount_victims(Some(&mixed), 6, ms_to_ticks(2173.0)), (6, ms_to_ticks(2173.0)));
    }

    fn behind() -> DiskBehind {
        let mut b = DiskBehind::default();
        b.kinds.insert(Kind::PagingFile, 5);
        b.kinds.insert(Kind::ProgramCode, 3);
        b.kinds.insert(Kind::PagedFile, 4);
        b.kinds.insert(Kind::Bookkeeping, 2);
        b.kinds.insert(Kind::FileData, 6);
        b.checked = 18;
        b.uncovered = 2;
        b.stuck.insert("explorer.exe".into(), (14, ms_to_ticks(9200.0)));
        b.stuck.insert("Discord.exe".into(), (2, ms_to_ticks(300.0)));
        b.chains.insert(("explorer.exe".into(), "System (kernel threads)".into()), (3, ms_to_ticks(2100.0)));
        b
    }

    #[test]
    fn the_disk_finding_says_what_was_slow_and_who_waited_for_it() {
        let s = behind_sentences(&behind(), true);
        assert!(
            s[0].starts_with("What the slow requests were: 8 paging")
                && s[0].contains("4 through the file cache")
                && s[0].contains("5 to or from the paging file"),
            "{s:?}"
        );
        assert!(s[0].contains("3 loading program code") && s[0].contains("2 file-system bookkeeping") && s[0].contains("6 a file's"));
        assert!(s[1].starts_with("Stuck behind them") && s[1].contains("explorer.exe (part of Windows): behind 14, "), "{s:?}");
        assert!(s[1].find("explorer").unwrap() < s[1].find("Discord").unwrap(), "most waiting first: {s:?}");
        assert!(
            s.iter().any(|l| l.contains("on a lock held by Windows itself (System), which was itself waiting on this drive (3 times)")),
            "{s:?}"
        );
        assert!(s.iter().any(|l| l.starts_with("2 of them could not be checked")), "{s:?}");
        // Lost events: nothing read from the thread-switch trace is said, only what the requests carry.
        let s = behind_sentences(&behind(), false);
        assert_eq!(s.len(), 1, "{s:?}");
        // Checked, and nobody waited: that is said plainly; not checked at all says nothing.
        let quiet = DiskBehind { checked: 4, ..DiskBehind::default() };
        assert!(behind_sentences(&quiet, true)[0].contains("No program was seen"));
        assert!(behind_sentences(&DiskBehind { uncovered: 4, ..DiskBehind::default() }, true).iter().all(|l| !l.contains("No program")));
    }

    /// The audience rule: a part of Windows is never something to close, pause, uninstall or run
    /// "one at a time", whatever the drive was doing.
    #[test]
    fn the_disk_finding_never_tells_anyone_to_stop_a_part_of_windows() {
        let windows = ["System (kernel threads)", "svchost.exe", "dwm.exe", "MsMpEng.exe", "SearchIndexer.exe", "explorer.exe"];
        for a in windows {
            for b in windows.iter().filter(|b| **b != a) {
                let mut d = behind();
                d.thrash = 3;
                d.thrash_programs.insert(a.to_string(), 3);
                d.thrash_programs.insert(b.to_string(), 2);
                d.stuck.insert(a.to_string(), (1, 10));
                d.chains.insert((b.to_string(), a.to_string()), (1, 10));
                let text = [behind_sentences(&d, true), behind_advice(&d, true)].concat().join(" ").to_lowercase();
                for bad in ["close", "end task", "uninstall", "pause", "one at a time"] {
                    assert!(!text.contains(bad), "{a} / {b}: says {bad:?}: {text}");
                }
            }
        }
        // Two ordinary programs do get the practical advice...
        let mut d = DiskBehind { thrash: 2, ..DiskBehind::default() };
        d.thrash_programs.insert("steam.exe".into(), 2);
        d.thrash_programs.insert("qbittorrent.exe".into(), 2);
        let advice = behind_advice(&d, true).join(" ");
        assert!(
            advice.contains("qbittorrent.exe and steam.exe were using this hard drive") && advice.contains("one at a time"),
            "{advice}"
        );
        // ...and one program against Windows' own work is told about only that program.
        let mut d = DiskBehind { thrash: 2, ..DiskBehind::default() };
        d.thrash_programs.insert("steam.exe".into(), 2);
        d.thrash_programs.insert("MsMpEng.exe".into(), 2);
        let advice = behind_advice(&d, true).join(" ");
        assert!(advice.starts_with("steam.exe was using") && advice.contains("MsMpEng.exe (part of Windows)"), "{advice}");
        assert!(!advice.contains("Pause MsMpEng"), "{advice}");
        // Program code paging from a hard drive is worth moving; from an SSD it is not.
        assert!(behind_advice(&behind(), true).iter().any(|a| a.contains("to an SSD")));
        assert!(behind_advice(&behind(), false).is_empty());
    }

    fn filter_map() -> HashMap<String, String> {
        [
            ("wdfilter.sys", "FSFilter Anti-Virus"),
            ("cldflt.sys", "FSFilter HSM"),
            ("fltmgr.sys", "FSFilter Infrastructure"),
            ("avx.sys", "FSFilter Anti-Virus"),
        ]
        .iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect()
    }

    fn stacked() -> DiskBehind {
        let mut b = DiskBehind { stack_found: 10, stack_missing: 2, wait_stacks: 4, ..DiskBehind::default() };
        for (m, n) in [("FLTMGR.SYS", 10), ("Ntfs.sys", 10), ("WdFilter.sys", 8), ("cldflt.sys", 1)] {
            b.in_path.insert(m.into(), n);
        }
        b.waited_in.insert("WdFilter.sys".into(), 3);
        b.waited_in.insert("the Windows kernel".into(), 1);
        b.issue_paths.insert("FLTMGR.SYS -> Ntfs.sys".into(), 7);
        b.wait_paths.insert(("explorer.exe".into(), "FLTMGR.SYS -> WdFilter.sys".into()), 3);
        b
    }

    fn names_for_test() -> StackNames {
        let mut n = StackNames::default();
        n.label.insert("WdFilter.sys".into(), stacks::filter_label("WdFilter.sys", Some("FSFilter Anti-Virus"), None));
        n.microsoft.insert("WdFilter.sys".into(), Some(true));
        n.label.insert("avx.sys".into(), "avx.sys (Example AV, antivirus scanning)".into());
        n.microsoft.insert("avx.sys".into(), Some(false));
        n
    }

    #[test]
    fn call_stacks_name_the_filters_in_the_path_without_calling_them_the_cause() {
        let s = stack_sentences(&stacked(), &filter_map(), &names_for_test());
        assert!(s[0].contains("(10 of the 12 checked had one)"), "{s:?}");
        assert!(
            s[0].contains("WdFilter.sys (Microsoft Defender Antivirus, antivirus scanning) in 80%") && s[0].contains("cldflt.sys in 10%"),
            "{s:?}"
        );
        assert!(!s[0].contains("FLTMGR") && !s[0].contains("Ntfs"), "the Filter Manager and the file system are not filters: {s:?}");
        assert!(s[0].contains("not the same as the cause"), "{s:?}");
        assert!(s[1].contains("inside WdFilter.sys (Microsoft Defender Antivirus, antivirus scanning) in 3 of 4"), "{s:?}");
        assert!(s[1].contains("inside the Windows kernel in 1 of 4"), "{s:?}");
        // No filter at all, and no stack at all, are both said plainly.
        let mut none = stacked();
        none.in_path.retain(|m, _| m == "Ntfs.sys");
        none.wait_stacks = 0;
        assert_eq!(stack_sentences(&none, &filter_map(), &names_for_test()).len(), 1);
        assert!(stack_sentences(&none, &filter_map(), &names_for_test())[0].contains("show no file-system filter"));
        let missing = DiskBehind { stack_missing: 3, ..DiskBehind::default() };
        assert!(stack_sentences(&missing, &filter_map(), &names_for_test())[0].contains("none arrived for the 3 slow requests"));
        let lines = stack_lines("disk 1 (D:)", &stacked());
        assert_eq!(lines[0], "  disk 1 (D:): slow requests issued through FLTMGR.SYS -> Ntfs.sys  (7 of 10)");
        assert_eq!(lines[1], "  disk 1 (D:): explorer.exe was blocked in FLTMGR.SYS -> WdFilter.sys  (3 times)");
    }

    /// The audience rule, for call stacks: Defender is part of Windows, so the most the report
    /// may do is point at Microsoft's documented exclusions - never off, never uninstall.
    #[test]
    fn defender_in_the_path_is_never_something_to_turn_off() {
        let advice = stack_advice(&stacked(), &filter_map(), &names_for_test()).join(" ");
        assert!(advice.contains("Exclusions") && advice.contains("no longer checked for threats"), "{advice}");
        for bad in ["turn off", "disable", "uninstall", "close", "remove", "stop", "real-time protection"] {
            assert!(!advice.to_lowercase().contains(bad), "says {bad:?}: {advice}");
        }
        // Only when it was in the path most of the time: once in ten says nothing.
        let mut rare = stacked();
        rare.in_path.insert("WdFilter.sys".into(), 1);
        rare.waited_in.clear();
        assert!(stack_advice(&rare, &filter_map(), &names_for_test()).is_empty());
        // Another vendor's antivirus filter gets that product's settings, and the one-antivirus rule.
        let mut other = DiskBehind { stack_found: 6, ..DiskBehind::default() };
        other.in_path.insert("avx.sys".into(), 5);
        let a = stack_advice(&other, &filter_map(), &names_for_test()).join(" ");
        assert!(a.starts_with("avx.sys (Example AV") && a.contains("that product's settings") && a.contains("Only one antivirus"), "{a}");
    }

    #[test]
    fn what_the_storage_driver_saw_live_is_said_in_one_sentence() {
        use crate::storport::ResetKind;
        let time = |ts: i64| format!("t{ts}");
        assert_eq!(live_sentence(AddrTotals { requests: 900, ..AddrTotals::default() }, &[], &time), None, "a quiet drive says nothing");
        let t = AddrTotals { requests: 900, failed: 1, retried: 5, retries: 8 };
        let reset = |ts| ResetRec { ts, kind: ResetKind::LogicalUnit, port: 6, bus: Some(0), target: Some(0), lun: Some(0) };
        let s = live_sentence(t, &[reset(1), reset(2)], &time).unwrap();
        assert_eq!(
            s,
            "Seen live by Windows' storage driver while monitoring: Windows had to retry 5 requests to it (8 retries in all); 1 read or \
             write came back failed; Windows reset the drive 2 times (at t1 and t2), and every request to it waits while that happens."
        );
        let many: Vec<ResetRec> = (0..5).map(reset).collect();
        let s = live_sentence(AddrTotals::default(), &many, &time).unwrap();
        assert!(s.contains("5 times (at t0, t1, t2 and 2 more)"), "{s}");
        let one = live_sentence(AddrTotals { retried: 1, retries: 1, ..AddrTotals::default() }, &[], &time).unwrap();
        assert!(one.contains("retry 1 request to it (1 retry in all)"), "{one}");
        // The audience rule: nothing here or in the advice treats a part of Windows as something to close.
        for text in [s, one, RETRY_ADVICE.to_string(), CONTROLLER_RESET_ADVICE.to_string(), storsplit::NOT_MEASURED.to_string()] {
            let l = text.to_lowercase();
            for bad in ["close", "end task", "uninstall", "pause"] {
                assert!(!l.contains(bad), "{bad}: {text}");
            }
        }
    }

    #[test]
    fn drive_health_separates_what_happened_now_from_lifetime_totals() {
        use crate::health::{NvmeHealth, SataSmart};
        let nvme = |temperature_c, throttle_seconds, media_errors| DriveHealth {
            nvme: Some(NvmeHealth { temperature_c, throttle_seconds, media_errors, spare_percent: 100, ..Default::default() }),
            ..Default::default()
        };
        assert!(health_findings(false, Some(&nvme(45, 0, 0)), &nvme(48, 0, 0)).is_empty(), "a healthy drive says nothing");

        let f = health_findings(false, Some(&nvme(60, 100, 0)), &nvme(78, 130, 0));
        assert_eq!(f.len(), 1);
        assert!(f[0].0 == Severity::High && f[0].1.contains("30 s slowed down by heat while monitoring"), "{}", f[0].1);

        let f = health_findings(false, None, &nvme(74, 5000, 2));
        assert!(f.iter().any(|x| x.0 == Severity::Medium && x.1.contains("2 unrecoverable media error")));
        assert!(f.iter().any(|x| x.1.contains("74 °C") && x.2 == DRIVE_HOT_ADVICE), "hot now, no baseline to compare");

        let sata = |crc, pending| DriveHealth {
            sata: Some(SataSmart { crc_errors: Some(crc), pending: Some(pending), reallocated: Some(0), ..Default::default() }),
            ..Default::default()
        };
        let f = health_findings(true, Some(&sata(10, 0)), &sata(10, 0));
        assert!(f.len() == 1 && f[0].0 == Severity::Low && f[0].1.contains("none while monitoring"), "old CRC errors are only a lead");
        let f = health_findings(true, Some(&sata(10, 0)), &sata(14, 3));
        assert!(f.iter().any(|x| x.0 == Severity::High && x.1.contains("4 new CRC") && x.2 == DRIVE_CABLE_ADVICE));
        assert!(f.iter().any(|x| x.0 == Severity::High && x.1.contains("3 pending") && x.2 == DRIVE_FAILING_ADVICE));
    }
}
