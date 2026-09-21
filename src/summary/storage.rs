//! Disks and memory: slow requests and why they were slow, which files did the waiting, what
//! Windows logged about storage, and what each drive reports about its own health.

use std::collections::HashMap;
use std::mem::{size_of, zeroed};

use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

use crate::disks::{fmt_size, DiskInfo};
use crate::diskwhy::{Cause, DiskWhy};
use crate::evlog;
use crate::files;
use crate::health::{self, DriveHealth};
use crate::procs::known_worker;
use crate::procs::process_name;
use crate::state::LatStat;
use crate::util::{fmt_dur, ms_to_ticks, plural, ticks_to_ms};

use super::ctx::{when_text, Ctx};
use super::{Metric, Severity};

const CONTROLLER_RESET_ADVICE: &str = "Every program waits, often for many seconds, while Windows resets a drive. Usual causes: a \
    loose or bad SATA/M.2 connection, drive firmware, or link power saving. Reseat or replace cables, update SSD firmware and the \
    chipset/storage driver, and set Power Options > PCI Express > Link State Power Management to Off. Event Viewer > Windows Logs > \
    System (event 129) shows which controller.";

fn memory_load() -> u32 {
    let mut mem: MEMORYSTATUSEX = unsafe { zeroed() };
    mem.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
    unsafe { GlobalMemoryStatusEx(&mut mem) };
    mem.dwMemoryLoad
}

/// One row of "which files waited on disk": (path already made public-safe, disk, requests,
/// total wait, worst wait).
pub(super) type FileRow = (String, u32, u64, i64, i64);

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

/// "Most of the waiting was for ...", naming the files that waited longest on one disk.
fn files_sentence(rows: &[FileRow]) -> Option<String> {
    let top = files::rank(rows, 3);
    if top.is_empty() {
        return None;
    }
    let list: Vec<String> =
        top.iter().map(|(name, _, count, total, _)| format!("{name} ({count} request{}, {})", plural(*count), fmt_dur(*total))).collect();
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
fn why_sentences(why: &DiskWhy) -> Vec<String> {
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
                format!("Why: the disk was busy moving a lot of data ({}).{who}", of(n))
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
    let mem = memory_load();
    for (name, s) in &faults_named {
        if s.total < ms_to_ticks(1000.0) && s.max < ms_to_ticks(200.0) {
            continue;
        }
        let share = ticks_to_ms(s.total) / (cx.run.elapsed_s.max(1.0) * 1000.0);
        let sev = paging_severity(s.total, s.max, cx.run.elapsed_s);
        let advice = if mem >= 85 {
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
            format!(" {victims} more happened while the whole PC was frozen and are counted there instead.")
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
        let logged = storage_log.iter().any(|e| e.disk == Some(*n));
        let on_disk: Vec<FileRow> = file_waits.iter().filter(|r| r.1 == *n).cloned().collect();
        let advice = disk_advice(&disk, why, logged, file_hint(&files::rank(&on_disk, 3)));
        cx.found.add(&key, sev, format!("{}  -  responding slowly", disk.title()), evidence, advice, worst * slow as i64);
        cx.found.measure(&key, Metric::count("slow requests", slow as f64));
        cx.found.measure(&key, Metric::ms("worst wait", ticks_to_ms(worst)));
        for sentence in why.map(why_sentences).unwrap_or_default() {
            cx.found.note(&key, sentence);
        }
        if let Some(sentence) = files_sentence(&on_disk) {
            cx.found.note(&key, sentence);
        }
    }
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
        let s = why_sentences(&why);
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
        assert!(why_sentences(&why)[0].contains("every time") && why_sentences(&why)[0].contains("42 s"));
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
        let s = files_sentence(&rows).expect("a sentence");
        assert!(s.starts_with("Most of the waiting was for: C:\\pagefile.sys (1204 requests,"), "{s}");
        assert!(s.contains("game.pak (40 requests"), "{s}");
        assert!(s.contains("short of memory"), "the worst one is explained: {s}");
        assert_eq!(files_sentence(&[]), None);
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
