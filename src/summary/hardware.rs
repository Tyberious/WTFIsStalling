//! What the hardware and the firmware did: errors Windows logged (WHEA), crashes and sudden
//! power loss, the processor being held back, and stalls landing on a hybrid CPU's slow cores.

use crate::cpuclock::ClockSample;
use crate::evlog::{self, HardwareEvent, HardwareKind, UnexpectedShutdown};
use crate::pci::{self, PciDevice};
use crate::topology::Topology;
use crate::util::{ms_to_ticks, plural, qpc_freq};

use super::ctx::{when_text, Ctx, EVENT_LOG_DAYS};
use super::{Metric, Severity};

const THROTTLE_ADVICE: &str = "The CPU is being held back by heat or a power limit. Watch temperatures under load (HWiNFO or the \
    vendor's tool): clean dust, check the cooler is seated and the fans spin, renew thermal paste on older machines. On laptops \
    plug in the charger and pick the 'Best performance' power mode. In the BIOS check that power limits, ECO mode or an undervolt \
    are not set too aggressively.";

const MEMORY_ERROR_ADVICE: &str = "The PC corrected these errors, but each one pauses everything briefly and they are a warning sign: \
    uncorrected ones crash programs and corrupt files. The usual cause is a memory overclock profile that is not quite stable: in the \
    BIOS turn XMP / EXPO / DOCP off (or lower the memory speed one step) and monitor again. Update the BIOS. If errors continue at \
    default settings, reseat the memory sticks and test them one at a time with MemTest86 or Windows Memory Diagnostic; replace the \
    one that fails.";

const PROCESSOR_ERROR_ADVICE: &str = "The processor reported errors it could correct; each one pauses everything briefly, and the \
    uncorrected kind crashes the PC. The usual cause is settings pushed past stable: in the BIOS remove any undervolt, Curve Optimizer \
    / PBO tuning or overclock (loading 'optimized defaults' does all of that), then monitor again. Update the BIOS and check CPU \
    temperatures under load. If errors continue at default settings the CPU or motherboard may be faulty: use the warranty.";

const PCIE_ERROR_ADVICE: &str = "Data on this PCI Express link arrived damaged and had to be sent again, which stalls the device and \
    everything waiting on it. Reseat the card or M.2 drive; if a riser or extension cable is used, that is the prime suspect: test \
    without it, or set that slot to a lower PCIe generation (Gen 4 -> Gen 3) in the BIOS. Also try Power Options > PCI Express > \
    Link State Power Management = Off, update the BIOS and chipset driver, and try another slot.";

const FATAL_ERROR_ADVICE: &str = "The PC crashed, froze or restarted because of a hardware error, not because of software. Load \
    'optimized defaults' in the BIOS to remove every overclock, undervolt and memory profile (XMP / EXPO), update the BIOS, and check \
    temperatures and that all power cables are firmly seated. If it still happens at default settings, test the memory (MemTest86) \
    and suspect the power supply, CPU or motherboard.";

/// Fewest stalls worth reading a pattern into, and the share of them that has to be on
/// efficiency cores before it is one.
const ECORE_MIN_STALLS: usize = 3;
const ECORE_SHARE: f64 = 0.8;

/// Were the stalls concentrated on the slow (efficiency) cores of a hybrid CPU?
///
/// `hit` is the CPUs each stall or flagged moment held up. It counts as an E-core stall only
/// when every CPU it hit was an efficiency core. The rule deliberately stays narrow: at least
/// 3 stalls, at least 80% of them on E-cores, and only where the E-cores are at most half of
/// the logical CPUs -- otherwise most stalls land on an E-core on any machine, simply because
/// most cores are E-cores, and that says nothing.
///
/// Returns (stalls on E-cores, stalls that named a CPU, the cores involved).
fn e_core_concentration(topo: &Topology, hit: &[Vec<u16>]) -> Option<(usize, usize, Vec<u16>)> {
    if !topo.hybrid() || topo.efficiency_cpus() * 2 > topo.total() {
        return None;
    }
    let named: Vec<&Vec<u16>> = hit.iter().filter(|c| !c.is_empty()).collect();
    let on_e: Vec<&&Vec<u16>> = named.iter().filter(|c| c.iter().all(|cpu| topo.is_efficiency(*cpu))).collect();
    if named.len() < ECORE_MIN_STALLS || (on_e.len() as f64) < named.len() as f64 * ECORE_SHARE {
        return None;
    }
    let mut cores: Vec<u16> = on_e.iter().flat_map(|c| c.iter().copied()).collect();
    cores.sort_unstable();
    cores.dedup();
    Some((on_e.len(), named.len(), cores))
}

/// What this finding may claim is limited to what the probes measure and what Microsoft documents.
/// The probes are pinned one per core, so a stall on an E-core means a driver or interrupt held
/// THAT core; it does not show what program was running there. Microsoft's Quality of Service page
/// (<https://learn.microsoft.com/windows/win32/procthread/quality-of-service>) documents which work
/// is sent to efficient cores: Eco QoS (Task Manager's "Efficiency mode") "always ... schedules to
/// efficient cores", and on battery so do windows that are not visible (Low) and background
/// services (Utility). It does not say that foreground work stays off E-cores, so that is not
/// claimed. Efficiency mode is toggled per process by right-clicking it on Task Manager's
/// Processes tab; a green leaf marks it.
const ECORE_ADVICE: &str = "This is a lead, not a verdict: it tells you where the stalls were, not who was waiting there. Two things \
    Windows documents as sending a program to the efficiency cores are worth ruling out. Open Task Manager, and on the Processes tab \
    check that the game or app you care about does not have 'Efficiency mode' switched on (a small green leaf next to its name): \
    right-click it to turn that off. On a laptop, plug in the charger: on battery, Windows moves background work and windows that \
    are not in view to the efficiency cores. The findings above say what caused the stalls themselves.";

/// (bus, device, function)
type PciAddress = (u32, u32, u32);

/// A hardware error and a stall this close together are treated as one event. Event log times are
/// whole seconds and logging lags the error slightly.
const COINCIDE_S: i64 = 2;

/// How many of `stalls` fall within COINCIDE_S of any of `events` (Unix seconds).
fn coinciding(stalls: &[i64], events: &[i64]) -> usize {
    stalls.iter().filter(|s| events.iter().any(|e| (*e - **s).abs() <= COINCIDE_S)).count()
}

const SHUTDOWN_ADVICE: &str = "A blue screen names its stop code: search for that code together with your PC or motherboard model, and \
    update the driver it points at. A sudden restart or power-off with no blue screen is usually power or heat: check CPU and GPU \
    temperatures under load, reseat the power cables, remove any overclock, undervolt or memory profile (XMP / EXPO) in the BIOS, \
    and suspect the power supply if it happens under load.";

/// One finding for the times Windows came back up without a clean shutdown.
fn shutdown_finding(events: &[UnexpectedShutdown], now: i64) -> Option<(Severity, String)> {
    // Someone holding the power button is a symptom (it had frozen), but not a crash by itself.
    let crashes: Vec<&UnexpectedShutdown> = events.iter().filter(|e| e.bugcheck != 0 || !e.power_button).collect();
    if crashes.is_empty() {
        return None;
    }
    let mut codes: Vec<u32> = crashes.iter().map(|e| e.bugcheck).filter(|c| *c != 0).collect();
    codes.sort();
    codes.dedup();
    let blue = crashes.iter().filter(|e| e.bugcheck != 0).count();
    let silent = crashes.len() - blue;
    let mut parts = Vec::new();
    if blue > 0 {
        let names: Vec<String> = codes
            .iter()
            .map(|c| match evlog::bugcheck_name(*c) {
                "" => format!("0x{c:X}"),
                name => format!("0x{c:X} {name}"),
            })
            .collect();
        parts.push(format!("{blue} blue screen{} (stop code {})", plural(blue as u64), names.join(", ")));
    }
    if silent > 0 {
        parts.push(format!("{silent} sudden restart{} or power loss with no blue screen", plural(silent as u64)));
    }
    let times: Vec<i64> = crashes.iter().map(|e| e.unix_time).collect();
    let text = format!(
        "Windows event log: this PC went down without shutting down {}: {}.",
        when_text(&times, now, i64::MAX),
        parts.join(" and ")
    );
    Some((if crashes.len() >= 2 { Severity::Medium } else { Severity::Low }, text))
}

struct HardwareFinding {
    key: String,
    severity: Severity,
    title: String,
    evidence: String,
    advice: &'static str,
    /// Errors while monitoring, then the 7-day total: the first is what a next run can change.
    metrics: Vec<Metric>,
}

/// One finding per failing component from the WHEA events Windows logged.
/// `stalls` are the wall-clock times (Unix seconds) of this run's stalls and flagged moments.
fn hardware_findings(events: &[HardwareEvent], devices: &[PciDevice], stalls: &[i64], now: i64, run_start: i64) -> Vec<HardwareFinding> {
    // PCIe errors are grouped per bus address; everything else per kind.
    let mut groups: Vec<(HardwareKind, Option<PciAddress>)> = events
        .iter()
        .filter(|e| e.kind != HardwareKind::Other)
        .map(|e| (e.kind, e.pci.as_ref().map(|p| (p.bus, p.device, p.function))))
        .collect();
    groups.sort();
    groups.dedup();
    let mut out = Vec::new();
    for (kind, address) in groups {
        let members: Vec<&HardwareEvent> =
            events.iter().filter(|e| e.kind == kind && e.pci.as_ref().map(|p| (p.bus, p.device, p.function)) == address).collect();
        let times: Vec<i64> = members.iter().map(|e| e.unix_time).collect();
        let during = times.iter().any(|t| *t >= run_start);
        let when = when_text(&times, now, run_start);
        let ids = {
            let mut ids: Vec<u32> = members.iter().map(|e| e.id).collect();
            ids.sort();
            ids.dedup();
            ids.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ")
        };
        let source = format!("Windows event log, WHEA-Logger event {ids}");
        let (key, title, evidence, advice, floor) = match kind {
            HardwareKind::Memory => (
                "whea memory".to_string(),
                "Memory (RAM)  -  errors were detected and corrected".to_string(),
                format!("Corrected memory errors {when}. ({source}.)"),
                MEMORY_ERROR_ADVICE,
                Severity::Medium,
            ),
            HardwareKind::Processor => {
                let mut cpus: Vec<u32> = members.iter().filter_map(|e| e.apic_id).collect();
                cpus.sort();
                cpus.dedup();
                let on = match cpus.len() {
                    0 => String::new(),
                    1..=4 => {
                        format!(" Reported by logical processor {}.", cpus.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(", "))
                    }
                    n => format!(" Reported by {n} different logical processors."),
                };
                (
                    "whea processor".to_string(),
                    "Processor  -  hardware errors were detected and corrected".to_string(),
                    format!("Corrected processor errors (cache, bus or interconnect) {when}.{on} ({source}.)"),
                    PROCESSOR_ERROR_ADVICE,
                    Severity::Medium,
                )
            }
            HardwareKind::PciExpress => {
                let pci = members.iter().find_map(|e| e.pci.as_ref());
                let name = pci.and_then(|p| pci::describe(devices, p.bus, p.device, p.function, p.secondary_bus));
                let place = match (pci, &name) {
                    (Some(p), Some(n)) => format!("{n} (PCI bus {}, device {}, function {})", p.bus, p.device, p.function),
                    (Some(p), None) => format!(
                        "the device at PCI bus {}, device {}, function {}{}",
                        p.bus,
                        p.device,
                        p.function,
                        p.hardware_id.as_ref().map_or(String::new(), |h| format!(" [{h}]"))
                    ),
                    (None, _) => "a PCI Express device Windows did not identify".to_string(),
                };
                (
                    format!("whea pcie {address:?}"),
                    format!("{}  -  PCI Express link errors", name.unwrap_or_else(|| "PCI Express device".to_string())),
                    format!("Corrected PCI Express errors on {place}, {when}. ({source}.)"),
                    PCIE_ERROR_ADVICE,
                    // A handful per week is common and harmless; a stream of them is not.
                    if times.len() >= 3 { Severity::Medium } else { Severity::Low },
                )
            }
            HardwareKind::Fatal => (
                "whea fatal".to_string(),
                "Hardware error  -  it crashed or restarted this PC".to_string(),
                format!("A fatal hardware error was recorded {when}. ({source}.)"),
                FATAL_ERROR_ADVICE,
                Severity::Medium,
            ),
            HardwareKind::Other => continue,
        };
        // An error is handled in firmware while the rest of the PC waits, so a stall at the same
        // moment is cause and effect, not coincidence.
        let hits = coinciding(stalls, &times);
        let evidence = if hits > 0 {
            format!("{evidence} {hits} of this run's stalls / flagged moments happened within {COINCIDE_S} seconds of one of these errors.")
        } else {
            evidence
        };
        out.push(HardwareFinding {
            key,
            severity: if during { Severity::High } else { floor },
            title,
            evidence,
            advice,
            metrics: vec![
                Metric::flat("errors while monitoring", times.iter().filter(|t| **t >= run_start).count() as u32),
                Metric::logged("in the last 7 days", times.len() as u32),
            ],
        });
    }
    out
}

/// On a hybrid CPU, work that kept landing on the efficiency cores.
pub(super) fn e_cores(cx: &mut Ctx) {
    let hit: Vec<Vec<u16>> = cx.az.incidents.iter().map(|i| i.cpus.clone()).collect();
    if let Some((on_e, named, cores)) = e_core_concentration(&cx.az.topo, &hit) {
        let list = cores.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(", ");
        cx.found.add(
            "e-core stalls",
            Severity::Low,
            "Most stalls were on the processor's efficiency cores (E-cores)".into(),
            format!(
                "{on_e} of the {named} stalls held up an efficiency core (CPU {list}). This processor pairs those with faster \
                 performance cores (P-cores). Only programs running on the stalled cores were held up by these."
            ),
            ECORE_ADVICE.into(),
            0,
        );
    }
}

/// Hardware errors Windows logged (WHEA).
pub(super) fn whea(cx: &mut Ctx) {
    let (now_unix, run_start_unix) = (cx.now_unix, cx.run_start_unix);
    let hardware_log = evlog::hardware_events(EVENT_LOG_DAYS);
    if !hardware_log.is_empty() {
        // QPC -> wall clock, anchored at the instant both clocks were read in `Ctx::new`.
        let (qpc_now, freq) = (cx.now_qpc, qpc_freq());
        let wall = |ticks: i64| now_unix - (qpc_now - ticks) / freq;
        let stall_times: Vec<i64> = cx.az.incidents.iter().map(|i| wall(i.start)).collect();
        let whea_times: Vec<i64> = hardware_log.iter().filter(|e| e.kind != HardwareKind::Other).map(|e| e.unix_time).collect();
        for f in hardware_findings(&hardware_log, &pci::devices(), &stall_times, now_unix, run_start_unix) {
            cx.found.add(&f.key, f.severity, f.title, f.evidence, f.advice.to_string(), 0);
            for m in f.metrics {
                cx.found.measure(&f.key, m);
            }
        }
        // "The CPU went dark" is exactly what firmware handling a hardware error looks like.
        let dark: Vec<i64> = cx.az.incidents.iter().filter(|i| i.culprit.starts_with("CPU went dark")).map(|i| wall(i.start)).collect();
        let explained = coinciding(&dark, &whea_times);
        if explained > 0 {
            let keys: Vec<String> = cx.found.0.iter().map(|(k, _)| k.clone()).filter(|k| k.starts_with("CPU went dark")).collect();
            for key in keys {
                cx.found.note(
                    &key,
                    format!(
                        "{explained} of these happened within {COINCIDE_S} seconds of a hardware error Windows logged (see the hardware \
                         finding): the firmware was busy handling that error."
                    ),
                );
            }
        }
    }
    cx.hardware_log = hardware_log;
}

/// Times this PC went down without shutting down.
pub(super) fn unexpected_shutdowns(cx: &mut Ctx) {
    let now_unix = cx.now_unix;
    let shutdown_log = evlog::unexpected_shutdowns(EVENT_LOG_DAYS);
    let crashes = shutdown_log.iter().filter(|e| e.bugcheck != 0 || !e.power_button).count();
    if let Some((sev, text)) = shutdown_finding(&shutdown_log, now_unix) {
        // A fatal hardware error already explains a crash; otherwise it stands alone.
        if !cx.found.note("whea fatal", text.clone()) {
            cx.found.add("unexpected shutdowns", sev, "This PC crashed or lost power unexpectedly".into(), text, SHUTDOWN_ADVICE.into(), 0);
            cx.found.measure("unexpected shutdowns", Metric::logged("crashes in the last 7 days", crashes as u32));
        }
    }
    cx.crashes = crashes;
}

/// The processor being slowed down by heat or a power limit.
pub(super) fn cpu_throttling(cx: &mut Ctx) {
    let clock = cx.run.clock;
    let throttled: Vec<&ClockSample> = clock.iter().filter(|c| c.throttled()).collect();
    if throttled.len() >= 3.max(clock.len() / 20) {
        let near = ms_to_ticks(1500.0);
        let hits = cx.az.incidents.iter().filter(|i| throttled.iter().any(|c| (c.ts - i.start).abs() <= near)).count();
        let share = throttled.len() as f64 / clock.len() as f64;
        let sev = if share >= 0.3 || (hits >= 2 && hits * 2 >= cx.az.incidents.len()) { Severity::High } else { Severity::Medium };
        let slowest = throttled.iter().map(|c| c.min_busy_perf).fold(100.0, f64::min);
        let cap = throttled.iter().map(|c| c.limit).fold(100.0, f64::min);
        let mut evidence = format!(
            "In {} of {} seconds, cores that were busy ran at as little as {slowest:.0}% of their rated speed.",
            throttled.len(),
            clock.len()
        );
        if cap < 99.5 {
            evidence.push_str(&format!(" Windows reported an active performance cap down to {cap:.0}% (thermal or power limit)."));
        }
        if hits > 0 {
            evidence.push_str(&format!(" {hits} of {} stalls / flagged moments happened while it was throttled.", cx.az.incidents.len()));
        }
        cx.found.add(
            "throttling",
            sev,
            "CPU throttling  -  the processor is being slowed down".into(),
            evidence,
            THROTTLE_ADVICE.into(),
            ms_to_ticks(1000.0) * throttled.len() as i64,
        );
        // The clock is sampled once a second, so the count of throttled samples is seconds.
        cx.found.measure("throttling", Metric::secs("seconds throttled", throttled.len() as u32));
    }
    cx.throttled_secs = throttled.len();
}

/// Windows logs when firmware (not the OS) caps the processor.
pub(super) fn firmware_throttle(cx: &mut Ctx) {
    let (now_unix, run_start_unix) = (cx.now_unix, cx.run_start_unix);
    // so older entries only back up a throttling finding; one during the run stands by itself.
    let firmware_caps = evlog::firmware_throttle_times(EVENT_LOG_DAYS);
    let caps_during = firmware_caps.iter().filter(|t| **t >= run_start_unix).count();
    if !firmware_caps.is_empty() {
        let text = format!(
            "Windows event log: firmware limited the processor's speed (Kernel-Processor-Power event 37), {}.",
            when_text(&firmware_caps, now_unix, run_start_unix)
        );
        if cx.found.note("throttling", text.clone()) {
            if caps_during > 0 {
                cx.found.raise("throttling", Severity::High);
            }
        } else if caps_during > 0 {
            cx.found.add(
                "throttling",
                Severity::Medium,
                "CPU throttling  -  firmware is limiting the processor's speed".into(),
                text,
                THROTTLE_ADVICE.into(),
                0,
            );
            cx.found.measure("throttling", Metric::flat("firmware caps while monitoring", caps_during as u32));
            cx.found.measure("throttling", Metric::logged("in the last 7 days", firmware_caps.len() as u32));
        }
    }
    cx.firmware_caps = firmware_caps;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardware_errors_become_one_finding_per_component() {
        use crate::evlog::PciRef;
        let now = 2_000_000;
        let ev = |unix_time, id, kind, apic_id, pci| HardwareEvent { unix_time, id, kind, apic_id, pci };
        let port = PciRef { bus: 0, device: 1, function: 1, secondary_bus: Some(1), hardware_id: None };
        let events = vec![
            ev(now - 90_000, 47, HardwareKind::Memory, None, None),
            ev(now - 50, 47, HardwareKind::Memory, None, None),
            ev(now - 80_000, 19, HardwareKind::Processor, Some(11), None),
            ev(now - 70_000, 17, HardwareKind::PciExpress, None, Some(port.clone())),
            ev(now - 60_000, 17, HardwareKind::PciExpress, None, Some(port)),
            ev(now - 60_000, 5, HardwareKind::Other, None, None),
        ];
        let devices = vec![PciDevice { bus: 1, device: 0, function: 0, name: "NVIDIA GeForce RTX 4090".into() }];
        let f = hardware_findings(&events, &devices, &[now - 49, now - 300], now, now - 600);
        assert_eq!(f.len(), 3, "memory, processor, one PCIe address; 'other' ignored");

        let mem = f.iter().find(|f| f.key == "whea memory").unwrap();
        assert_eq!(mem.severity, Severity::High, "it fired while monitoring");
        assert!(
            mem.evidence.contains("2 times") && mem.evidence.contains("1 while monitoring") && mem.advice.contains("XMP"),
            "{}",
            mem.evidence
        );

        let cpu = f.iter().find(|f| f.key == "whea processor").unwrap();
        assert_eq!(cpu.severity, Severity::Medium);
        assert!(cpu.evidence.contains("logical processor 11"), "{}", cpu.evidence);

        let gpu = f.iter().find(|f| f.key.starts_with("whea pcie")).unwrap();
        assert_eq!(gpu.severity, Severity::Low, "two corrected link errors in a week is only a lead");
        assert!(
            gpu.title.starts_with("NVIDIA GeForce RTX 4090") && gpu.evidence.contains("PCI bus 0, device 1, function 1"),
            "{}",
            gpu.evidence
        );
        assert!(mem.evidence.contains("1 of this run's stalls / flagged moments happened within 2 seconds"), "{}", mem.evidence);
        assert!(!cpu.evidence.contains("within 2 seconds"), "no stall near the processor error");
        assert!(hardware_findings(&[], &devices, &[], now, now - 600).is_empty());
    }

    #[test]
    fn crashes_are_summarized_and_forced_power_offs_alone_are_not() {
        let now = 3_000_000;
        let ev = |ago, bugcheck, power_button| UnexpectedShutdown { unix_time: now - ago, bugcheck, power_button };
        let (sev, text) = shutdown_finding(&[ev(90_000, 0x9F, false), ev(200_000, 0, false), ev(300_000, 0, true)], now).unwrap();
        assert_eq!(sev, Severity::Medium);
        assert!(
            text.contains("2 times in the last 7 days") && text.contains("1 blue screen (stop code 0x9F DRIVER_POWER_STATE_FAILURE)"),
            "{text}"
        );
        assert!(text.contains("1 sudden restart or power loss with no blue screen") && !text.contains("while monitoring"), "{text}");
        assert_eq!(shutdown_finding(&[ev(100, 0x999, false)], now).unwrap().0, Severity::Low);
        assert!(shutdown_finding(&[ev(100, 0x999, false)], now).unwrap().1.contains("stop code 0x999)"));
        assert!(shutdown_finding(&[ev(100, 0, true)], now).is_none(), "held power button only");
        assert_eq!(coinciding(&[100, 200, 300], &[102, 297, 1000]), 1, "3 s apart is outside the window");
        assert_eq!(coinciding(&[100, 200, 300], &[102, 298, 1000]), 2);
    }

    // --- hybrid CPUs: stalls landing on the efficiency cores --------------------------------

    /// `p` performance cores then `e` efficiency cores, one group, no SMT.
    fn hybrid_topo(p: u8, e: u8) -> Topology {
        let sets: Vec<crate::topology::CpuSet> =
            (0..p + e).map(|i| crate::topology::CpuSet { group: 0, index: i, class: u8::from(i < p), core: i }).collect();
        Topology::build(&[(p + e) as u32], &sets)
    }

    #[test]
    fn stalls_concentrated_on_efficiency_cores_are_reported() {
        let topo = hybrid_topo(4, 4);
        let hit = vec![vec![5u16], vec![6], vec![7]];
        assert_eq!(e_core_concentration(&topo, &hit), Some((3, 3, vec![5, 6, 7])));
        // One in four on a P-core is 75%: under the 80% rule.
        let mixed = vec![vec![5u16], vec![6], vec![7], vec![1]];
        assert_eq!(e_core_concentration(&topo, &mixed), None);
        // A stall that hit a P-core as well as an E-core does not count as an E-core stall.
        assert_eq!(e_core_concentration(&topo, &[vec![5, 1], vec![6], vec![7]]), None);
    }

    #[test]
    fn too_few_stalls_or_no_cpu_is_not_a_pattern() {
        let topo = hybrid_topo(4, 4);
        assert_eq!(e_core_concentration(&topo, &[vec![5u16], vec![6]]), None);
        // CPU-starvation stalls name no CPU at all.
        assert_eq!(e_core_concentration(&topo, &[vec![], vec![], vec![]]), None);
    }

    #[test]
    fn nothing_is_said_about_cores_on_a_uniform_cpu() {
        let topo = Topology::build(&[8], &[]);
        assert_eq!(e_core_concentration(&topo, &[vec![5u16], vec![6], vec![7]]), None);
        assert_eq!(e_core_concentration(&Topology::default(), &[vec![0u16], vec![0], vec![0]]), None);
    }

    /// With 2 P-cores and 6 E-cores, stalls land on an E-core simply because most cores are.
    #[test]
    fn e_cores_in_the_majority_prove_nothing() {
        let topo = hybrid_topo(2, 6);
        assert_eq!(e_core_concentration(&topo, &[vec![3u16], vec![4], vec![5], vec![6]]), None);
    }
}
