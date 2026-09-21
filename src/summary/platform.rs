//! What this PC is made of that a trace cannot show: utilities that talk to the motherboard
//! hardware directly, network filter drivers from other vendors, and devices on an old-style
//! shared interrupt.
//!
//! All three are observations, never verdicts. Each is Low on its own - the development PC runs six
//! hardware-access drivers and has three devices on legacy interrupts, and it is healthy - and each
//! is attached as EVIDENCE to the findings it could explain, labeled as context rather than blame.
//!
//! The live reads are in the three `pub(super)` entry points; everything that decides what the
//! report SAYS is a pure function below them, so it can be tested without this machine.

use crate::devices::DeviceMap;
use crate::hwaccess::{self, Found};
use crate::interrupts::{self, IrqMode, MsiOptIn, PciInterrupt, Support};
use crate::netfilters::{self, NetFilter};
use crate::util::plural;

use super::ctx::Ctx;
use super::freezes::FREEZE_KEY;
use super::{Findings, Metric, Severity};

pub(super) const HW_TOOLS_KEY: &str = "hardware-access tools";
pub(super) const LEGACY_IRQ_KEY: &str = "legacy interrupts";

/// Every sentence here comes from a primary source. The mechanism: an I/O write by such a tool can
/// be trapped by the chipset and turned into a System Management Interrupt (Intel 9 Series PCH
/// datasheet, SMI_EN: "Enables PCH to trap accesses to the microcontroller range (62h or 66h) and
/// generate an SMI#"; ACPI 6.5 s5.2.9 makes the SMI command port architectural). On a UEFI PC,
/// servicing one is a full processor rendezvous - Intel's "A Tour Beyond BIOS" white paper: "The
/// BSP/APs will rendezvous to make sure all processors are running at the same point ... all
/// processors will rendezvous again and execute the RSM instruction". The consequence is
/// Microsoft's own, from *Network Adapter Performance Tuning in Windows Server*: "this behavior can
/// result in latency spikes of 100 microseconds or more" and "The operating system can't control
/// SMIs because the logical processor is running in a special maintenance mode, which prevents
/// operating system intervention."
///
/// Note what is NOT here: no duration threshold. Microsoft publishes no limit on how long one of
/// these pauses may take, so the report quotes the one number Microsoft does publish and invents
/// none of its own.
/// What the finding says when nothing in the report could be explained by it: most enthusiast PCs
/// run a few of these and are fine (the development PC runs six and measures clean).
const QUIET_NOTE: &str = "Common on a PC with RGB, fan or monitoring software, and not a problem by itself: nothing in this run \
    points at them. They matter only if a report ever shows the whole PC stopping, stalls that repeat on a timer, or a processor \
    going dark. The full list, and who named each driver, is in DETAILS.";

const HOW_IT_STOPS_A_PC: &str = "Software like this reaches motherboard chips directly - sensor, fan and lighting controllers - \
    instead of going through Windows. When that happens the motherboard can hand control to its own firmware for a moment, and \
    while the firmware works it typically stops every processor core (the firmware gathers them all before it proceeds; the \
    processor itself does not require that): Windows can neither interrupt it nor see it happening. Microsoft \
    describes these pauses as spikes of 100 microseconds or more, and says Windows has no way to intervene.";

/// ACPI 6.5 s12.1: access to the shared embedded-controller interface "requires the Global Lock
/// semaphore overhead to arbitrate ownership", and s12.9 calls what happens without it "contentious
/// accesses". Linux's own i2c-i801 driver permanently disables its own access the moment it sees
/// firmware using the same registers ("BIOS is accessing SMBus registers" / "Driver SMBus register
/// access inhibited"). OpenRGB's documentation: "The SMBus only works properly if one application at
/// a time is accessing it, and if two applications try to control the device at the same time, it
/// can confuse the device or put it in an invalid state."
///
/// Deliberately absent: which named products conflict with which. That is forum lore.
const SHARING_IS_THE_PROBLEM: &str = "These chips are shared with the firmware, and the specification that governs them has a lock \
    for taking turns - which a tool reaching past Windows takes no part in. The specification's own word for what happens then is \
    'contentious accesses', and the projects that write this kind of software document that only one program at a time can safely \
    use the bus. One of these running is normal; several at once is a documented problem.";

const HONEST_LIMIT: &str = "This tool cannot prove any of that happened here. Reading the processor's own count of those firmware \
    pauses needs a kernel driver, and this tool deliberately ships none - which is also why it is not adding another of these \
    drivers to your PC.";

// ---------------------------------------------------------------------------------------------
// Utilities that talk to the motherboard hardware directly
// ---------------------------------------------------------------------------------------------

/// What is loaded right now, from the sourced table in `hwaccess`.
pub(super) fn hardware_access(cx: &mut Ctx) {
    let found = hwaccess::present(&cx.az.modules.file_names());
    hw_tools_table(&mut cx.platform_lines, &found);
    note_hardware_tools(&mut cx.found, &found);
}

/// Low by itself, always: six of these are loaded on the development PC, which runs clean. They are
/// listed because this is one of the few things software can do that stops every processor core at
/// once, and because the rest of the report can then name the actual products instead of reciting a
/// generic list of brand names at someone who may run none of them.
fn note_hardware_tools(found: &mut Findings, tools: &[Found]) {
    let (direct, sandboxed): (Vec<&Found>, Vec<&Found>) = tools.iter().partition(|f| !f.tool.sandboxed);
    if direct.is_empty() {
        // Still worth a sentence when only the sandboxed one is there: it is the answer to "should
        // I remove my fan software", and the answer is no.
        if !sandboxed.is_empty() {
            found.add(
                HW_TOOLS_KEY,
                Severity::Low,
                "Your monitoring or fan software uses the sandboxed hardware driver".into(),
                format!(
                    "{} is loaded. That is the sandboxed driver LibreHardwareMonitor, FanControl and OpenRGB moved to, rather than \
                     the raw hardware access those tools used to install.",
                    files(&sandboxed)
                ),
                "Nothing to do: this is the safer of the two ways these tools work.".into(),
                0,
            );
            found.measure(HW_TOOLS_KEY, Metric::flat("hardware-access drivers", 0));
        }
        return;
    }

    let n = direct.len();
    let list = direct.iter().map(|f| f.label()).collect::<Vec<_>>().join(", ");
    let act = format!(
        "The utilities of that kind running on this PC are {}: fully exit them one at a time (not just close the window), \
         monitoring again after each.",
        products(&direct)
    );
    found.add(
        HW_TOOLS_KEY,
        Severity::Low,
        if n == 1 {
            "1 program that talks to the hardware directly is running".to_string()
        } else {
            format!("{n} programs that talk to the hardware directly are running")
        },
        format!("These kernel drivers are loaded right now: {list}."),
        format!("Nothing here needs changing on its own. If the report above shows the whole PC stopping, stalls that keep time, or a processor going dark: {act}"),
        0,
    );
    // Which findings this could be context for. Decided before the explanation is attached: on a
    // PC where nothing of the kind showed up, three paragraphs about firmware are noise on the
    // first screen of a clean report, and one sentence is the honest size for it.
    let keys: Vec<String> = found
        .0
        .iter()
        .filter(|(k, f)| {
            k == FREEZE_KEY
                || k.starts_with("CPU went dark")
                || k == "periodic"
                || k.starts_with("timer ")
                // A driver finding that repeats on a timer had the generic "the usual suspects poll
                // hardware sensors" list appended to it; name the ones actually here instead.
                || f.evidence.iter().any(|e| e.contains("keep time"))
        })
        .map(|(k, _)| k.clone())
        .collect();
    if keys.is_empty() {
        found.note(HW_TOOLS_KEY, QUIET_NOTE.to_string());
    } else {
        for line in [HOW_IT_STOPS_A_PC, SHARING_IS_THE_PROBLEM, HONEST_LIMIT] {
            found.note(HW_TOOLS_KEY, line.to_string());
        }
    }
    if !sandboxed.is_empty() {
        found.note(
            HW_TOOLS_KEY,
            format!(
                "Not counted above: {} is the sandboxed driver that current versions of LibreHardwareMonitor, FanControl and OpenRGB \
                 use instead. That one is the safer way round.",
                files(&sandboxed)
            ),
        );
    }
    found.measure(HW_TOOLS_KEY, Metric::flat("hardware-access drivers", n as u32));

    // ...and as context on everything it could explain. Evidence, never blame: nothing in the
    // trace ties these drivers to any of it, and the wording has to keep saying so.
    let context = format!(
        "Context, not blame: {} that {} to the motherboard hardware directly {} running here ({list}). That is one of the few \
         things software can do that stops every processor core at once, and Windows cannot see it happen - but nothing in this \
         trace shows that it did.",
        if n == 1 { "1 program".to_string() } else { format!("{n} programs") },
        if n == 1 { "talks" } else { "talk" },
        if n == 1 { "is" } else { "are" },
    );
    for key in keys {
        found.note(&key, context.clone());
        found.advise(&key, &act);
    }
}

/// "SignalRGB, MSI Center and HWiNFO"
fn products(found: &[&Found]) -> String {
    and_list(&found.iter().map(|f| f.tool.product).collect::<Vec<_>>(), usize::MAX)
}

fn files(found: &[&Found]) -> String {
    found.iter().map(|f| f.file.clone()).collect::<Vec<_>>().join(", ")
}

fn hw_tools_table(out: &mut Vec<String>, found: &[Found]) {
    if found.is_empty() {
        return;
    }
    out.push(String::new());
    out.push("PROGRAMS THAT TALK TO THE HARDWARE DIRECTLY  (loaded kernel drivers)".into());
    out.push(format!("  {:<26} {:<46} {}", "driver file", "product", "named by"));
    for f in found {
        out.push(format!("  {:<26} {:<46} {}", f.file, f.tool.product, f.tool.source.label()));
        out.push(format!("  {:<26} {} - {}", "", f.tool.vendor, f.tool.access));
    }
}

// ---------------------------------------------------------------------------------------------
// Network filter drivers
// ---------------------------------------------------------------------------------------------

/// Network filter drivers from other vendors, and what they mean for a stall blamed on one of
/// Windows' own networking files.
///
/// No finding of its own: an installed VPN or security product is not news. It becomes evidence
/// only when something in Windows' network path is actually being blamed.
pub(super) fn network_filters(cx: &mut Ctx) {
    let filters = netfilters::filters();
    filter_table(&mut cx.platform_lines, &filters);
    note_network_filters(&mut cx.found, &filters);
}

fn note_network_filters(found: &mut Findings, filters: &[NetFilter]) {
    if filters.is_empty() {
        return;
    }
    let others: Vec<&NetFilter> = filters.iter().filter(|f| f.vendor.third_party()).collect();
    let hosts: Vec<String> =
        found.0.iter().map(|(k, _)| k.clone()).filter(|k| k.strip_prefix("driver ").is_some_and(netfilters::hosts_filters)).collect();
    for key in hosts {
        if others.is_empty() {
            // Ruling something out is worth as much as naming it, and cheaper to act on.
            found.note(
                &key,
                format!(
                    "All {} network filter driver{} installed on this PC are Microsoft's own, so no other vendor's filter is \
                     running inside this file: a VPN, a 'network optimizer' or a security product's network filter is not what is \
                     doing this work.",
                    filters.len(),
                    plural(filters.len() as u64)
                ),
            );
            continue;
        }
        let list = others.iter().map(|f| f.label()).collect::<Vec<_>>().join(", ");
        let caveat = if others.iter().any(|f| f.vendor.guessed()) {
            " (for some of these the driver file could not be read, so who wrote it is judged by the name Windows gave the component)"
        } else {
            ""
        };
        found.note(
            &key,
            format!(
                "Network filter drivers from other vendors are installed on this PC: {list}{caveat}. Windows runs a filter's code \
                 inside its own networking files, so work done by one of those is attributed to Windows here. Which one it was is \
                 not something this trace can say."
            ),
        );
        found.advise(
            &key,
            &format!(
                "Because another vendor's network filter is installed ({list}), turn that off or uninstall it and monitor again: a \
                 VPN, a 'gaming network optimizer' and a security product's network filter all sit in this same path."
            ),
        );
    }
}

fn filter_table(out: &mut Vec<String>, filters: &[NetFilter]) {
    if filters.is_empty() {
        return;
    }
    out.push(String::new());
    out.push("NETWORK FILTER DRIVERS  (they sit in the path of every packet)".into());
    out.push(format!("  {:<22} {:<16} {:<22} {}", "component", "service", "driver file", "written by"));
    for f in filters {
        let who = match &f.company {
            Some(c) => c.clone(),
            None if f.vendor.third_party() => "not Microsoft (judged by name)".to_string(),
            None => "Microsoft (judged by name)".to_string(),
        };
        out.push(format!("  {:<22} {:<16} {:<22} {who}", f.component_id, f.service, f.file.as_deref().unwrap_or("-")));
    }
}

// ---------------------------------------------------------------------------------------------
// Devices on an old-style shared interrupt
// ---------------------------------------------------------------------------------------------

/// Microsoft publishes no warning about forcing message-signaled interrupts on, and no
/// encouragement either. A PC maker publishes the opposite case: Dell documents an SSD that "does
/// not properly complete input/output operations when Message Signaled Interrupt (MSI) mode is
/// enabled in Windows 10", with "Change the value of the MSISupported key from 1 to 0" as the fix.
/// Everything else - devices failing to start, machines not booting - is community reporting only.
/// So this recommends the two supported changes, and mentions the registry only to say what it can
/// cost and how to get back from it.
const LEGACY_IRQ_ADVICE: &str = "This is normally the device maker's own choice, recorded by the driver when it was installed, so \
    the two safe and supported ways to change it are to install the current driver for the device from the maker's website, and to \
    check for a BIOS/UEFI update for your PC. Either can change this the way it was meant to be changed. You will find guides online \
    that switch it by editing the Windows registry instead: this report does not recommend that. Microsoft documents no such change, \
    at least one PC maker has published a case where turning it on stopped a drive working properly, and a device - or the PC - can \
    fail to start afterwards. If you ever do try it, write the original value down first so you can put it back.";

pub(super) fn legacy_interrupts(cx: &mut Ctx) {
    let devices = interrupts::devices();
    let legacy: Vec<PciInterrupt> = devices.iter().filter(|d| d.legacy_despite_hardware()).cloned().collect();
    irq_table(&mut cx.platform_lines, &devices, &legacy);
    let device_map = std::mem::take(&mut cx.device_map);
    note_legacy_interrupts(&mut cx.found, &device_map, &legacy);
    cx.device_map = device_map;
}

fn note_legacy_interrupts(found: &mut Findings, device_map: &DeviceMap, legacy: &[PciInterrupt]) {
    if legacy.is_empty() {
        return;
    }
    let n = legacy.len();
    let names: Vec<&str> = legacy.iter().map(|d| d.name.as_str()).collect();
    found.add(
        LEGACY_IRQ_KEY,
        Severity::Low,
        format!("{n} device{} {} using an old-style shared interrupt", plural(n as u64), if n == 1 { "is" } else { "are" }),
        format!(
            "{} {} on a line-based interrupt: the older way hardware gets the processor's attention, where the signal line can be \
             shared with other devices and Windows has to ask each of them in turn whose interrupt it was. The newer kind gives a \
             device a line of its own. The hardware in {} says it can do the newer kind as well.",
            and_list(&names, 3),
            if n == 1 { "is" } else { "are" },
            if n == 1 { "this device" } else { "each of these" }
        ),
        LEGACY_IRQ_ADVICE.to_string(),
        0,
    );
    if let Some(line) = opt_in_line(legacy) {
        found.note(LEGACY_IRQ_KEY, line);
    }
    found.note(
        LEGACY_IRQ_KEY,
        "Nothing in this run measured a delay caused by this, and this tool cannot measure one. It is here because you asked what \
         is unusual about this PC, not because it is stalling anything."
            .to_string(),
    );
    found.measure(LEGACY_IRQ_KEY, Metric::flat("devices on a shared interrupt", n as u32));

    // On a driver finding whose own device is one of these: one more fact about that device.
    let drivers: Vec<String> = found.0.iter().map(|(k, _)| k.clone()).filter(|k| k.starts_with("driver ")).collect();
    for key in drivers {
        let Some(file) = key.strip_prefix("driver ") else { continue };
        let mine: Vec<&str> =
            device_map.get(file).iter().filter(|d| legacy.iter().any(|l| l.name == d.device)).map(|d| d.device.as_str()).collect();
        if mine.is_empty() {
            continue;
        }
        found.note(
            &key,
            format!(
                "Its device ({}) is using an old-style shared interrupt, although the hardware also offers the newer \
                 message-signaled kind. See the finding about that below: the safe fix is a current driver from the device maker or \
                 a BIOS update, not a registry edit.",
                and_list(&mine, 3)
            ),
        );
    }
}

/// What the registry records about the opt-in, across the devices found.
///
/// The three states stay three states. Microsoft documents `MSISupported = 1` and nothing else: no
/// meaning for a 0, and no default for the key being absent. So "no setting at all" is never
/// rendered as "disabled", and neither is called "non-default".
fn opt_in_line(legacy: &[PciInterrupt]) -> Option<String> {
    let off = legacy.iter().filter(|d| d.opt_in == MsiOptIn::TurnedOff).count();
    let none = legacy.iter().filter(|d| d.opt_in == MsiOptIn::NotRecorded).count();
    let n = legacy.len();
    let mut parts = Vec::new();
    if off > 0 {
        parts.push(format!(
            "on {off} of {n}, Windows holds a setting that switches the newer kind off for that device - someone, or the driver \
             package itself, wrote that deliberately"
        ));
    }
    if none > 0 {
        parts.push(format!(
            "on {none} of {n} there is no such setting at all, which means the driver package never asked for the newer kind, not \
             that anything turned it off"
        ));
    }
    (!parts.is_empty()).then(|| format!("{}.", capitalize(&parts.join("; "))))
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// "A, B and C", capped at `max` names so one line cannot run away on a big machine.
fn and_list(names: &[&str], max: usize) -> String {
    let shown: Vec<&str> = names.iter().copied().take(max).collect();
    let more = names.len() - shown.len();
    let joined = match shown.split_last() {
        Some((last, [])) => (*last).to_string(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
        None => String::new(),
    };
    if more > 0 {
        format!("{joined} and {more} more")
    } else {
        joined
    }
}

fn irq_table(out: &mut Vec<String>, devices: &[PciInterrupt], legacy: &[PciInterrupt]) {
    if devices.is_empty() {
        return;
    }
    out.push(String::new());
    out.push(format!(
        "DEVICE INTERRUPTS  ({} of {} devices use message-signaled interrupts, {} an old-style shared line)",
        devices.iter().filter(|d| d.mode == IrqMode::Message).count(),
        devices.len(),
        devices.iter().filter(|d| d.mode == IrqMode::LineBased).count()
    ));
    if legacy.is_empty() {
        out.push("  No device is on a shared line while its own hardware offers the newer kind.".into());
        return;
    }
    out.push(format!("  {:<44} {:<14} {:<20} {}", "device", "in use", "hardware offers", "Windows setting"));
    for d in legacy {
        out.push(format!(
            "  {:<44} {:<14} {:<20} {}",
            d.name.chars().take(44).collect::<String>(),
            "shared line",
            match d.support {
                Support::HasMessage => "message-signaled",
                Support::LineOnly => "shared line only",
                Support::Unknown => "not known",
            },
            match d.opt_in {
                MsiOptIn::TurnedOff => "switched off for this device",
                MsiOptIn::TurnedOn => "switched on (yet not in use)",
                MsiOptIn::NotRecorded => "never asked for",
                MsiOptIn::Other => "an unrecognized value",
            }
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::DeviceDriver;
    use crate::netfilters::Vendor;
    use crate::summary::Group;

    fn tools(files: &[&str]) -> Vec<Found> {
        hwaccess::present(&files.iter().map(|f| f.to_string()).collect::<Vec<_>>())
    }

    fn get<'a>(found: &'a Findings, key: &str) -> &'a super::super::Finding {
        &found.0.iter().find(|(k, _)| k == key).unwrap_or_else(|| panic!("no finding {key}")).1
    }

    /// A synthetic freeze plus a synthetic module list: the hardware-access tools have to arrive on
    /// it as context, name the real products in the advice, and stay Low themselves.
    #[test]
    fn hardware_tools_land_on_a_freeze_as_context_and_never_as_blame() {
        let mut found = Findings::default();
        found.in_group(Group::WholePc);
        found.add(FREEZE_KEY, Severity::High, "The whole PC stopped responding, 12 times".into(), "e".into(), "Try things.".into(), 0);
        found.in_group(Group::Health);
        note_hardware_tools(&mut found, &tools(&["SignalIo.sys", "HWiNFO_x64_215.sys", "ndis.sys"]));

        let t = get(&found, HW_TOOLS_KEY);
        assert_eq!(t.severity, Severity::Low, "six of these run on a healthy PC: this must never flip the banner");
        assert_eq!(t.group, Group::Health);
        assert_eq!(t.title, "2 programs that talk to the hardware directly are running");
        let said = t.evidence.join(" ");
        assert!(said.contains("SignalRGB (SignalIo.sys)") && said.contains("HWiNFO / HWiNFO64 (HWiNFO_x64_215.sys)"), "{said}");
        // "typically": the all-core stop is the firmware's rendezvous, not something the processor requires.
        assert!(said.contains("typically stops every processor core"), "the verified mechanism: {said}");
        assert!(said.contains("100 microseconds or more"), "Microsoft's own number, and the only one: {said}");
        assert!(said.contains("contentious accesses"), "the specification's own word: {said}");
        assert!(said.contains("cannot prove"), "the limit is stated plainly: {said}");
        assert!(t.advice.contains("HWiNFO / HWiNFO64 and SignalRGB"), "the advice names the products found: {}", t.advice);

        let freeze = get(&found, FREEZE_KEY);
        assert_eq!(freeze.severity, Severity::High, "context must not change the freeze's severity");
        let line = freeze.evidence.iter().find(|e| e.contains("motherboard hardware directly")).expect("context on the freeze");
        assert!(line.starts_with("Context, not blame:"), "{line}");
        assert!(line.contains("nothing in this trace shows that it did"), "{line}");
        assert!(freeze.advice.contains("HWiNFO / HWiNFO64 and SignalRGB"), "the freeze advice names them too: {}", freeze.advice);
        assert!(freeze.advice.starts_with("Try things."), "and it is appended, not substituted: {}", freeze.advice);
    }

    /// The same context, on the two other findings it can explain.
    #[test]
    fn a_dark_cpu_and_a_periodic_finding_get_the_same_context() {
        let mut found = Findings::default();
        found.add("CPU went dark (firmware SMI / hypervisor / interrupts off)", Severity::High, "t".into(), "e".into(), "a".into(), 0);
        found.add("periodic", Severity::Medium, "Stalls repeat on a timer".into(), "e".into(), "a".into(), 0);
        found.add("driver NETIO.SYS", Severity::Medium, "t".into(), "The stalls keep time.".into(), "a".into(), 0);
        found.add("driver other.sys", Severity::Medium, "t".into(), "Blamed for 3 stalls.".into(), "a".into(), 0);
        note_hardware_tools(&mut found, &tools(&["AsIO3.sys"]));

        for key in ["CPU went dark (firmware SMI / hypervisor / interrupts off)", "periodic", "driver NETIO.SYS"] {
            let f = get(&found, key);
            assert!(f.evidence.iter().any(|e| e.starts_with("Context, not blame:")), "{key}: {:?}", f.evidence);
            assert!(f.advice.contains("ASUS Armoury Crate / AI Suite"), "{key}: {}", f.advice);
        }
        let other = get(&found, "driver other.sys");
        assert!(!other.evidence.iter().any(|e| e.contains("Context, not blame")), "an unrelated finding is left alone");
        // One program: the sentence has to read as English, not "1 programs ... are running".
        let t = get(&found, HW_TOOLS_KEY);
        assert_eq!(t.title, "1 program that talks to the hardware directly is running");
        assert!(t.evidence[0].contains("ASUS Armoury Crate / AI Suite (AsIO3.sys)"), "{:?}", t.evidence);
    }

    #[test]
    fn a_clean_pc_and_the_sandboxed_driver_are_reported_differently() {
        let mut found = Findings::default();
        note_hardware_tools(&mut found, &tools(&["ndis.sys", "nvlddmkm.sys"]));
        assert!(found.0.is_empty(), "no hardware-access driver, no finding");

        let mut found = Findings::default();
        note_hardware_tools(&mut found, &tools(&["PawnIO.sys"]));
        let f = get(&found, HW_TOOLS_KEY);
        assert_eq!(f.severity, Severity::Low);
        assert!(f.title.contains("sandboxed"), "{}", f.title);
        assert!(f.advice.contains("Nothing to do"), "{}", f.advice);

        // Alongside a raw one, the sandboxed driver is mentioned but not counted or blamed.
        let mut found = Findings::default();
        note_hardware_tools(&mut found, &tools(&["PawnIO.sys", "AsIO3.sys"]));
        let f = get(&found, HW_TOOLS_KEY);
        assert_eq!(f.title, "1 program that talks to the hardware directly is running");
        assert!(f.evidence.iter().any(|e| e.contains("Not counted above: PawnIO.sys")), "{:?}", f.evidence);
        assert!(!f.advice.contains("PawnIO"), "nobody is told to exit the safe one: {}", f.advice);
    }

    // --- network filters ------------------------------------------------------------------------

    fn filter(id: &str, file: &str, company: Option<&str>) -> NetFilter {
        NetFilter {
            component_id: id.into(),
            service: id.trim_start_matches("ms_").into(),
            file: Some(file.into()),
            company: company.map(String::from),
            vendor: netfilters::classify(id, company),
        }
    }

    #[test]
    fn a_third_party_filter_becomes_evidence_on_the_windows_file_that_hosts_it() {
        let mut found = Findings::default();
        found.add("driver NETIO.SYS", Severity::Medium, "t".into(), "Blamed for 55 stalls.".into(), "Update the NIC driver.".into(), 0);
        found.add("driver nvlddmkm.sys", Severity::Medium, "t".into(), "e".into(), "a".into(), 0);
        note_network_filters(
            &mut found,
            &[filter("ms_pacer", "pacer.sys", Some("Microsoft Corporation")), filter("nordlwf", "nordlwf.sys", Some("NordVPN S.A."))],
        );
        let f = get(&found, "driver NETIO.SYS");
        let said = f.evidence.join(" ");
        assert!(said.contains("nordlwf.sys (NordVPN S.A.)"), "{said}");
        assert!(!said.contains("pacer.sys"), "Microsoft's own filters are not paraded as suspects: {said}");
        assert!(said.contains("Which one it was is not something this trace can say"), "{said}");
        assert!(f.advice.contains("nordlwf.sys (NordVPN S.A.)") && f.advice.starts_with("Update the NIC driver."), "{}", f.advice);
        assert!(!get(&found, "driver nvlddmkm.sys").evidence.iter().any(|e| e.contains("filter")), "the GPU driver hosts no filters");
    }

    #[test]
    fn all_microsoft_filters_rule_something_out_instead() {
        let mut found = Findings::default();
        found.add("driver ndis.sys", Severity::Medium, "t".into(), "e".into(), "a".into(), 0);
        note_network_filters(
            &mut found,
            &[filter("ms_pacer", "pacer.sys", Some("Microsoft Corporation")), filter("ms_ndiscap", "ndiscap.sys", None)],
        );
        let said = get(&found, "driver ndis.sys").evidence.join(" ");
        assert!(said.contains("All 2 network filter drivers installed on this PC are Microsoft's own"), "{said}");
        assert!(said.contains("is not what is doing this work"), "{said}");
    }

    /// When the vendor had to be guessed from a name, the sentence says so.
    #[test]
    fn a_guessed_vendor_is_admitted_in_the_evidence() {
        let mut found = Findings::default();
        found.add("driver tcpip.sys", Severity::Medium, "t".into(), "e".into(), "a".into(), 0);
        let mut unreadable = filter("somevpnlwf", "somevpn.sys", None);
        assert_eq!(unreadable.vendor, Vendor::GuessedThirdParty);
        unreadable.company = None;
        note_network_filters(&mut found, &[unreadable]);
        let said = get(&found, "driver tcpip.sys").evidence.join(" ");
        assert!(said.contains("judged by the name Windows gave the component"), "{said}");
    }

    // --- legacy interrupts ----------------------------------------------------------------------

    fn dev(name: &str, support: Support, opt_in: MsiOptIn) -> PciInterrupt {
        PciInterrupt { instance_id: format!("PCI\\{name}"), name: name.into(), mode: IrqMode::LineBased, support, opt_in, allocations: 1 }
    }

    #[test]
    fn lists_read_as_english_and_never_run_away() {
        assert_eq!(and_list(&["A"], 3), "A");
        assert_eq!(and_list(&["A", "B"], 3), "A and B");
        assert_eq!(and_list(&["A", "B", "C"], 3), "A, B and C");
        assert_eq!(and_list(&["A", "B", "C", "D", "E"], 3), "A, B and C and 2 more");
        assert_eq!(and_list(&[], 3), "");
    }

    /// The three registry states stay three states: "no setting" is never called "turned off".
    #[test]
    fn the_msi_opt_in_is_described_without_inventing_a_default() {
        let line = opt_in_line(&[dev("X", Support::HasMessage, MsiOptIn::TurnedOff)]).unwrap();
        assert!(line.contains("switches the newer kind off") && line.contains("deliberately"), "{line}");
        let line = opt_in_line(&[dev("X", Support::HasMessage, MsiOptIn::NotRecorded)]).unwrap();
        assert!(line.contains("never asked for the newer kind") && line.contains("not that anything turned it off"), "{line}");
        assert!(!line.contains("default") && !line.contains("disabled"), "Microsoft documents neither: {line}");
        assert_eq!(opt_in_line(&[dev("X", Support::HasMessage, MsiOptIn::TurnedOn)]), None, "nothing to say, so nothing is said");
        assert_eq!(opt_in_line(&[]), None);
    }

    /// The real shape of the development PC: three HD Audio functions, all with the opt-out written.
    #[test]
    fn the_finding_describes_what_is_known_and_stays_low() {
        let mut found = Findings::default();
        found.in_group(Group::Health);
        note_legacy_interrupts(
            &mut found,
            &DeviceMap::default(),
            &[
                dev("High Definition Audio Bus", Support::HasMessage, MsiOptIn::TurnedOff),
                dev("High Definition Audio Controller", Support::HasMessage, MsiOptIn::TurnedOff),
                dev("AMD High Definition Audio Device", Support::HasMessage, MsiOptIn::TurnedOff),
            ],
        );
        let f = get(&found, LEGACY_IRQ_KEY);
        assert_eq!((f.severity, f.group), (Severity::Low, Group::Health));
        assert_eq!(f.title, "3 devices are using an old-style shared interrupt");
        let said = f.evidence.join(" ");
        assert!(said.contains("High Definition Audio Bus, High Definition Audio Controller and AMD High"), "{said}");
        assert!(said.contains("can do the newer kind as well"), "the hardware half is stated: {said}");
        assert!(!said.contains("supports MSI"), "never jargon, and never a claim beyond what was read: {said}");
        assert!(said.contains("cannot measure one"), "no performance claim is made: {said}");
        assert!(f.advice.contains("does not recommend"), "{}", f.advice);
        assert!(found.0.iter().all(|(_, f)| f.severity == Severity::Low));
    }

    /// The whole point of the advice, and the thing a test must hold it to.
    #[test]
    fn the_interrupt_advice_leads_with_the_safe_fixes_and_warns_about_the_registry() {
        let a = LEGACY_IRQ_ADVICE;
        assert!(a.contains("current driver") && a.contains("BIOS/UEFI update"), "the safe fixes come first: {a}");
        let at = |needle: &str| a.find(needle).unwrap_or(usize::MAX);
        assert!(at("current driver") < at("registry"), "the registry is never the first thing offered");
        assert!(a.contains("does not recommend"), "{a}");
        assert!(a.contains("fail to start") && a.contains("put it back"), "mentioning the registry costs a warning and a way back");
        assert!(!a.contains("MSISupported") && !a.contains("regedit"), "no recipe a non-technical reader could follow by accident");
    }

    #[test]
    fn a_devices_shared_interrupt_shows_up_on_its_drivers_finding() {
        let mut found = Findings::default();
        found.add("driver hdaudbus.sys", Severity::Medium, "hdaudbus.sys  -  audio".into(), "e".into(), "a".into(), 0);
        found.add("driver nvlddmkm.sys", Severity::Medium, "nvlddmkm.sys  -  GPU".into(), "e".into(), "a".into(), 0);
        let mut map = DeviceMap::default();
        map.insert_for_test("hdaudbus.sys", vec![DeviceDriver { device: "High Definition Audio Bus".into(), ..Default::default() }]);
        map.insert_for_test("nvlddmkm.sys", vec![DeviceDriver { device: "NVIDIA GeForce RTX 5090".into(), ..Default::default() }]);
        note_legacy_interrupts(&mut found, &map, &[dev("High Definition Audio Bus", Support::HasMessage, MsiOptIn::TurnedOff)]);

        let audio = get(&found, "driver hdaudbus.sys");
        assert!(audio.evidence.iter().any(|e| e.contains("old-style shared interrupt")), "{:?}", audio.evidence);
        assert!(audio.evidence.iter().any(|e| e.contains("not a registry edit")), "{:?}", audio.evidence);
        assert!(!get(&found, "driver nvlddmkm.sys").evidence.iter().any(|e| e.contains("shared interrupt")));
    }

    #[test]
    fn nothing_to_report_means_nothing_is_reported() {
        let mut found = Findings::default();
        note_legacy_interrupts(&mut found, &DeviceMap::default(), &[]);
        note_network_filters(&mut found, &[]);
        assert!(found.0.is_empty());
    }

    /// Reads this machine's own state and prints it. Nothing is asserted: a CI runner has none of
    /// it, and a non-elevated session cannot see loaded kernel modules at all.
    #[test]
    fn what_this_pc_actually_has() {
        use crate::modules::ModuleMap;
        let loaded = ModuleMap::load().file_names();
        println!(
            "{} kernel modules loaded (0 means this session is not elevated: Windows hides kernel addresses below high IL)",
            loaded.len()
        );
        for f in hwaccess::present(&loaded) {
            println!("  hardware access: {:<28} {:<46} {}", f.file, f.tool.product, f.tool.source.label());
        }
        // Cross-check the same table against the REGISTERED drivers, which a normal session can
        // read. Not what the feature uses - a registered driver need not be loaded - but it is the
        // only way to exercise the table's matching against real file names without elevation.
        let mut registered: Vec<String> = Vec::new();
        for service in crate::reg::subkeys(r"SYSTEM\CurrentControlSet\Services") {
            if let Some(path) = crate::reg::hklm_path(&format!(r"SYSTEM\CurrentControlSet\Services\{service}"), "ImagePath") {
                if let Some(tool) = hwaccess::lookup(&path) {
                    println!("  registered:      {service:<28} {path}  ->  {}", tool.product);
                    registered.push(service);
                }
            }
        }
        println!("{} registered services match the hardware-access table", registered.len());
        let filters = netfilters::filters();
        println!("{} NDIS filters, {} from other vendors", filters.len(), filters.iter().filter(|f| f.vendor.third_party()).count());
        let devices = interrupts::devices();
        for d in devices.iter().filter(|d| d.legacy_despite_hardware()) {
            println!("  legacy interrupt: {:<52} MSISupported={:?}", d.name, d.opt_in);
        }
        println!("{} PCI devices hold interrupt resources", devices.len());
    }
}
