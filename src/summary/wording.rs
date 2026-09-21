//! How the report talks about a process or a driver. Every sentence that names one comes
//! through here, because the answer for "System" or "svchost.exe" is never "close it".

use crate::devices::{self, DeviceMap};
use crate::procs::{known_worker, process_name};

use super::ctx::Ctx;
use super::Findings;

pub(super) const GENERIC_DRIVER_ADVICE: &str =
    "Update this driver from the device maker's site, or roll it back if the problem started after an \
    update. To confirm, temporarily disable the device (or close the software it belongs to) and monitor again.";

pub(super) const POLLING_ADVICE: &str =
    "Something runs on a timer. The usual suspects poll hardware sensors: RGB and fan utilities (iCUE, Armoury \
    Crate, Aura, RGB Fusion, MSI Center, NZXT CAM), monitoring tools (HWiNFO, Afterburner/RTSS, Ryzen Master), vendor 'control \
    center' and battery utilities. Fully exit them one at a time (not just close the window) and monitor again.";

/// Third-party drivers older than this get "update it" put first.
const OLD_DRIVER_YEARS: i32 = 2;

/// Retitles "driver <file>" findings with the device the driver serves and adds the driver's
/// version, date and age. Drivers without a device (filters, antivirus, the kernel) stay as they are.
fn name_devices(found: &mut Findings, map: &DeviceMap, today: (i32, u32, u32)) {
    for (key, f) in found.0.iter_mut() {
        let Some(file) = key.strip_prefix("driver ") else { continue };
        let (Some(title), Some(first)) = (map.device_title(file), map.get(file).first()) else { continue };
        // Keep whatever followed the description, e.g. ": it hung and was reset".
        let suffix =
            f.title.split_once("  -  ").and_then(|(_, rest)| rest.split_once(": ")).map_or(String::new(), |(_, tail)| format!(": {tail}"));
        f.title = format!("{file}  -  {title}{suffix}");
        let about = first.describe(today);
        if !about.is_empty() {
            f.evidence.push(about);
        }
        if let Some(years) = first.age_years(today).filter(|y| *y >= OLD_DRIVER_YEARS) {
            let provider =
                if first.provider.is_empty() { "the device maker".to_string() } else { first.provider.trim_end_matches('.').to_string() };
            f.advice = format!(
                "Start here: this driver is {years} years old. Install the current one from {provider} or from the support page of your \
                 PC or motherboard model (Windows Update rarely offers the newest). {}",
                f.advice
            );
        }
    }
}

/// Title for a process blamed for CPU time. Parts of Windows are named as such: nobody can close
/// "System", and calling it a program sends people looking for something that does not exist.
pub(super) fn process_title(label: &str) -> String {
    let name = process_name(label);
    if name.starts_with("System") {
        return "Windows kernel (the System process)  -  a driver, or Windows itself".to_string();
    }
    match known_worker(&name) {
        Some(w) if w.windows => format!("{name}  -  part of Windows: {}", w.what),
        Some(w) => format!("{name}  -  {}", w.what),
        None => format!("{name}  -  program"),
    }
}

/// What to try for a process blamed for CPU time; never "close it" for something that is Windows.
pub(super) fn process_advice(label: &str) -> String {
    let name = process_name(label);
    if name.starts_with("System") {
        return "This is not a program you can close: it is where Windows runs the work of drivers and of the kernel itself. The \
                driver behind it is usually named under 'Kernel-mode time by module' for that stall in the event log below: update \
                or roll back that driver. If only ntoskrnl.exe appears there, suspect storage, memory pressure or power management: \
                check the disk and drive-health findings in this report, update the chipset driver and the BIOS."
            .to_string();
    }
    match known_worker(&name) {
        Some(w) if w.windows => format!(
            "{name} is part of Windows ({}), not something you can close. {} If it keeps showing up, the driver it leans on is \
             listed under 'Kernel-mode time by module' for that stall in the event log.",
            w.what, w.tip
        ),
        Some(w) => format!("{} Then monitor again; if the stalls are gone, that was it.", w.tip),
        None => "Close this program and monitor again. If the stalls disappear, update or replace it, or look at the driver it \
                 leans on (listed under 'Kernel-mode time by module' in the event log)."
            .to_string(),
    }
}

/// Says which device each blamed driver belongs to, and how old the driver is.
pub(super) fn devices_behind_drivers(cx: &mut Ctx) {
    let device_map = DeviceMap::load();
    let today = devices::today();
    name_devices(&mut cx.found, &device_map, today);
    cx.device_map = device_map;
    cx.today = today;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summary::Severity;

    #[test]
    fn blamed_drivers_are_named_after_their_device_and_old_ones_say_so() {
        use crate::devices::DeviceDriver;
        let mut found = Findings::default();
        found.add(
            "driver rtwlane.sys",
            Severity::High,
            "rtwlane.sys  -  Wi-Fi adapter driver".into(),
            "Blamed for 3 stalls.".into(),
            "Disable power saving.".into(),
            0,
        );
        found.add(
            "driver nvlddmkm.sys",
            Severity::High,
            "nvlddmkm.sys  -  NVIDIA GPU driver: it hung and was reset".into(),
            "e".into(),
            "a".into(),
            0,
        );
        found.add("driver wdfilter.sys", Severity::Medium, "wdfilter.sys  -  Microsoft Defender filter".into(), "e".into(), "a".into(), 0);
        found.add("disk 1", Severity::Medium, "Disk 1  -  responding slowly".into(), "e".into(), "a".into(), 0);
        let mut map = DeviceMap::default();
        let dev = |device: &str, provider: &str, date| DeviceDriver {
            device: device.into(),
            provider: provider.into(),
            version: "1.2".into(),
            date: Some(date),
        };
        map.insert_for_test(
            "rtwlane.sys",
            vec![dev("Realtek 8822CE Wireless LAN 802.11ac PCI-E NIC", "Realtek Semiconductor Corp.", (2021, 3, 4))],
        );
        map.insert_for_test("nvlddmkm.sys", vec![dev("NVIDIA GeForce RTX 5090", "NVIDIA", (2026, 9, 4))]);
        name_devices(&mut found, &map, (2026, 9, 20));

        let f = |key: &str| &found.0.iter().find(|(k, _)| k == key).unwrap().1;
        let wifi = f("driver rtwlane.sys");
        assert_eq!(wifi.title, "rtwlane.sys  -  Realtek 8822CE Wireless LAN 802.11ac PCI-E NIC");
        assert!(
            wifi.evidence.iter().any(|e| e.contains("dated 2021-03-04 (5 years old), from Realtek Semiconductor Corp.")),
            "{:?}",
            wifi.evidence
        );
        assert!(
            wifi.advice.starts_with("Start here: this driver is 5 years old") && wifi.advice.ends_with("Disable power saving."),
            "{}",
            wifi.advice
        );

        let gpu = f("driver nvlddmkm.sys");
        assert_eq!(gpu.title, "nvlddmkm.sys  -  NVIDIA GeForce RTX 5090: it hung and was reset");
        assert_eq!(gpu.advice, "a", "a current driver gets no 'update it' advice");
        assert_eq!(f("driver wdfilter.sys").title, "wdfilter.sys  -  Microsoft Defender filter", "no device: unchanged");
        assert_eq!(f("disk 1").title, "Disk 1  -  responding slowly");
    }

    #[test]
    fn windows_processes_are_never_called_programs_you_can_close() {
        for label in [
            "System (kernel threads)",
            "System (4)",
            "svchost.exe (1234)",
            "MsMpEng.exe (99)",
            "dwm.exe (1500)",
            "backgroundTaskHost.exe (7)",
        ] {
            let (title, advice) = (process_title(label), process_advice(label));
            assert!(!title.ends_with("-  program"), "{label}: {title}");
            assert!(!advice.starts_with("Close this program") && !advice.contains("pause it"), "{label}: {advice}");
            assert!(
                advice.contains("not") && (advice.contains("you can close") || advice.contains("something you can close")),
                "{label}: {advice}"
            );
        }
        assert!(process_title("System (kernel threads)").starts_with("Windows kernel"));
        assert!(process_advice("System (kernel threads)").contains("Kernel-mode time by module"));
        // A real program still gets the plain advice, and a known app its own tip.
        assert_eq!(process_title("game.exe (4242)"), "game.exe  -  program");
        assert!(process_advice("game.exe (4242)").starts_with("Close this program"));
        assert!(process_advice("steam.exe (77)").contains("Pause the download"));
    }
}
