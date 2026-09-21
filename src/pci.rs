//! Names for PCI bus addresses, so a hardware-error event that says "bus 1, device 0, function 0"
//! can be reported as "NVIDIA GeForce RTX 4090". Read from the device registry; only devices
//! that are present right now count, since the registry also remembers every card ever installed.

use crate::devices::{clean_desc, present};
use crate::reg;

const ENUM_PCI: &str = r"SYSTEM\CurrentControlSet\Enum\PCI";

#[derive(Clone, Debug, PartialEq)]
pub struct PciDevice {
    pub bus: u32,
    pub device: u32,
    pub function: u32,
    pub name: String,
}

/// Every PCI device currently present, with its bus address.
pub fn devices() -> Vec<PciDevice> {
    let mut out = Vec::new();
    for hw in reg::subkeys(ENUM_PCI) {
        for instance in reg::subkeys(&format!(r"{ENUM_PCI}\{hw}")) {
            let key = format!(r"{ENUM_PCI}\{hw}\{instance}");
            let Some((bus, device, function)) = reg::hklm_path(&key, "LocationInformation").as_deref().and_then(parse_location) else {
                continue;
            };
            if !present(&format!(r"PCI\{hw}\{instance}")) {
                continue;
            }
            let Some(name) = reg::hklm_path(&key, "FriendlyName").or_else(|| reg::hklm_path(&key, "DeviceDesc")).map(|d| clean_desc(&d))
            else {
                continue;
            };
            out.push(PciDevice { bus, device, function, name });
        }
    }
    out
}

/// What sits at an address. For a bridge or root port (`secondary_bus`), the card plugged into it
/// is the useful answer, since the port itself is just "PCI Express Root Port".
pub fn describe(devices: &[PciDevice], bus: u32, device: u32, function: u32, secondary_bus: Option<u32>) -> Option<String> {
    if let Some(behind) = secondary_bus {
        let mut cards: Vec<&PciDevice> = devices.iter().filter(|d| d.bus == behind && !is_never_the_card(&d.name)).collect();
        cards.sort_by_key(|d| (d.device, d.function));
        if let Some(card) = cards.first() {
            return Some(card.name.clone());
        }
    }
    devices.iter().find(|d| (d.bus, d.device, d.function) == (bus, device, function)).map(|d| d.name.clone())
}

/// ONE JOB, and it is not a general "boring device" filter: when a hardware error names a bridge
/// or a root port, `describe` looks for the card plugged in behind it, and these names are the ones
/// that are never the answer to "what card is this". A graphics card's audio function sits on the
/// same bus as the GPU, so it has to be skipped there or a PCI Express error on the graphics card
/// gets reported as an audio device.
///
/// Do NOT reuse this to decide which devices are worth mentioning. It used to be called
/// `is_plumbing`, and under that name it reads like a general filter - which would have hidden
/// every device issue #17 is about: on the development PC, all three devices on a legacy shared
/// interrupt are High Definition Audio functions. `interrupts::devices()` deliberately does its own
/// enumeration and never calls this.
fn is_never_the_card(name: &str) -> bool {
    let n = name.to_lowercase();
    ["root port", "pci-to-pci", "pci express switch", "upstream", "downstream", "high definition audio", "bridge"]
        .iter()
        .any(|k| n.contains(k))
}

/// "PCI bus 1, device 0, function 0", or the indirect form Windows stores on recent builds:
/// "@System32\drivers\pci.sys,#65536;PCI bus %1, device %2, function %3;(1,0,0)".
fn parse_location(s: &str) -> Option<(u32, u32, u32)> {
    let numbers =
        |t: &str| -> Vec<u32> { t.split(|c: char| !c.is_ascii_digit()).filter(|p| !p.is_empty()).filter_map(|p| p.parse().ok()).collect() };
    if let Some((_, tuple)) = s.rsplit_once(";(") {
        if let [b, d, f] = numbers(tuple)[..] {
            return Some((b, d, f));
        }
    }
    let lower = s.to_lowercase();
    let at = lower.find("pci bus")?;
    match numbers(&lower[at..])[..] {
        [b, d, f, ..] => Some((b, d, f)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_location_formats_parse() {
        assert_eq!(parse_location("PCI bus 1, device 0, function 0"), Some((1, 0, 0)));
        assert_eq!(parse_location(r"@System32\drivers\pci.sys,#65536;PCI bus %1, device %2, function %3;(12,0,3)"), Some((12, 0, 3)));
        assert_eq!(parse_location("somewhere else"), None);
        assert_eq!(clean_desc("@oem12.inf,%dev.2684%;NVIDIA GeForce RTX 4090"), "NVIDIA GeForce RTX 4090");
        assert_eq!(clean_desc("Plain name"), "Plain name");
        assert_eq!(clean_desc("@usbxhci.inf,%x%;%1 USB %2 Host Controller - %3;(AMD,3.10,1.20)"), "AMD USB 3.10 Host Controller - 1.20");
    }

    #[test]
    fn a_root_port_is_described_by_the_card_behind_it() {
        let dev = |bus, device, function, name: &str| PciDevice { bus, device, function, name: name.into() };
        let devices = vec![
            dev(0, 1, 1, "PCI Express Root Port"),
            dev(1, 0, 1, "High Definition Audio Controller"),
            dev(1, 0, 0, "NVIDIA GeForce RTX 4090"),
            dev(0, 2, 0, "Standard NVM Express Controller"),
        ];
        assert_eq!(describe(&devices, 0, 1, 1, Some(1)).as_deref(), Some("NVIDIA GeForce RTX 4090"));
        assert_eq!(describe(&devices, 0, 2, 0, None).as_deref(), Some("Standard NVM Express Controller"));
        // Nothing known behind the port: fall back to the port itself.
        assert_eq!(describe(&devices, 0, 1, 1, Some(9)).as_deref(), Some("PCI Express Root Port"));
        assert_eq!(describe(&devices, 7, 0, 0, None), None);
    }

    #[test]
    fn listing_devices_does_not_panic() {
        // No count is asserted: virtual machines (CI runners included) can have no PCI devices at all.
        let found = devices();
        println!("{} PCI devices present", found.len());
        // Everything, audio functions included: this list is not what `is_never_the_card` is for.
        for d in found.iter().take(12) {
            println!("  {}:{}.{}  {}", d.bus, d.device, d.function, d.name);
        }
    }

    /// The helper keeps doing its one job, and the test says what that job is.
    #[test]
    fn only_the_things_that_are_never_the_card_behind_a_bridge_are_skipped() {
        assert!(is_never_the_card("PCI Express Root Port") && is_never_the_card("Intel PCI-to-PCI Bridge"));
        assert!(is_never_the_card("High Definition Audio Controller"), "a GPU's audio function must not be named instead of the GPU");
        assert!(!is_never_the_card("NVIDIA GeForce RTX 5090") && !is_never_the_card("Standard NVM Express Controller"));
    }
}
