//! Names for PCI bus addresses, so a hardware-error event that says "bus 1, device 0, function 0"
//! can be reported as "NVIDIA GeForce RTX 4090". Read from the device registry; only devices
//! that are present right now count, since the registry also remembers every card ever installed.

use std::ptr::{null, null_mut};

use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{CM_Locate_DevNodeW, CM_LOCATE_DEVNODE_NORMAL, CR_SUCCESS};
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RRF_RT_REG_SZ,
};

use crate::util::{from_wide, wide};

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
    for hw in subkeys(ENUM_PCI) {
        for instance in subkeys(&format!(r"{ENUM_PCI}\{hw}")) {
            let key = format!(r"{ENUM_PCI}\{hw}\{instance}");
            let Some((bus, device, function)) = reg_str(&key, "LocationInformation").as_deref().and_then(parse_location) else { continue };
            if !present(&format!(r"PCI\{hw}\{instance}")) {
                continue;
            }
            let Some(name) = reg_str(&key, "FriendlyName").or_else(|| reg_str(&key, "DeviceDesc")).map(|d| clean_desc(&d)) else {
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
        let mut cards: Vec<&PciDevice> = devices.iter().filter(|d| d.bus == behind && !is_plumbing(&d.name)).collect();
        cards.sort_by_key(|d| (d.device, d.function));
        if let Some(card) = cards.first() {
            return Some(card.name.clone());
        }
    }
    devices.iter().find(|d| (d.bus, d.device, d.function) == (bus, device, function)).map(|d| d.name.clone())
}

/// Bridges, switches and the audio function of a graphics card say nothing about what the card is.
fn is_plumbing(name: &str) -> bool {
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

/// "@oem12.inf,%dev.2684%;NVIDIA GeForce RTX 4090" -> "NVIDIA GeForce RTX 4090", and the form with
/// arguments: "@usbxhci.inf,%x%;%1 USB %2 Host Controller - %3;(AMD,3.10,1.20)".
fn clean_desc(s: &str) -> String {
    let parts: Vec<&str> = s.split(';').collect();
    if !s.starts_with('@') || parts.len() < 2 {
        return s.trim().to_string();
    }
    let mut text = parts[1].trim().to_string();
    if let Some(args) = parts.get(2).and_then(|a| a.trim().strip_prefix('(')).and_then(|a| a.strip_suffix(')')) {
        for (i, arg) in args.split(',').enumerate() {
            text = text.replace(&format!("%{}", i + 1), arg.trim());
        }
    }
    text
}

fn present(instance_id: &str) -> bool {
    let mut devinst = 0u32;
    unsafe { CM_Locate_DevNodeW(&mut devinst, wide(instance_id).as_ptr(), CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS }
}

fn subkeys(path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut key: HKEY = null_mut();
    if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, wide(path).as_ptr(), 0, KEY_READ, &mut key) } != ERROR_SUCCESS {
        return out;
    }
    for index in 0..4096 {
        let mut name = [0u16; 256];
        let mut len = name.len() as u32;
        if unsafe { RegEnumKeyExW(key, index, name.as_mut_ptr(), &mut len, null(), null_mut(), null_mut(), null_mut()) } != ERROR_SUCCESS {
            break;
        }
        out.push(String::from_utf16_lossy(&name[..len as usize]));
    }
    unsafe { RegCloseKey(key) };
    out
}

fn reg_str(subkey: &str, value: &str) -> Option<String> {
    let mut buf = [0u16; 512];
    let mut size = (buf.len() * 2) as u32;
    let r = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            wide(subkey).as_ptr(),
            wide(value).as_ptr(),
            RRF_RT_REG_SZ,
            null_mut(),
            buf.as_mut_ptr() as *mut _,
            &mut size,
        )
    };
    (r == ERROR_SUCCESS).then(|| from_wide(&buf)).filter(|s| !s.is_empty())
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
        for d in found.iter().filter(|d| !is_plumbing(&d.name)).take(8) {
            println!("  {}:{}.{}  {}", d.bus, d.device, d.function, d.name);
        }
    }
}
