//! Which device a driver file belongs to, and how old that driver is. "rtwlane.sys" means nothing
//! to most people; "Realtek 8822CE Wireless LAN adapter, driver from 2021" is something they can
//! act on, and the driver's age is often the whole answer.
//!
//! Source: the device registry (Enum\<bus>\<device>\<instance> -> Service and Driver keys), limited
//! to devices that are present right now, since the registry remembers everything ever plugged in.

use std::collections::HashMap;

use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{CM_Locate_DevNodeW, CM_LOCATE_DEVNODE_NORMAL, CR_SUCCESS};

use crate::reg;
use crate::util::wide;

const ENUM: &str = r"SYSTEM\CurrentControlSet\Enum";
const CLASS: &str = r"SYSTEM\CurrentControlSet\Control\Class";
const SERVICES: &str = r"SYSTEM\CurrentControlSet\Services";

/// One present device and the driver package serving it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DeviceDriver {
    pub device: String,
    pub provider: String,
    pub version: String,
    /// (year, month, day) of the driver package.
    pub date: Option<(i32, u32, u32)>,
}

impl DeviceDriver {
    /// Windows' own drivers all carry the placeholder date 2006-06-21 and are serviced by Windows
    /// Update, so their "age" says nothing.
    pub fn from_microsoft(&self) -> bool {
        self.provider.to_lowercase().starts_with("microsoft")
    }

    /// Whole years between the driver date and `today`, for third-party drivers only.
    pub fn age_years(&self, today: (i32, u32, u32)) -> Option<i32> {
        if self.from_microsoft() {
            return None;
        }
        let (y, m, d) = self.date?;
        let years = today.0 - y - i32::from((today.1, today.2) < (m, d));
        (0..60).contains(&years).then_some(years)
    }

    /// "Version 2024.10.138.3, dated 2021-03-04 (4 years old), from Realtek."
    pub fn describe(&self, today: (i32, u32, u32)) -> String {
        if self.from_microsoft() {
            return format!("Driver built into Windows (version {}), kept up to date by Windows Update.", self.version);
        }
        let mut parts = Vec::new();
        if !self.version.is_empty() {
            parts.push(format!("version {}", self.version));
        }
        if let Some((y, m, d)) = self.date {
            let age = match self.age_years(today) {
                Some(0) => " (less than a year old)".to_string(),
                Some(1) => " (1 year old)".to_string(),
                Some(n) => format!(" ({n} years old)"),
                None => String::new(),
            };
            parts.push(format!("dated {y:04}-{m:02}-{d:02}{age}"));
        }
        if !self.provider.is_empty() {
            parts.push(format!("from {}", self.provider.trim_end_matches('.')));
        }
        if parts.is_empty() {
            return String::new();
        }
        let text = parts.join(", ");
        format!("Driver {text}.")
    }
}

/// Driver file name (lower case, e.g. "rtwlane.sys") -> the present devices it serves.
#[derive(Default)]
pub struct DeviceMap {
    by_file: HashMap<String, Vec<DeviceDriver>>,
}

impl DeviceMap {
    pub fn load() -> DeviceMap {
        let mut by_file: HashMap<String, Vec<DeviceDriver>> = HashMap::new();
        let mut service_files: HashMap<String, Option<String>> = HashMap::new();
        for bus in reg::subkeys(ENUM) {
            for device in reg::subkeys(&format!(r"{ENUM}\{bus}")) {
                for instance in reg::subkeys(&format!(r"{ENUM}\{bus}\{device}")) {
                    let key = format!(r"{ENUM}\{bus}\{device}\{instance}");
                    let Some(service) = reg::hklm_path(&key, "Service") else { continue };
                    let file = service_files
                        .entry(service.to_lowercase())
                        .or_insert_with(|| reg::hklm_path(&format!(r"{SERVICES}\{service}"), "ImagePath").and_then(|p| file_name(&p)))
                        .clone();
                    let Some(file) = file else { continue };
                    if !present(&format!(r"{bus}\{device}\{instance}")) {
                        continue;
                    }
                    let Some(name) =
                        reg::hklm_path(&key, "FriendlyName").or_else(|| reg::hklm_path(&key, "DeviceDesc")).map(|d| clean_desc(&d))
                    else {
                        continue;
                    };
                    let mut entry = DeviceDriver { device: name, ..Default::default() };
                    if let Some(driver) = reg::hklm_path(&key, "Driver") {
                        let class_key = format!(r"{CLASS}\{driver}");
                        entry.provider = reg::hklm_path(&class_key, "ProviderName").map(|p| clean_desc(&p)).unwrap_or_default();
                        entry.version = reg::hklm_path(&class_key, "DriverVersion").unwrap_or_default();
                        entry.date = reg::hklm_path(&class_key, "DriverDate").as_deref().and_then(parse_date);
                    }
                    let list = by_file.entry(file).or_default();
                    if !list.iter().any(|d| d.device == entry.device) {
                        list.push(entry);
                    }
                }
            }
        }
        DeviceMap { by_file }
    }

    #[cfg(test)]
    pub(crate) fn insert_for_test(&mut self, file: &str, devices: Vec<DeviceDriver>) {
        self.by_file.insert(file.to_lowercase(), devices);
    }

    pub fn len(&self) -> usize {
        self.by_file.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_file.is_empty()
    }

    pub fn get(&self, driver_file: &str) -> &[DeviceDriver] {
        self.by_file.get(&driver_file.to_lowercase()).map_or(&[], |v| v.as_slice())
    }

    /// "Realtek 8822CE Wireless LAN adapter" or "AMD USB 3.10 Host Controller (and 2 more devices)".
    pub fn device_title(&self, driver_file: &str) -> Option<String> {
        let devices = self.get(driver_file);
        let first = devices.first()?;
        Some(match devices.len() {
            1 => first.device.clone(),
            2 => format!("{} (and 1 more device)", first.device),
            n => format!("{} (and {} more devices)", first.device, n - 1),
        })
    }
}

/// "\SystemRoot\System32\drivers\rtwlane.sys", "system32\DRIVERS\x.sys", "\??\C:\...\y.sys" -> "rtwlane.sys"
fn file_name(image_path: &str) -> Option<String> {
    let path = image_path.trim().trim_matches('"');
    let name = path.rsplit(['\\', '/']).next()?.to_lowercase();
    name.ends_with(".sys").then_some(name)
}

/// "3-4-2021" (month-day-year, as Windows stores it).
fn parse_date(s: &str) -> Option<(i32, u32, u32)> {
    let mut parts = s.trim().split('-').map(|p| p.trim().parse::<u32>().ok());
    let (m, d, y) = (parts.next()??, parts.next()??, parts.next()??);
    ((1..=12).contains(&m) && (1..=31).contains(&d) && (1990..2200).contains(&y)).then_some((y as i32, m, d))
}

/// "@oem12.inf,%dev%;NVIDIA GeForce RTX 4090" -> "NVIDIA GeForce RTX 4090", including the form
/// with arguments: "@usbxhci.inf,%x%;%1 USB %2 Host Controller;(AMD,3.10)".
pub(crate) fn clean_desc(s: &str) -> String {
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

pub(crate) fn present(instance_id: &str) -> bool {
    let mut devinst = 0u32;
    unsafe { CM_Locate_DevNodeW(&mut devinst, wide(instance_id).as_ptr(), CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS }
}

/// Today's date in local time, for driver ages.
pub fn today() -> (i32, u32, u32) {
    let st = crate::util::local_time();
    (st.wYear as i32, st.wMonth as u32, st.wDay as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_paths_and_dates_parse() {
        assert_eq!(file_name(r"\SystemRoot\System32\drivers\RTWlanE.sys").as_deref(), Some("rtwlane.sys"));
        assert_eq!(file_name(r"System32\DriverStore\FileRepository\nv_dispi.inf_amd64_1\nvlddmkm.sys").as_deref(), Some("nvlddmkm.sys"));
        assert_eq!(file_name(r#""\??\C:\Program Files\Tool\helper.sys""#).as_deref(), Some("helper.sys"));
        assert_eq!(file_name(r"C:\Windows\system32\svchost.exe -k netsvcs"), None);
        assert_eq!(parse_date("3-4-2021"), Some((2021, 3, 4)));
        assert_eq!(parse_date("6-21-2006"), Some((2006, 6, 21)));
        assert_eq!(parse_date("2021-03-04"), None, "year-first is not what Windows stores; refuse rather than guess");
        assert_eq!(parse_date("nonsense"), None);
    }

    #[test]
    fn driver_age_is_stated_for_third_parties_only() {
        let today = (2026, 9, 20);
        let realtek =
            DeviceDriver { device: "Realtek NIC".into(), provider: "Realtek".into(), version: "10.1.2".into(), date: Some((2021, 10, 4)) };
        assert_eq!(realtek.age_years(today), Some(4), "birthday not reached yet this year");
        assert_eq!(realtek.describe(today), "Driver version 10.1.2, dated 2021-10-04 (4 years old), from Realtek.");

        let inbox = DeviceDriver {
            device: "USB xHCI".into(),
            provider: "Microsoft".into(),
            version: "10.0.26100.1".into(),
            date: Some((2006, 6, 21)),
        };
        assert_eq!(inbox.age_years(today), None);
        assert!(inbox.describe(today).contains("built into Windows") && !inbox.describe(today).contains("2006"));

        let fresh = DeviceDriver { date: Some((2026, 8, 1)), provider: "NVIDIA".into(), ..Default::default() };
        assert!(fresh.describe(today).contains("less than a year old"));
        assert_eq!(DeviceDriver::default().describe(today), "");
    }

    #[test]
    fn several_devices_on_one_driver_are_summarized() {
        let mut map = DeviceMap::default();
        let dev = |name: &str| DeviceDriver { device: name.into(), ..Default::default() };
        map.by_file.insert(
            "usbxhci.sys".into(),
            vec![dev("AMD USB 3.10 Host Controller"), dev("AMD USB 2.0 Host Controller"), dev("ASMedia USB 3.2")],
        );
        map.by_file.insert("nvlddmkm.sys".into(), vec![dev("NVIDIA GeForce RTX 5090")]);
        assert_eq!(map.device_title("USBXHCI.SYS").as_deref(), Some("AMD USB 3.10 Host Controller (and 2 more devices)"));
        assert_eq!(map.device_title("nvlddmkm.sys").as_deref(), Some("NVIDIA GeForce RTX 5090"));
        assert_eq!(map.device_title("ntoskrnl.exe"), None);
    }

    #[test]
    fn loading_this_pc_does_not_panic() {
        // No count asserted: CI runners are minimal virtual machines.
        let start = std::time::Instant::now();
        let map = DeviceMap::load();
        println!("{} driver files mapped in {:?}", map.len(), start.elapsed());
        for file in ["nvlddmkm.sys", "stornvme.sys", "usbxhci.sys", "rt640x64.sys", "e2f.sys", "amdkmdag.sys", "hdaudio.sys"] {
            if let Some(d) = map.get(file).first() {
                println!("  {file}: {}  |  {}", map.device_title(file).unwrap(), d.describe(today()));
            }
        }
    }
}
