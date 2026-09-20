//! Turns the bare disk number carried by kernel I/O events into something a person recognizes:
//! drive letters, model, firmware, how it is connected and how full it is.
//!
//! Everything is read with zero-access handles, so it works without touching the disk's data.
//! Serial numbers are deliberately not read: reports get pasted into forums.

use std::collections::HashMap;
use std::ffi::c_void;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDrives, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Ioctl::{IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, IOCTL_STORAGE_QUERY_PROPERTY};
use windows_sys::Win32::System::IO::DeviceIoControl;

use crate::util::wide;

/// CTL_CODE(IOCTL_VOLUME_BASE ('V'), 0, METHOD_BUFFERED, FILE_ANY_ACCESS); not exported by windows-sys.
const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x0056_0000;
const DRIVE_REMOVABLE: u32 = 2;
const DRIVE_FIXED: u32 = 3;
/// STORAGE_PROPERTY_ID values.
const STORAGE_DEVICE_PROPERTY: u32 = 0;
const STORAGE_DEVICE_SEEK_PENALTY_PROPERTY: u32 = 7;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Volume {
    pub letter: char,
    pub total: u64,
    pub free: u64,
}

impl Volume {
    pub fn percent_full(&self) -> Option<u32> {
        (self.total > 0).then(|| (100.0 * (self.total - self.free.min(self.total)) as f64 / self.total as f64).round() as u32)
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct DiskInfo {
    pub number: u32,
    /// "Samsung SSD 990 PRO 2TB". Empty when the disk could not be queried.
    pub model: String,
    pub firmware: String,
    /// "NVMe", "SATA", "USB", ... Empty when unknown.
    pub bus: &'static str,
    /// Some(true) = spinning hard drive, Some(false) = SSD / flash.
    pub spinning: Option<bool>,
    pub removable: bool,
    pub size: u64,
    pub volumes: Vec<Volume>,
}

impl DiskInfo {
    /// "E: F:" or "".
    pub fn letters(&self) -> String {
        self.volumes.iter().map(|v| format!("{}:", v.letter)).collect::<Vec<_>>().join(" ")
    }

    /// "disk 6 (E:)" - for one-line log entries.
    pub fn short(&self) -> String {
        match self.letters() {
            l if l.is_empty() => format!("disk {}", self.number),
            l => format!("disk {} ({l})", self.number),
        }
    }

    /// "Disk 6 (E:), Samsung SSD 990 PRO 2TB" - for headlines.
    pub fn title(&self) -> String {
        let mut s = format!("Disk {}", self.number);
        let letters = self.letters();
        if !letters.is_empty() {
            s.push_str(&format!(" ({letters})"));
        }
        if !self.model.is_empty() {
            s.push_str(&format!(", {}", self.model));
        }
        s
    }

    /// "NVMe SSD, 2.0 TB, firmware 4B2QJXD7" - whatever of it is known.
    pub fn hardware(&self) -> String {
        let kind = match (self.bus, self.spinning) {
            ("", Some(true)) => "hard drive".to_string(),
            ("", Some(false)) => "SSD".to_string(),
            ("", None) => String::new(),
            (bus, Some(true)) => format!("{bus} hard drive"),
            (bus, Some(false)) if self.removable => format!("{bus} flash drive"),
            (bus, Some(false)) => format!("{bus} SSD"),
            (bus, None) => format!("{bus} drive"),
        };
        let mut parts = Vec::new();
        if !kind.is_empty() {
            parts.push(kind);
        }
        if self.size > 0 {
            parts.push(fmt_size(self.size));
        }
        if !self.firmware.is_empty() {
            parts.push(format!("firmware {}", self.firmware));
        }
        parts.join(", ")
    }

    /// "C: 91% full, D: 40% full"
    pub fn fullness(&self) -> String {
        self.volumes.iter().filter_map(|v| v.percent_full().map(|p| format!("{}: {p}% full", v.letter))).collect::<Vec<_>>().join(", ")
    }

    /// Letters of volumes that are close enough to full to slow an SSD down.
    pub fn nearly_full(&self) -> Vec<char> {
        self.volumes.iter().filter(|v| v.percent_full().is_some_and(|p| p >= 90)).map(|v| v.letter).collect()
    }
}

/// Disk number -> description, looked up on first use so drives plugged in mid-run still resolve.
#[derive(Default)]
pub struct DiskMap {
    cache: HashMap<u32, DiskInfo>,
}

impl DiskMap {
    pub fn new() -> DiskMap {
        DiskMap::default()
    }

    pub fn get(&mut self, number: u32) -> &DiskInfo {
        self.cache.entry(number).or_insert_with(|| query_disk(number))
    }
}

pub fn fmt_size(bytes: u64) -> String {
    // Decimal units, to match the number printed on the box.
    let gb = bytes as f64 / 1e9;
    if gb >= 1000.0 {
        format!("{:.1} TB", gb / 1000.0)
    } else if gb >= 1.0 {
        format!("{gb:.0} GB")
    } else {
        format!("{:.0} MB", bytes as f64 / 1e6)
    }
}

struct Handle(HANDLE);

impl Handle {
    /// Zero desired access: enough for the property and geometry ioctls, never reads user data.
    fn open(path: &str) -> Option<Handle> {
        let h = unsafe {
            CreateFileW(
                wide(path).as_ptr(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        (h != INVALID_HANDLE_VALUE && !h.is_null()).then_some(Handle(h))
    }

    fn ioctl(&self, code: u32, input: &[u8], out: &mut [u8]) -> Option<usize> {
        let mut returned = 0u32;
        let inp = if input.is_empty() { null() } else { input.as_ptr() as *const c_void };
        let ok = unsafe {
            DeviceIoControl(
                self.0,
                code,
                inp,
                input.len() as u32,
                out.as_mut_ptr() as *mut c_void,
                out.len() as u32,
                &mut returned,
                null_mut(),
            )
        };
        (ok != 0).then_some(returned as usize)
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn query_disk(number: u32) -> DiskInfo {
    let mut info = DiskInfo { number, volumes: volumes_on(number), ..Default::default() };
    let Some(h) = Handle::open(&format!(r"\\.\PhysicalDrive{number}")) else { return info };

    // STORAGE_PROPERTY_QUERY { PropertyId, QueryType = PropertyStandardQuery (0), AdditionalParameters[1] }
    let query = |property: u32| {
        let mut q = [0u8; 12];
        q[..4].copy_from_slice(&property.to_le_bytes());
        q
    };
    let mut buf = [0u8; 1024];
    if let Some(n) = h.ioctl(IOCTL_STORAGE_QUERY_PROPERTY, &query(STORAGE_DEVICE_PROPERTY), &mut buf) {
        if let Some(d) = parse_device_descriptor(&buf[..n]) {
            info.model = d.model;
            info.firmware = d.firmware;
            info.bus = d.bus;
            info.removable = d.removable;
        }
    }
    // DEVICE_SEEK_PENALTY_DESCRIPTOR { Version, Size, IncursSeekPenalty: u8 }
    let mut buf = [0u8; 16];
    if let Some(n) = h.ioctl(IOCTL_STORAGE_QUERY_PROPERTY, &query(STORAGE_DEVICE_SEEK_PENALTY_PROPERTY), &mut buf) {
        if n >= 9 {
            info.spinning = Some(buf[8] != 0);
        }
    }
    if info.spinning.is_none() && info.bus == "NVMe" {
        info.spinning = Some(false);
    }
    // DISK_GEOMETRY_EX { Geometry: DISK_GEOMETRY (24 bytes), DiskSize: i64, .. }
    let mut buf = [0u8; 256];
    if let Some(n) = h.ioctl(IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, &[], &mut buf) {
        if n >= 32 {
            info.size = u64::from_le_bytes(buf[24..32].try_into().unwrap());
        }
    }
    info
}

#[derive(Debug, PartialEq)]
struct Descriptor {
    model: String,
    firmware: String,
    bus: &'static str,
    removable: bool,
}

/// STORAGE_DEVICE_DESCRIPTOR: RemovableMedia u8 @10, VendorIdOffset u32 @12, ProductIdOffset @16,
/// ProductRevisionOffset @20, SerialNumberOffset @24 (not read), BusType u32 @28; strings are
/// NUL-terminated ASCII at those offsets, 0 meaning "none".
fn parse_device_descriptor(d: &[u8]) -> Option<Descriptor> {
    if d.len() < 32 {
        return None;
    }
    let u32_at = |o: usize| u32::from_le_bytes(d[o..o + 4].try_into().unwrap());
    let text = |o: usize| -> String {
        let o = u32_at(o) as usize;
        if o == 0 || o >= d.len() {
            return String::new();
        }
        let end = d[o..].iter().position(|&b| b == 0).map_or(d.len(), |p| o + p);
        let s: String = d[o..end].iter().map(|&b| if b.is_ascii_graphic() { b as char } else { ' ' }).collect();
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    };
    let (vendor, product) = (text(12), text(16));
    // SATA and NVMe disks usually leave the vendor empty and put everything in the product string.
    let model = if vendor.is_empty() || product.to_lowercase().starts_with(&vendor.to_lowercase()) {
        product
    } else {
        format!("{vendor} {product}").trim().to_string()
    };
    Some(Descriptor { model, firmware: text(20), bus: bus_name(u32_at(28)), removable: d[10] != 0 })
}

/// STORAGE_BUS_TYPE, in words people have seen on a box.
fn bus_name(bus: u32) -> &'static str {
    match bus {
        1 => "SCSI",
        2 => "ATAPI",
        3 => "ATA",
        4 => "FireWire",
        6 => "Fibre Channel",
        7 => "USB",
        8 => "RAID",
        9 => "iSCSI",
        10 => "SAS",
        11 => "SATA",
        12 => "SD card",
        13 => "MMC",
        14 | 15 => "virtual",
        16 => "Storage Spaces",
        17 => "NVMe",
        19 => "UFS",
        _ => "",
    }
}

/// Lettered volumes with at least one extent on this physical disk.
fn volumes_on(number: u32) -> Vec<Volume> {
    let mut out = Vec::new();
    let mask = unsafe { GetLogicalDrives() };
    for i in 0..26u32 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let letter = (b'A' + i as u8) as char;
        let root = wide(&format!(r"{letter}:\"));
        // Skips network shares and optical drives: no disk number, and probing them can block.
        if !matches!(unsafe { GetDriveTypeW(root.as_ptr()) }, DRIVE_FIXED | DRIVE_REMOVABLE) {
            continue;
        }
        let Some(h) = Handle::open(&format!(r"\\.\{letter}:")) else { continue };
        // VOLUME_DISK_EXTENTS { NumberOfDiskExtents u32, pad, DISK_EXTENT[] { DiskNumber u32, pad, offset i64, length i64 } }
        let mut buf = [0u8; 8 + 24 * 32];
        let Some(n) = h.ioctl(IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, &[], &mut buf) else { continue };
        if !extent_disks(&buf[..n]).contains(&number) {
            continue;
        }
        let (mut total, mut free) = (0u64, 0u64);
        unsafe { GetDiskFreeSpaceExW(root.as_ptr(), null_mut(), &mut total, &mut free) };
        out.push(Volume { letter, total, free });
    }
    out
}

fn extent_disks(d: &[u8]) -> Vec<u32> {
    if d.len() < 8 {
        return Vec::new();
    }
    let count = u32::from_le_bytes(d[..4].try_into().unwrap()) as usize;
    (0..count).map(|i| 8 + i * 24).take_while(|o| o + 4 <= d.len()).map(|o| u32::from_le_bytes(d[o..o + 4].try_into().unwrap())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(vendor: &str, product: &str, revision: &str, bus: u32, removable: bool) -> Vec<u8> {
        let mut d = vec![0u8; 40];
        d[10] = removable as u8;
        d[28..32].copy_from_slice(&bus.to_le_bytes());
        for (field, s) in [(12usize, vendor), (16, product), (20, revision)] {
            if s.is_empty() {
                continue;
            }
            let at = d.len() as u32;
            d[field..field + 4].copy_from_slice(&at.to_le_bytes());
            d.extend_from_slice(s.as_bytes());
            d.push(0);
        }
        d
    }

    #[test]
    fn descriptor_strings_are_trimmed_and_vendor_is_not_repeated() {
        let d = parse_device_descriptor(&descriptor("", "Samsung SSD 990 PRO 2TB   ", "4B2QJXD7", 17, false)).unwrap();
        assert_eq!(d, Descriptor { model: "Samsung SSD 990 PRO 2TB".into(), firmware: "4B2QJXD7".into(), bus: "NVMe", removable: false });

        let d = parse_device_descriptor(&descriptor("SanDisk ", "Ultra  Fit", "1.00", 7, true)).unwrap();
        assert_eq!((d.model.as_str(), d.bus, d.removable), ("SanDisk Ultra Fit", "USB", true));

        let d = parse_device_descriptor(&descriptor("WDC", "WDC WD40EZAZ", "80.0", 11, false)).unwrap();
        assert_eq!(d.model, "WDC WD40EZAZ");
    }

    #[test]
    fn short_or_corrupt_descriptors_do_not_panic() {
        assert!(parse_device_descriptor(&[0u8; 8]).is_none());
        let mut d = descriptor("", "x", "", 11, false);
        d[16..20].copy_from_slice(&9999u32.to_le_bytes()); // offset past the end
        assert_eq!(parse_device_descriptor(&d).unwrap().model, "");
    }

    #[test]
    fn extents_list_every_disk_a_volume_spans() {
        let mut d = vec![0u8; 8 + 48];
        d[..4].copy_from_slice(&2u32.to_le_bytes());
        d[8..12].copy_from_slice(&6u32.to_le_bytes());
        d[32..36].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(extent_disks(&d), vec![6, 1]);
        assert!(extent_disks(&[]).is_empty());
    }

    #[test]
    fn labels_read_well_with_and_without_details() {
        let bare = DiskInfo { number: 3, ..Default::default() };
        assert_eq!((bare.short(), bare.title(), bare.hardware()), ("disk 3".into(), "Disk 3".into(), String::new()));

        let full = DiskInfo {
            number: 6,
            model: "Samsung SSD 990 PRO 2TB".into(),
            firmware: "4B2QJXD7".into(),
            bus: "NVMe",
            spinning: Some(false),
            removable: false,
            size: 2_000_398_934_016,
            volumes: vec![Volume { letter: 'E', total: 1000, free: 50 }, Volume { letter: 'F', total: 1000, free: 600 }],
        };
        assert_eq!(full.short(), "disk 6 (E: F:)");
        assert_eq!(full.title(), "Disk 6 (E: F:), Samsung SSD 990 PRO 2TB");
        assert_eq!(full.hardware(), "NVMe SSD, 2.0 TB, firmware 4B2QJXD7");
        assert_eq!(full.fullness(), "E: 95% full, F: 40% full");
        assert_eq!(full.nearly_full(), vec!['E']);
        assert_eq!((fmt_size(118_000_000_000), fmt_size(42_500_000)), ("118 GB".to_string(), "42 MB".to_string()));
    }

    #[test]
    fn the_system_disk_can_be_described() {
        // Live read; only checks that nothing crashes and the system volume maps to some disk.
        let disks: Vec<DiskInfo> = (0..32).map(query_disk).filter(|d| !d.model.is_empty() || !d.volumes.is_empty()).collect();
        for d in &disks {
            println!("{}  |  {}  |  {}", d.title(), d.hardware(), d.fullness());
        }
        let found = disks.iter().any(|d| d.volumes.iter().any(|v| v.letter == 'C'));
        assert!(found || std::env::var("SystemDrive").map_or(true, |d| !d.eq_ignore_ascii_case("C:")));
    }
}
