//! What a drive says about its own health: temperature, the NVMe health log, and the handful of
//! SATA SMART attributes that actually predict trouble. Read once when monitoring starts and once
//! when it ends, because a counter that moved *during* the run (thermal throttling, cable CRC
//! errors) is evidence, while a lifetime total is only background.
//!
//! Every read is best effort: USB bridges, RAID drivers and virtual disks often refuse, and then
//! there is simply nothing to report.

use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::System::Ioctl::{
    NVMeDataTypeLogPage, ProtocolTypeNvme, StorageAdapterProtocolSpecificProperty, StorageDeviceProtocolSpecificProperty,
    StorageDeviceTemperatureProperty, IOCTL_STORAGE_QUERY_PROPERTY, SMART_RCV_DRIVE_DATA,
};

use crate::disks::Handle;

/// NVMe SMART / Health Information log page (02h), the fields worth showing.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NvmeHealth {
    /// Bit 0 spare low, 1 temperature, 2 reliability degraded, 3 read-only, 4 backup failed.
    pub critical_warning: u8,
    pub temperature_c: i32,
    pub spare_percent: u8,
    pub spare_threshold: u8,
    pub percent_used: u8,
    pub media_errors: u64,
    pub unsafe_shutdowns: u64,
    pub power_on_hours: u64,
    /// Minutes above the warning / critical temperature, lifetime.
    pub warning_temp_minutes: u32,
    pub critical_temp_minutes: u32,
    /// Seconds spent in (light / heavy) thermal throttling, lifetime. 0 when the drive does not count.
    pub throttle_seconds: u64,
}

/// The SATA SMART attributes that predict failure or point at the cable. Raw values.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SataSmart {
    pub reallocated: Option<u64>,
    pub pending: Option<u64>,
    pub uncorrectable: Option<u64>,
    /// UltraDMA CRC errors: data damaged between drive and motherboard, i.e. the cable or port.
    pub crc_errors: Option<u64>,
    pub temperature_c: Option<i32>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct DriveHealth {
    /// From Windows' generic temperature query; NVMe and SATA readings take precedence.
    pub temperature_c: Option<i32>,
    pub nvme: Option<NvmeHealth>,
    pub sata: Option<SataSmart>,
}

impl DriveHealth {
    pub fn is_empty(&self) -> bool {
        self.temperature_c.is_none() && self.nvme.is_none() && self.sata.is_none()
    }

    pub fn temperature(&self) -> Option<i32> {
        self.nvme.as_ref().map(|n| n.temperature_c).or(self.sata.as_ref().and_then(|s| s.temperature_c)).or(self.temperature_c)
    }
}

/// `bus` is the name from `disks::DiskInfo`, used to skip commands a drive cannot understand.
pub fn read(number: u32, bus: &str) -> DriveHealth {
    let path = format!(r"\\.\PhysicalDrive{number}");
    let mut health = DriveHealth::default();
    if let Some(h) = Handle::open(&path) {
        health.temperature_c = query_temperature(&h);
        // The NVMe health log is a plain property query, so the zero-access handle is enough.
        if bus == "NVMe" {
            health.nvme = query_nvme(&h);
        }
    }
    // SMART (and NVMe on stricter drivers) wants a read/write handle, which needs admin; the monitor
    // has it, unit tests may not.
    let needs_rw = (bus == "NVMe" && health.nvme.is_none()) || matches!(bus, "SATA" | "ATA" | "RAID");
    if let Some(h) = needs_rw.then(|| Handle::open_with(&path, GENERIC_READ | GENERIC_WRITE)).flatten() {
        match bus {
            "NVMe" => health.nvme = query_nvme(&h),
            _ => health.sata = query_sata(&h, number),
        }
    }
    health
}

fn query_temperature(h: &Handle) -> Option<i32> {
    let mut query = [0u8; 12];
    query[..4].copy_from_slice(&(StorageDeviceTemperatureProperty as u32).to_le_bytes());
    let mut out = [0u8; 256];
    let n = h.ioctl(IOCTL_STORAGE_QUERY_PROPERTY, &query, &mut out)?;
    parse_temperature(&out[..n])
}

/// STORAGE_TEMPERATURE_DATA_DESCRIPTOR: InfoCount u16 @12, first STORAGE_TEMPERATURE_INFO @24
/// with Temperature i16 (Celsius) @2.
fn parse_temperature(d: &[u8]) -> Option<i32> {
    if d.len() < 32 || u16::from_le_bytes([d[12], d[13]]) == 0 {
        return None;
    }
    let t = i16::from_le_bytes([d[26], d[27]]) as i32;
    // Drives without a sensor report 0 or nonsense.
    (1..=120).contains(&t).then_some(t)
}

fn query_nvme(h: &Handle) -> Option<NvmeHealth> {
    // STORAGE_PROPERTY_QUERY { PropertyId, QueryType = 0 } whose AdditionalParameters is a
    // STORAGE_PROTOCOL_SPECIFIC_DATA (40 bytes) followed by room for the 512-byte log page.
    const HEADER: usize = 8;
    const SPECIFIC: usize = 40;
    const LOG: usize = 512;
    // Some drivers answer on the device property, some only on the adapter property.
    for property in [StorageDeviceProtocolSpecificProperty, StorageAdapterProtocolSpecificProperty] {
        let mut buf = [0u8; HEADER + SPECIFIC + LOG];
        let put = |buf: &mut [u8], at: usize, v: u32| buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
        put(&mut buf, 0, property as u32);
        put(&mut buf, HEADER, ProtocolTypeNvme as u32);
        put(&mut buf, HEADER + 4, NVMeDataTypeLogPage as u32);
        put(&mut buf, HEADER + 8, 0x02); // log page: SMART / Health Information
        put(&mut buf, HEADER + 16, SPECIFIC as u32); // data offset, from the start of this struct
        put(&mut buf, HEADER + 20, LOG as u32);
        let input = buf;
        let Some(n) = h.ioctl(IOCTL_STORAGE_QUERY_PROPERTY, &input, &mut buf) else { continue };
        // Reply: STORAGE_PROTOCOL_DATA_DESCRIPTOR { Version, Size, STORAGE_PROTOCOL_SPECIFIC_DATA }.
        if n < HEADER + SPECIFIC + LOG {
            continue;
        }
        let offset = u32::from_le_bytes(buf[HEADER + 16..HEADER + 20].try_into().unwrap()) as usize;
        let start = HEADER + offset;
        if let Some(health) = buf.get(start..start + LOG).and_then(parse_nvme_health) {
            return Some(health);
        }
    }
    None
}

/// NVMe spec, SMART / Health Information log. 128-bit counters are read as their low 64 bits.
fn parse_nvme_health(d: &[u8]) -> Option<NvmeHealth> {
    if d.len() < 232 {
        return None;
    }
    let u16_at = |o: usize| u16::from_le_bytes([d[o], d[o + 1]]);
    let u32_at = |o: usize| u32::from_le_bytes(d[o..o + 4].try_into().unwrap());
    let u64_at = |o: usize| u64::from_le_bytes(d[o..o + 8].try_into().unwrap());
    let kelvin = u16_at(1) as i32;
    if kelvin == 0 {
        return None; // an all-zero page: the drive or driver did not really answer
    }
    Some(NvmeHealth {
        critical_warning: d[0],
        temperature_c: kelvin - 273,
        spare_percent: d[3],
        spare_threshold: d[4],
        percent_used: d[5],
        power_on_hours: u64_at(128),
        unsafe_shutdowns: u64_at(144),
        media_errors: u64_at(160),
        warning_temp_minutes: u32_at(192),
        critical_temp_minutes: u32_at(196),
        throttle_seconds: u32_at(224) as u64 + u32_at(228) as u64,
    })
}

fn query_sata(h: &Handle, number: u32) -> Option<SataSmart> {
    // SENDCMDINPARAMS (packed): cBufferSize u32, IDEREGS { Features, SectorCount, SectorNumber,
    // CylLow, CylHigh, DriveHead, Command, reserved }, bDriveNumber, ...; 32 bytes + buffer.
    let mut input = [0u8; 33];
    input[..4].copy_from_slice(&512u32.to_le_bytes());
    input[4] = 0xD0; // SMART READ DATA
    input[5] = 1;
    input[6] = 1;
    input[7] = 0x4F;
    input[8] = 0xC2;
    input[9] = 0xA0;
    input[10] = 0xB0; // SMART
    input[12] = number as u8;
    // SENDCMDOUTPARAMS: cBufferSize u32, DRIVERSTATUS (12 bytes), then the 512-byte sector.
    let mut out = [0u8; 16 + 512];
    let n = h.ioctl(SMART_RCV_DRIVE_DATA, &input, &mut out)?;
    if n < 16 + 362 {
        return None;
    }
    parse_smart_attributes(&out[16..])
}

/// SMART data sector: 30 attribute slots of 12 bytes from offset 2: id, flags u16, current,
/// worst, raw[6], reserved.
fn parse_smart_attributes(d: &[u8]) -> Option<SataSmart> {
    if d.len() < 362 {
        return None;
    }
    let mut smart = SataSmart::default();
    let mut any = false;
    for slot in (0..30).map(|i| &d[2 + i * 12..14 + i * 12]) {
        let raw = slot[5..11].iter().rev().fold(0u64, |acc, b| (acc << 8) | *b as u64);
        match slot[0] {
            0 => continue,
            5 => smart.reallocated = Some(raw),
            197 => smart.pending = Some(raw),
            198 => smart.uncorrectable = Some(raw),
            199 => smart.crc_errors = Some(raw),
            // The raw value packs min/max into the upper bytes; the low byte is the reading.
            194 => smart.temperature_c = Some((raw & 0xFF) as i32).filter(|t| (1..=120).contains(t)),
            190 if smart.temperature_c.is_none() => smart.temperature_c = Some((raw & 0xFF) as i32).filter(|t| (1..=120).contains(t)),
            _ => {}
        }
        any = true;
    }
    any.then_some(smart)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nvme_health_page_is_decoded() {
        let mut d = [0u8; 512];
        d[0] = 0b10; // temperature warning
        d[1..3].copy_from_slice(&(273u16 + 81).to_le_bytes());
        d[3] = 100;
        d[4] = 10;
        d[5] = 7;
        d[128..136].copy_from_slice(&4321u64.to_le_bytes());
        d[144..152].copy_from_slice(&12u64.to_le_bytes());
        d[160..168].copy_from_slice(&3u64.to_le_bytes());
        d[192..196].copy_from_slice(&55u32.to_le_bytes());
        d[224..228].copy_from_slice(&600u32.to_le_bytes());
        d[228..232].copy_from_slice(&30u32.to_le_bytes());
        let h = parse_nvme_health(&d).unwrap();
        assert_eq!((h.critical_warning, h.temperature_c, h.spare_percent, h.spare_threshold, h.percent_used), (2, 81, 100, 10, 7));
        assert_eq!((h.power_on_hours, h.unsafe_shutdowns, h.media_errors), (4321, 12, 3));
        assert_eq!((h.warning_temp_minutes, h.critical_temp_minutes, h.throttle_seconds), (55, 0, 630));
        assert!(parse_nvme_health(&[0u8; 512]).is_none(), "an all-zero page is not an answer");
        assert!(parse_nvme_health(&[1u8; 100]).is_none());
    }

    #[test]
    fn smart_attributes_are_picked_out_by_id() {
        let mut d = [0u8; 512];
        let mut put = |slot: usize, id: u8, raw: u64| {
            let o = 2 + slot * 12;
            d[o] = id;
            d[o + 5..o + 11].copy_from_slice(&raw.to_le_bytes()[..6]);
        };
        put(0, 5, 8);
        put(1, 9, 30_000);
        put(2, 194, 0x0000_0033_0014_0029); // min 20, max 51, now 41
        put(3, 197, 2);
        put(4, 199, 117);
        let s = parse_smart_attributes(&d).unwrap();
        assert_eq!(
            s,
            SataSmart { reallocated: Some(8), pending: Some(2), uncorrectable: None, crc_errors: Some(117), temperature_c: Some(41) }
        );
        assert!(parse_smart_attributes(&[0u8; 512]).is_none());
    }

    #[test]
    fn temperature_descriptor_is_decoded_and_nonsense_is_dropped() {
        let mut d = [0u8; 40];
        d[12] = 1;
        d[26..28].copy_from_slice(&47i16.to_le_bytes());
        assert_eq!(parse_temperature(&d), Some(47));
        d[26..28].copy_from_slice(&0i16.to_le_bytes());
        assert_eq!(parse_temperature(&d), None);
        d[12] = 0;
        assert_eq!(parse_temperature(&d), None);
    }

    #[test]
    fn reading_this_pc_does_not_panic() {
        for n in 0..8 {
            let info = crate::disks::DiskMap::new().get(n).clone();
            if info.model.is_empty() {
                continue;
            }
            let h = read(n, info.bus);
            println!("disk {n} ({}): temp {:?}, nvme {}, sata {}", info.bus, h.temperature(), h.nvme.is_some(), h.sata.is_some());
            if let Some(nv) = h.nvme {
                println!("    {nv:?}");
            }
        }
    }
}
