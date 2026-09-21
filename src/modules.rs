//! Maps kernel addresses (DPC/ISR routines, sampled instruction pointers) to loaded drivers,
//! and knows what the usual suspects are.

use std::collections::HashMap;
use std::ffi::c_void;
use std::ptr::null_mut;
use std::time::Instant;

use windows_sys::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};

use crate::util::{from_wide, wide};

#[link(name = "ntdll")]
extern "system" {
    fn NtQuerySystemInformation(class: u32, info: *mut c_void, len: u32, ret_len: *mut u32) -> i32;
}

const SYSTEM_MODULE_INFORMATION: u32 = 11;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;
const ENTRY_SIZE: usize = 296; // RTL_PROCESS_MODULE_INFORMATION on x64

pub const KERNEL_SPACE: u64 = 0xFFFF_8000_0000_0000;

pub struct KModule {
    pub base: u64,
    pub size: u64,
    pub name: String,
    pub path: String,
}

pub struct ModuleMap {
    mods: Vec<KModule>,
    last_refresh: Instant,
    vendor_cache: HashMap<String, Option<String>>,
}

impl ModuleMap {
    pub fn load() -> ModuleMap {
        let mut m = ModuleMap { mods: Vec::new(), last_refresh: Instant::now(), vendor_cache: HashMap::new() };
        m.refresh();
        m
    }

    /// Synthetic module list for tests: no live system lookups, ever. `modules` is
    /// (name, base address, size); pick names that resolve harmlessly, e.g. via the
    /// knowledge base (`describe`/`describe_short` return without touching disk) or
    /// names that plainly aren't real files (`describe` then falls back to "unidentified driver").
    #[cfg(test)]
    pub fn for_test(modules: &[(&str, u64, u64)]) -> ModuleMap {
        let mods = modules
            .iter()
            .map(|(name, base, size)| KModule { base: *base, size: *size, name: name.to_string(), path: name.to_string() })
            .collect();
        ModuleMap { mods, last_refresh: Instant::now(), vendor_cache: HashMap::new() }
    }

    pub fn len(&self) -> usize {
        self.mods.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mods.is_empty()
    }

    /// File names of every loaded kernel module, e.g. `ndis.sys`, `HWiNFO_x64_215.sys`.
    ///
    /// Note for anyone testing this: at medium integrity Windows hides kernel addresses, so a
    /// non-elevated process gets an empty or useless list. The tool itself runs elevated.
    pub fn file_names(&self) -> Vec<String> {
        self.mods.iter().map(|m| m.name.clone()).collect()
    }

    /// Whether a loaded driver's own version resource says Microsoft wrote it.
    ///
    /// The version resource rather than the code signature: `WinVerifyTrust` would mean a new
    /// windows-sys feature and revocation checks (disk, and potentially network) in the middle of a
    /// measuring run, and it answers "who signed this" rather than "who wrote this". `CompanyName`
    /// is what Microsoft's own vulnerable-driver blocklist keys on. Unknown when the file has no
    /// readable version resource, which is itself unusual for an in-box driver.
    pub fn is_microsoft(&mut self, name: &str) -> Option<bool> {
        let company = self.company(name)?;
        Some(company.to_ascii_lowercase().starts_with("microsoft"))
    }

    /// `CompanyName` from a loaded driver's version resource.
    pub fn company(&mut self, name: &str) -> Option<String> {
        let path = self.mods.iter().find(|m| m.name.eq_ignore_ascii_case(name)).map(|m| dos_path(&m.path))?;
        version_field(&path, "CompanyName")
    }

    pub fn refresh(&mut self) {
        self.last_refresh = Instant::now();
        let mut len = 1u32 << 18;
        let buf = loop {
            let mut buf = vec![0u8; len as usize];
            let mut ret = 0u32;
            let st = unsafe { NtQuerySystemInformation(SYSTEM_MODULE_INFORMATION, buf.as_mut_ptr() as _, len, &mut ret) };
            if st == STATUS_INFO_LENGTH_MISMATCH && len < (1 << 26) {
                len = ret.max(len * 2);
                continue;
            }
            if st < 0 {
                return;
            }
            break buf;
        };
        let count = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let mut mods = Vec::with_capacity(count);
        for i in 0..count {
            let Some(e) = buf.get(8 + i * ENTRY_SIZE..8 + (i + 1) * ENTRY_SIZE) else { break };
            let base = u64::from_le_bytes(e[16..24].try_into().unwrap());
            let size = u32::from_le_bytes(e[24..28].try_into().unwrap()) as u64;
            let name_off = u16::from_le_bytes(e[38..40].try_into().unwrap()) as usize;
            let raw = &e[40..296];
            let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            let path = String::from_utf8_lossy(&raw[..end]).into_owned();
            let name = path.get(name_off.min(path.len())..).unwrap_or(&path).to_string();
            if base != 0 {
                mods.push(KModule { base, size, name, path });
            }
        }
        mods.sort_by_key(|m| m.base);
        self.mods = mods;
    }

    fn find(&self, addr: u64) -> Option<&KModule> {
        let i = self.mods.partition_point(|m| m.base <= addr);
        let m = self.mods.get(i.checked_sub(1)?)?;
        (addr < m.base + m.size).then_some(m)
    }

    /// Driver file name for a kernel address. Reloads the module list (rate limited)
    /// when the address is unknown, since drivers can load after we started.
    pub fn name(&mut self, addr: u64) -> String {
        if self.find(addr).is_none() && self.last_refresh.elapsed().as_secs() >= 5 {
            self.refresh();
        }
        match self.find(addr) {
            Some(m) => m.name.clone(),
            None => format!("unknown@{addr:#x}"),
        }
    }

    /// "driver.sys+0x1234"
    pub fn symbolish(&mut self, addr: u64) -> String {
        let name = self.name(addr);
        match self.find(addr) {
            Some(m) => format!("{name}+{:#x}", addr - m.base),
            None => name,
        }
    }

    /// `describe` without the parenthesized elaboration, for headlines and one-line verdicts.
    pub fn describe_short(&mut self, name: &str) -> String {
        let full = self.describe(name);
        match full.find(" (") {
            Some(i) if i > 0 => full[..i].to_string(),
            _ => full,
        }
    }

    /// One-line explanation of what a module is: knowledge base first, then the
    /// file's own version resource (vendor + description).
    pub fn describe(&mut self, name: &str) -> String {
        if let Some(k) = knowledge(name) {
            return k.what.to_string();
        }
        let key = name.to_ascii_lowercase();
        if !self.vendor_cache.contains_key(&key) {
            let info = self.mods.iter().find(|m| m.name.eq_ignore_ascii_case(name)).and_then(|m| version_strings(&dos_path(&m.path)));
            self.vendor_cache.insert(key.clone(), info);
        }
        self.vendor_cache[&key].clone().unwrap_or_else(|| "unidentified driver".into())
    }
}

/// A driver's binary path as the kernel or an `ImagePath` registry value spells it, turned into
/// something that can be opened: `\SystemRoot\...`, `\??\C:\...`, a bare `\...` and the relative
/// `System32\drivers\x.sys` form all occur in practice.
pub fn dos_path(nt: &str) -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let nt = nt.trim().trim_matches('"');
    if let Some(rest) = nt.strip_prefix("\\SystemRoot\\") {
        format!("{root}\\{rest}")
    } else if let Some(rest) = nt.strip_prefix("\\??\\") {
        rest.to_string()
    } else if nt.starts_with('\\') {
        format!("{}{nt}", &root[..2])
    } else if nt.len() > 1 && nt.as_bytes()[1] == b':' {
        nt.to_string()
    } else {
        // "System32\DRIVERS\pacer.sys" - the form a service's ImagePath uses most often.
        format!("{root}\\{nt}")
    }
}

/// Named strings from a file's version resource, in the order asked for.
fn version_fields(path: &str, fields: &[&str]) -> Option<Vec<Option<String>>> {
    unsafe {
        let w = wide(path);
        let mut dummy = 0u32;
        let size = GetFileVersionInfoSizeW(w.as_ptr(), &mut dummy);
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        if GetFileVersionInfoW(w.as_ptr(), 0, size, buf.as_mut_ptr() as _) == 0 {
            return None;
        }
        let mut p: *mut c_void = null_mut();
        let mut len = 0u32;
        if VerQueryValueW(buf.as_ptr() as _, wide("\\VarFileInfo\\Translation").as_ptr(), &mut p, &mut len) == 0 || len < 4 {
            return None;
        }
        let tr = std::slice::from_raw_parts(p as *const u16, 2);
        let out = fields
            .iter()
            .map(|field| {
                let q = wide(&format!("\\StringFileInfo\\{:04x}{:04x}\\{field}", tr[0], tr[1]));
                let mut p: *mut c_void = null_mut();
                let mut len = 0u32;
                if VerQueryValueW(buf.as_ptr() as _, q.as_ptr(), &mut p, &mut len) == 0 || len == 0 {
                    return None;
                }
                let s = from_wide(std::slice::from_raw_parts(p as *const u16, len as usize));
                (!s.trim().is_empty()).then(|| s.trim().to_string())
            })
            .collect();
        Some(out)
    }
}

/// One named string from a file's version resource. Used for files that are not loaded modules
/// (a network filter driver's binary, say), so it takes a path rather than a module name.
pub fn version_field(path: &str, field: &str) -> Option<String> {
    version_fields(path, &[field])?.into_iter().next().flatten()
}

fn version_strings(path: &str) -> Option<String> {
    let v = version_fields(path, &["CompanyName", "FileDescription"])?;
    match (v[0].clone(), v[1].clone()) {
        (Some(c), Some(d)) => Some(format!("{d} ({c})")),
        (c, d) => d.or(c),
    }
}

pub struct Knowledge {
    pub what: &'static str,
    pub advice: &'static str,
}

/// Lower-case file name prefixes of drivers that show up again and again in stall hunts.
const KB: &[(&[&str], Knowledge)] = &[
    (&["nvlddmkm"], Knowledge {
        what: "NVIDIA GPU driver",
        advice: "Clean-reinstall the NVIDIA driver (DDU), try an older/newer version, test with Hardware-Accelerated GPU Scheduling toggled, set power mode to 'Prefer maximum performance', and close GPU overlays/monitoring tools.",
    }),
    (&["amdkmdag", "atikmdag", "atikmpag"], Knowledge {
        what: "AMD GPU driver",
        advice: "Clean-reinstall the AMD driver (DDU / AMD Cleanup Utility), try another version, and disable overlay/metrics features in Adrenalin.",
    }),
    (&["igdkmd", "igfx"], Knowledge {
        what: "Intel GPU driver",
        advice: "Update the Intel graphics driver from Intel directly (not the OEM one), or disable the iGPU if a discrete GPU is used.",
    }),
    (&["dxgkrnl", "dxgmms"], Knowledge {
        what: "DirectX graphics kernel (acts on behalf of the GPU driver)",
        advice: "This is almost always the GPU driver underneath: update/clean-reinstall it, and test with overlays, HAGS and multi-monitor mixed refresh rates disabled.",
    }),
    (&["ndis", "tcpip", "netio", "afd", "fwpkclnt"], Knowledge {
        what: "Windows network stack (acts on behalf of the NIC / Wi-Fi driver or a network filter)",
        advice: "Update the Ethernet/Wi-Fi driver from the chip vendor, disable adapter power saving and 'Interrupt Moderation' as a test, and remove VPN / 'gaming network optimizer' / firewall filter software. Test with Wi-Fi disabled.",
    }),
    (&["netwtw", "netwbw", "netwlv", "rtwlan", "rtwlane", "mtkwl", "athw", "athwn", "bcmwl", "qcamain", "qcwlan"], Knowledge {
        what: "Wi-Fi adapter driver",
        advice: "Update the Wi-Fi driver from the chip vendor (Intel/Realtek/MediaTek/Qualcomm), disable adapter power saving and background scanning/roaming aggressiveness; test with Wi-Fi off and Ethernet in.",
    }),
    (&["rt640", "rt68c", "rtcx21", "rt25cx", "e1d", "e1r", "e1i", "e2f", "e1c", "e2xw", "killer", "aqnic"], Knowledge {
        what: "Ethernet adapter driver",
        advice: "Update the NIC driver from the chip vendor (Realtek/Intel/Marvell), and test with Energy-Efficient Ethernet, Green Ethernet and Interrupt Moderation disabled.",
    }),
    (&["storport", "stornvme", "storahci", "iastor", "amd_sata", "amdsbs", "classpnp", "disk.sys", "partmgr", "secnvme", "nvme"], Knowledge {
        what: "Storage driver stack",
        advice: "Check drive health (SMART), update SSD firmware and the storage controller/chipset driver, make sure the drive is not nearly full, and try disabling aggressive link power management (ASPM/LPM).",
    }),
    (&["usbxhci", "usbport", "usbhub", "ucx01000", "usbehci", "usbccgp", "usbaudio"], Knowledge {
        what: "USB controller / device stack",
        advice: "Unplug USB devices one at a time (hubs, RGB controllers, webcams, DACs, wireless dongles), try other ports/controllers, update chipset drivers and disable USB selective suspend.",
    }),
    (&["hdaudbus", "portcls", "rtkvhd", "rtkhda", "nvhda", "atihdw", "intcaud", "ksthunk"], Knowledge {
        what: "Audio driver",
        advice: "Update or replace the audio driver (try the generic Microsoft HD Audio driver), and disable unused audio devices such as monitor/HDMI audio and audio 'enhancement' suites (Nahimic, Sonic Studio, DTS...).",
    }),
    (&["acpi.sys", "acpiex", "intelpep", "amdpep"], Knowledge {
        what: "ACPI / platform power (firmware-driven: embedded controller, battery, thermal)",
        advice: "Update the BIOS/UEFI and chipset drivers. On laptops, the battery/EC polling is a classic cause: test on AC, and remove OEM 'control center' utilities.",
    }),
    (&["wdf01000"], Knowledge {
        what: "Windows Driver Framework host (runs code for some other WDF driver)",
        advice: "The real culprit is a framework-based device driver (often USB, touchpad/HID, Bluetooth, NIC or card reader). Look at the other drivers active in the same incidents, and disable devices one at a time in Device Manager.",
    }),
    (&["ntoskrnl", "ntkrnlmp", "ntkrpamp"], Knowledge {
        what: "Windows kernel (timers, memory manager, scheduler; often doing work queued by other drivers)",
        advice: "Usually a symptom, not the cause: look at other drivers in the same incidents, check for heavy paging (hard faults), and test with CPU power saving (C-states / 'Balanced' plan) changed.",
    }),
    (&["hal.dll", "halmacpi"], Knowledge {
        what: "Hardware Abstraction Layer (timers/interrupt controller/firmware calls)",
        advice: "Update BIOS and chipset drivers; if a 'latency tweak' guide or utility set boot timer options (bcdedit useplatformclock, useplatformtick, disabledynamictick), remove them again so Windows makes its own choice (Microsoft documents the options but no recommended value).",
    }),
    (&["intelppm", "amdppm", "processr"], Knowledge {
        what: "CPU power management driver (C-states / P-states / core parking)",
        advice: "Test with the High/Ultimate Performance power plan, update BIOS + chipset driver, and as an experiment disable deep C-states in the BIOS.",
    }),
    (&["wdfilter", "mpfilter", "mbam", "aswsp", "aswmon", "klif", "klhk", "epfw", "eamon", "bdselfpr", "atc.sys", "symefa", "srtsp", "mfehidk", "sophos", "csagent", "sentinel", "fltmgr"], Knowledge {
        what: "Antivirus / file-system filter driver",
        advice: "Add exclusions for games/projects, test with real-time protection temporarily off, and never run two antivirus products at once.",
    }),
    (&["bthport", "bthusb", "bthenum", "ibtusb", "rtkbt", "btha2dp", "bthhfenum"], Knowledge {
        what: "Bluetooth driver",
        advice: "Update the Bluetooth driver; test with Bluetooth turned off (it shares the radio with Wi-Fi on most cards).",
    }),
    (&["vmbus", "hvix", "hvax", "winhv", "vmswitch", "vid.sys"], Knowledge {
        what: "Hyper-V / virtualization",
        advice: "Hyper-V, WSL2, Core Isolation (VBS/HVCI) or an Android emulator is active. Test with them disabled if latency matters.",
    }),
    (&["i8042prt", "kbdclass", "mouclass", "hidclass", "hidusb", "mouhid", "kbdhid"], Knowledge {
        what: "Keyboard / mouse / HID input driver",
        advice: "Try lowering a very high mouse polling rate (4k/8k Hz), update peripheral firmware, and remove vendor peripheral software as a test.",
    }),
    (&["win32k"], Knowledge {
        what: "Windows window manager / GDI kernel side",
        advice: "Often input hooks or overlays: close overlays, macro tools and screen recorders.",
    }),
];

/// The drivers that RGB / fan / monitoring / overclocking utilities install to reach motherboard
/// chips directly. The file names live in `hwaccess`, where every one is tied to a published
/// source; this is only what the report says about them when one is blamed for a stall.
const HARDWARE_ACCESS: Knowledge = Knowledge {
    what: "Driver of a utility that talks to the motherboard hardware directly (sensors, fans, lighting)",
    advice: "A very common cause of periodic hitches. Fully exit it (not just minimize it) and monitor again; if you run \
             several tools of this kind, do them one at a time. The report lists which ones are running on this PC under \
             'worth knowing'.",
};

/// `PawnIO.sys` is the sandboxed replacement LibreHardwareMonitor, FanControl and OpenRGB moved to
/// in 2025. Telling someone to undo that would be telling them to go back to the raw one.
const SANDBOXED_ACCESS: Knowledge = Knowledge {
    what: "Sandboxed hardware-access driver (PawnIO), used by current monitoring and fan-control tools",
    advice: "This is the safer, sandboxed driver those tools moved to, so it is not something to remove. If it keeps \
             appearing, exit the monitoring or fan-control program using it and monitor again.",
};

pub fn knowledge(name: &str) -> Option<&'static Knowledge> {
    if let Some(tool) = crate::hwaccess::lookup(name) {
        return Some(if tool.sandboxed { &SANDBOXED_ACCESS } else { &HARDWARE_ACCESS });
    }
    let lower = name.to_ascii_lowercase();
    KB.iter().find(|(prefixes, _)| prefixes.iter().any(|p| lower.starts_with(p))).map(|(_, k)| k)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knowledge_matches_by_case_insensitive_prefix() {
        assert_eq!(knowledge("nvlddmkm.sys").unwrap().what, "NVIDIA GPU driver");
        assert_eq!(knowledge("USBXHCI.SYS").unwrap().what, "USB controller / device stack");
        assert!(knowledge("Netwtw14.sys").unwrap().what.contains("Wi-Fi"));
        assert!(knowledge("totally_unknown.sys").is_none());
    }

    /// The hardware-access table decides these, so the advice follows a renamed or suffixed file
    /// that no prefix list would have caught - and never tells anyone to undo the sandboxed one.
    #[test]
    fn hardware_access_drivers_get_their_advice_from_the_sourced_table() {
        for file in ["WinRing0x64.sys", "AsIO3.sys", "HWiNFO_x64_215.sys", "FanControl.sys", "kerneld.x64"] {
            let k = knowledge(file).unwrap_or_else(|| panic!("{file}"));
            assert!(k.what.contains("motherboard hardware directly"), "{file}: {}", k.what);
            assert!(k.advice.contains("Fully exit"), "{file}");
        }
        let safe = knowledge("PawnIO.sys").unwrap();
        assert!(safe.what.contains("Sandboxed") && safe.advice.contains("not something to remove"), "{}", safe.advice);
    }

    #[test]
    fn nt_paths_become_dos_paths() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        assert_eq!(dos_path(r"\SystemRoot\system32\drivers\ndis.sys"), format!(r"{root}\system32\drivers\ndis.sys"));
        assert_eq!(dos_path(r"\??\C:\Program Files\x\y.sys"), r"C:\Program Files\x\y.sys");
        // The relative form a service's ImagePath uses, and a plain absolute path.
        assert_eq!(dos_path(r"System32\drivers\pacer.sys"), format!(r"{root}\System32\drivers\pacer.sys"));
        assert_eq!(dos_path(r#""C:\Program Files\Tool\helper.sys""#), r"C:\Program Files\Tool\helper.sys");
    }
}
