//! Which PCI devices are on an old-style line-based (INTx) interrupt although their hardware also
//! offers the message-signaled kind (MSI / MSI-X).
//!
//! A line-based interrupt is a shared signal wire: several devices can sit on the same line, and
//! the kernel has to ask each of them whether the interrupt was theirs. A message-signaled one is a
//! write to a fixed address, so it belongs to one device and needs no sharing. This module only
//! reports what is in use and what the hardware advertises. It does NOT claim that a line-based
//! interrupt stalled this PC: nothing here measures that.
//!
//! TWO QUESTIONS, TWO SOURCES.
//!
//! 1. **What is actually in use** comes from the allocated resources the configuration manager
//!    hands out: `CM_Get_First_Log_Conf(ALLOC_LOG_CONF)` then `CM_Get_Next_Res_Des(ResType_IRQ)`,
//!    `CM_Get_Res_Des_Data_Size` and `CM_Get_Res_Des_Data`, which fills an `IRQ_RESOURCE_64`
//!    (`um\cfgmgr32.h`, inside the file's `pshpack1.h` block, so byte-packed: `IRQD_Count` @0,
//!    `IRQD_Type` @4, flags @8, `IRQD_Alloc_Num` @12, `IRQD_Affinity` @16 = 24 bytes, plus one
//!    12-byte `IRQ_RANGE`). Learn:
//!    <https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_get_res_des_data>
//!    - which also warns that this call "returns CR_CALL_NOT_IMPLEMENTED when used in a Wow64
//!      scenario", so **this only works from a native x64 binary**. Adding a 32-bit target would
//!      silently delete this whole feature.
//! 2. **What the hardware can do** comes from `DEVPKEY_PciDevice_InterruptSupport`
//!    (`shared\pciprop.h`: fmtid {3AB22E31-8264-4b4e-9AF5-A8D2D8E33E62}, pid 14; values
//!    `DevProp_PciDevice_InterruptType_LineBased` 1, `_Msi` 2, `_MsiX` 4). Microsoft publishes no
//!    page for `pciprop.h`; the only prose describing these values is the mirrored NDIS structure
//!    <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddndis/ns-ntddndis-_ndis_pci_device_custom_properties>
//!    - "The hardware support for interrupts on the PCI Express device ... This property is valid
//!      only for PCI Express devices". So a missing property means UNKNOWN, never "no MSI".
//!
//! There is no user-mode way to read PCI config space to check for itself: Microsoft documents only
//! `BUS_INTERFACE_STANDARD` and `IRP_MN_READ_CONFIG`, both kernel-mode, and warns that on a machine
//! with an SDEV ACPI table and virtualization-based security, a process reaching config space any
//! other way is met with a **bug check**
//! (<https://learn.microsoft.com/en-us/windows-hardware/drivers/pci/accessing-pci-device-configuration-space>).
//! These properties are the whole of what a driverless tool may know.

use std::ffi::c_void;

use windows_sys::core::GUID;
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Free_Log_Conf_Handle, CM_Free_Res_Des_Handle, CM_Get_DevNode_PropertyW, CM_Get_First_Log_Conf, CM_Get_Next_Res_Des,
    CM_Get_Res_Des_Data, CM_Get_Res_Des_Data_Size, ResType_IRQ, ALLOC_LOG_CONF, CR_SUCCESS,
};
use windows_sys::Win32::Devices::Properties::DEVPROP_TYPE_UINT32;
use windows_sys::Win32::Foundation::DEVPROPKEY;

use crate::devices::{clean_desc, devnode};
use crate::reg;

const ENUM_PCI: &str = r"SYSTEM\CurrentControlSet\Enum\PCI";

// pciprop.h:190-196 defines the seed GUID for every PCI device property; :349 and :357 give the
// two ids. Declared here rather than by enabling the `Win32_NetworkManagement_WiFi` feature, which
// is the surprising module windows-sys files `DEVPKEY_PciDevice_*` under.
const PCI_DEVICE_FMTID: GUID = GUID::from_u128(0x3ab2_2e31_8264_4b4e_9af5_a8d2_d8e3_3e62);
const DEVPKEY_PCI_INTERRUPT_SUPPORT: DEVPROPKEY = DEVPROPKEY { fmtid: PCI_DEVICE_FMTID, pid: 14 };

// pciprop.h:345-347
const INT_LINE_BASED: u32 = 1;
const INT_MSI: u32 = 2;
const INT_MSI_X: u32 = 4;

// cfgmgr32.h:461-476. NOTE the header's own warning that 32-bit ConfigMgr reverses the meaning of
// the level bit; the values below are the 32-bit-and-later ones the comment describes.
const M_IRQD_EDGE_LEVEL: u32 = 0x2;
const F_IRQD_LEVEL: u32 = 0x0;
const F_IRQD_EDGE: u32 = 0x2;

/// `IRQ_DES_64` is 24 bytes; anything shorter is not the structure we think it is.
const IRQ_DES_64_LEN: u32 = 24;
/// An MSI allocation is reported as a small negative number in an unsigned field, which is what
/// Device Manager renders as a negative IRQ. Every MSI descriptor on the development PC fell in
/// `0xFFFFFF00..=0xFFFFFFFE`, and the largest real line number there was 511, so this separates
/// them with an enormous margin. Corroboration only: Microsoft documents no such rule, so the
/// flags below are the primary test and a disagreement means "say nothing".
const MSI_ALLOC_FLOOR: u32 = 0xFFFF_0000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IrqMode {
    /// Shared signal line (INTx).
    LineBased,
    /// Message-signaled (MSI or MSI-X).
    Message,
}

/// What `DEVPKEY_PciDevice_InterruptSupport` says the silicon can do.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Support {
    /// The hardware advertises MSI or MSI-X.
    HasMessage,
    /// The hardware advertises line-based interrupts only.
    LineOnly,
    /// The property is absent, empty or not a UINT32. Common on conventional (non-Express) PCI,
    /// where Microsoft says the property is not valid at all. Never read as "no MSI".
    Unknown,
}

/// What the registry records about the driver package's message-signaled-interrupt opt-in.
///
/// Microsoft documents the value
/// (<https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/enabling-message-signaled-interrupts-in-the-registry>:
/// "The MSISupported entry ... is a REG_DWORD value that determines whether the device supports
/// MSIs. Set MSISupported to 1 to enable MSI support.") and documents **no** meaning for a 0 and
/// none for the key being absent. So the three states stay three states, and "absent" is never
/// rendered as "disabled".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MsiOptIn {
    /// No `MessageSignaledInterruptProperties` key, or no `MSISupported` value in it.
    NotRecorded,
    /// `MSISupported = 0`: written deliberately by an INF or by a person.
    TurnedOff,
    /// `MSISupported = 1`.
    TurnedOn,
    /// Some other number. Microsoft documents only 1, so anything else is not interpreted.
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PciInterrupt {
    pub instance_id: String,
    pub name: String,
    pub mode: IrqMode,
    pub support: Support,
    pub opt_in: MsiOptIn,
    /// `MessageNumberLimit`, when the registry holds one: "a REG_DWORD value that specifies the
    /// maximum number of MSIs to allocate" (same Learn page as `MsiOptIn`). Read, never written,
    /// and shown only where it is set: Microsoft documents no default for it being absent.
    pub message_limit: Option<u32>,
    /// How many interrupt resources the device holds. A device on MSI-X can hold dozens.
    pub allocations: usize,
}

impl PciInterrupt {
    /// The device is on a shared line although its own hardware advertises the newer kind.
    pub fn legacy_despite_hardware(&self) -> bool {
        self.mode == IrqMode::LineBased && self.support == Support::HasMessage
    }
}

/// One interrupt resource descriptor, classified.
///
/// Two independent signals in the same 36 bytes, and both have to agree:
///
/// * `IRQD_Flags` low 16 bits. Line-based read `0x0001` (`fIRQD_Share | fIRQD_Level`: shareable and
///   level-sensitive, the INTx signature) on every device tested; message-signaled read `0x0002`
///   (`fIRQD_Exclusive | fIRQD_Edge`). This is the documented, meaningful test.
/// * `IRQD_Alloc_Num` magnitude (see `MSI_ALLOC_FLOOR`). Corroboration.
///
/// Only the low 16 bits of the flags word are looked at: no SDK header defines
/// `NT_PROCESSOR_GROUPS`, so whether the high half is `IRQD_Group` or undocumented flag bits is
/// unknown, and on the development PC it read 1 on a single-group machine. Returns `None` when the
/// buffer is too short or the two signals disagree - reporting nothing is the honest failure.
pub fn classify(size: u32, flags_word: u32, alloc_num: u32) -> Option<IrqMode> {
    if size < IRQ_DES_64_LEN {
        return None;
    }
    let by_flags = match (flags_word & 0xFFFF) & M_IRQD_EDGE_LEVEL {
        F_IRQD_EDGE => IrqMode::Message,
        F_IRQD_LEVEL => IrqMode::LineBased,
        _ => return None,
    };
    let by_number = if alloc_num >= MSI_ALLOC_FLOOR { IrqMode::Message } else { IrqMode::LineBased };
    (by_flags == by_number).then_some(by_flags)
}

/// `DEVPKEY_PciDevice_InterruptSupport`'s bitmask, read honestly.
pub fn hardware_support(raw: Option<u32>) -> Support {
    match raw {
        Some(bits) if bits & (INT_MSI | INT_MSI_X) != 0 => Support::HasMessage,
        // Line-based only is a real answer; a bitmask of 0 is not, so it stays unknown.
        Some(bits) if bits & INT_LINE_BASED != 0 => Support::LineOnly,
        _ => Support::Unknown,
    }
}

pub fn opt_in_of(value: Option<u32>) -> MsiOptIn {
    match value {
        None => MsiOptIn::NotRecorded,
        Some(0) => MsiOptIn::TurnedOff,
        Some(1) => MsiOptIn::TurnedOn,
        Some(_) => MsiOptIn::Other,
    }
}

/// Which kind of interrupt a driver's handler was seen running for in the kernel trace: ISR events
/// with PerfInfo event type 50 (the message-signaled hook) or 67 (the documented ISR event, by
/// elimination the line-based kind). See `etw::events` for what is and is not documented.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Observed {
    Message,
    Line,
    Both,
}

impl Observed {
    /// From the two counts; `None` when the driver ran no interrupt handler at all.
    pub fn from_counts(line: u64, message: u64) -> Option<Observed> {
        match (line > 0, message > 0) {
            (true, true) => Some(Observed::Both),
            (true, false) => Some(Observed::Line),
            (false, true) => Some(Observed::Message),
            (false, false) => None,
        }
    }

    /// Plain words for a table cell.
    pub fn words(self) -> &'static str {
        match self {
            Observed::Message => "message-signaled",
            Observed::Line => "line-based",
            Observed::Both => "both kinds",
        }
    }
}

/// Where the configuration and the trace disagree about one driver, the line that says so.
///
/// Only drivers whose devices are ALL in the interrupt list and ALL on the same mode are judged:
/// a driver that serves several devices on different modes, or a device this list does not have
/// (not PCI, no interrupt resources, or signals that disagreed), could be where an interrupt came
/// from, and which device's interrupt a handler ran for is not in the event. So nothing is said
/// about those rather than guessing. `served` is the instance ids of the present devices the
/// driver serves (from the device registry).
pub fn disagreement(driver: &str, served: &[&str], devices: &[PciInterrupt], seen: Observed) -> Option<String> {
    let mine: Vec<&PciInterrupt> = served.iter().filter_map(|id| devices.iter().find(|d| d.instance_id.eq_ignore_ascii_case(id))).collect();
    if mine.is_empty() || mine.len() != served.len() {
        return None;
    }
    let mode = mine[0].mode;
    if mine.iter().any(|d| d.mode != mode) {
        return None;
    }
    let configured = match mode {
        IrqMode::LineBased => Observed::Line,
        IrqMode::Message => Observed::Message,
    };
    if seen == configured {
        return None;
    }
    let what = if mine.len() == 1 { format!("its device ({}) is", mine[0].name) } else { format!("all {} of its devices are", mine.len()) };
    let config_words = match mode {
        IrqMode::LineBased => "on a line-based interrupt",
        IrqMode::Message => "on message-signaled interrupts",
    };
    Some(format!(
        "  {driver}: Windows' configuration says {what} {config_words}, but the trace saw its interrupt handler run for {} interrupts.",
        match seen {
            Observed::Both => "both kinds of",
            other => other.words(),
        }
    ))
}

/// Every present PCI device, with the interrupt mode it is actually using.
///
/// Devices that take no interrupt at all (most bridges), and devices whose two signals disagree,
/// are simply absent from the result.
pub fn devices() -> Vec<PciInterrupt> {
    let mut out = Vec::new();
    for hw in reg::subkeys(ENUM_PCI) {
        for instance in reg::subkeys(&format!(r"{ENUM_PCI}\{hw}")) {
            let key = format!(r"{ENUM_PCI}\{hw}\{instance}");
            let instance_id = format!(r"PCI\{hw}\{instance}");
            let Some(devinst) = devnode(&instance_id) else { continue };
            let modes = irq_modes(devinst);
            if modes.is_empty() {
                continue;
            }
            // A device holding both kinds at once is not something this tool has ever observed and
            // not something it will guess about.
            let first = modes[0];
            if modes.iter().any(|m| *m != first) {
                continue;
            }
            let name = reg::hklm_path(&key, "FriendlyName")
                .or_else(|| reg::hklm_path(&key, "DeviceDesc"))
                .map(|d| clean_desc(&d))
                .unwrap_or_else(|| instance_id.clone());
            // Both values live in the device's hardware key; read-only (`reg` never writes).
            let props = format!(r"{key}\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties");
            let msi = reg::hklm_dword(&props, "MSISupported");
            out.push(PciInterrupt {
                instance_id,
                name,
                mode: first,
                support: hardware_support(devnode_u32(devinst, &DEVPKEY_PCI_INTERRUPT_SUPPORT)),
                opt_in: opt_in_of(msi),
                message_limit: reg::hklm_dword(&props, "MessageNumberLimit"),
                allocations: modes.len(),
            });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.instance_id.cmp(&b.instance_id)));
    out
}

/// The interrupt resources one device node holds, classified. One descriptor per allocated message,
/// so an NVMe controller on MSI-X yields dozens of identical answers.
fn irq_modes(devinst: u32) -> Vec<IrqMode> {
    let mut modes = Vec::new();
    let mut log_conf: usize = 0;
    if unsafe { CM_Get_First_Log_Conf(&mut log_conf, devinst, ALLOC_LOG_CONF) } != CR_SUCCESS {
        return modes;
    }
    let mut res: usize = 0;
    let mut res_type = 0u32;
    // The first call walks from the log conf handle; later ones from the previous descriptor.
    let mut from = log_conf;
    // Bounded: a device with an absurd number of descriptors must not hold the report up.
    for _ in 0..4096 {
        if unsafe { CM_Get_Next_Res_Des(&mut res, from, ResType_IRQ, &mut res_type, 0) } != CR_SUCCESS {
            break;
        }
        let mut size = 0u32;
        if unsafe { CM_Get_Res_Des_Data_Size(&mut size, res, 0) } == CR_SUCCESS && size >= IRQ_DES_64_LEN {
            let mut buf = vec![0u8; size as usize];
            if unsafe { CM_Get_Res_Des_Data(res, buf.as_mut_ptr() as *mut c_void, size, 0) } == CR_SUCCESS {
                let word = |at: usize| u32::from_le_bytes(buf[at..at + 4].try_into().unwrap_or([0; 4]));
                if let Some(mode) = classify(size, word(8), word(12)) {
                    modes.push(mode);
                }
            }
        }
        if from != log_conf {
            unsafe { CM_Free_Res_Des_Handle(from) };
        }
        from = res;
    }
    if from != log_conf {
        unsafe { CM_Free_Res_Des_Handle(from) };
    }
    unsafe { CM_Free_Log_Conf_Handle(log_conf) };
    modes
}

/// A UINT32 device property, or `None` when it is absent or is some other type.
fn devnode_u32(devinst: u32, key: &DEVPROPKEY) -> Option<u32> {
    let mut kind: u32 = 0;
    let mut buf = [0u8; 4];
    let mut len = buf.len() as u32;
    let cr = unsafe { CM_Get_DevNode_PropertyW(devinst, key, &mut kind, buf.as_mut_ptr(), &mut len, 0) };
    (cr == CR_SUCCESS && kind == DEVPROP_TYPE_UINT32 && len == 4).then(|| u32::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real numbers read off the development PC: flags 0x1 with a small IRQ for the three HD
    /// Audio functions, flags 0x2 with a near-2^32 number for the GPU and the NVMe controllers.
    #[test]
    fn the_two_signals_in_a_descriptor_have_to_agree() {
        assert_eq!(classify(36, 0x0000_0001, 43), Some(IrqMode::LineBased));
        assert_eq!(classify(36, 0x0000_0001, 25), Some(IrqMode::LineBased));
        assert_eq!(classify(36, 0x0001_0002, 0xFFFF_FF64), Some(IrqMode::Message), "the high half of the flags word is ignored");
        assert_eq!(classify(36, 0x0001_0002, 0xFFFF_FFB3), Some(IrqMode::Message));
        // The largest real line number seen is 511, nowhere near the floor.
        assert_eq!(classify(36, 0x0000_0001, 511), Some(IrqMode::LineBased));
        // Disagreement: report nothing rather than pick a winner.
        assert_eq!(classify(36, 0x0000_0002, 43), None);
        assert_eq!(classify(36, 0x0000_0001, 0xFFFF_FFFE), None);
        // Too short to be IRQ_DES_64.
        assert_eq!(classify(20, 0x0000_0001, 43), None);
        assert_eq!(classify(24, 0x0000_0001, 43), Some(IrqMode::LineBased), "exactly the header is enough");
    }

    /// 7 = LineBased|Msi|MsiX and 3 = LineBased|Msi are what the real devices reported.
    #[test]
    fn hardware_capability_is_never_guessed_from_an_absent_property() {
        assert_eq!(hardware_support(Some(7)), Support::HasMessage);
        assert_eq!(hardware_support(Some(3)), Support::HasMessage);
        assert_eq!(hardware_support(Some(4)), Support::HasMessage);
        assert_eq!(hardware_support(Some(1)), Support::LineOnly);
        assert_eq!(hardware_support(None), Support::Unknown, "absent means unknown, never 'no MSI'");
        assert_eq!(hardware_support(Some(0)), Support::Unknown);
    }

    #[test]
    fn the_registry_opt_in_keeps_its_three_states_apart() {
        assert_eq!(opt_in_of(None), MsiOptIn::NotRecorded);
        assert_eq!(opt_in_of(Some(0)), MsiOptIn::TurnedOff);
        assert_eq!(opt_in_of(Some(1)), MsiOptIn::TurnedOn);
        assert_eq!(opt_in_of(Some(2)), MsiOptIn::Other);
        assert_ne!(MsiOptIn::NotRecorded, MsiOptIn::TurnedOff, "'never asked' is not 'turned off'");
    }

    #[test]
    fn a_device_is_only_flagged_when_both_halves_of_the_test_hold() {
        let dev = |mode, support| PciInterrupt {
            instance_id: "PCI\\X".into(),
            name: "X".into(),
            mode,
            support,
            opt_in: MsiOptIn::NotRecorded,
            message_limit: None,
            allocations: 1,
        };
        assert!(dev(IrqMode::LineBased, Support::HasMessage).legacy_despite_hardware());
        assert!(!dev(IrqMode::LineBased, Support::Unknown).legacy_despite_hardware(), "unknown hardware is not evidence");
        assert!(!dev(IrqMode::LineBased, Support::LineOnly).legacy_despite_hardware(), "nothing to say: the hardware has no choice");
        assert!(!dev(IrqMode::Message, Support::HasMessage).legacy_despite_hardware());
    }

    #[test]
    fn what_the_trace_saw_is_read_from_the_two_counts() {
        assert_eq!(Observed::from_counts(0, 0), None, "no interrupt handler ran: nothing to say");
        assert_eq!(Observed::from_counts(5, 0), Some(Observed::Line));
        assert_eq!(Observed::from_counts(0, 9), Some(Observed::Message));
        assert_eq!(Observed::from_counts(1, 1), Some(Observed::Both));
        assert_eq!(Observed::Message.words(), "message-signaled");
        assert_eq!(Observed::Line.words(), "line-based");
    }

    fn pci(id: &str, name: &str, mode: IrqMode) -> PciInterrupt {
        PciInterrupt {
            instance_id: id.into(),
            name: name.into(),
            mode,
            support: Support::HasMessage,
            opt_in: MsiOptIn::NotRecorded,
            message_limit: None,
            allocations: 1,
        }
    }

    /// A disagreement is one fact line, and only where it cannot be about the wrong device.
    #[test]
    fn configuration_and_trace_are_compared_only_where_the_device_is_certain() {
        let devices = [
            pci(r"PCI\VEN_10DE&DEV_1\3&1", "NVIDIA GeForce RTX 5090", IrqMode::Message),
            pci(r"PCI\VEN_1022&DEV_2\3&2", "High Definition Audio Controller", IrqMode::LineBased),
            pci(r"PCI\VEN_1022&DEV_2\3&3", "High Definition Audio Controller", IrqMode::LineBased),
            pci(r"PCI\VEN_144D&DEV_3\4&1", "Standard NVM Express Controller", IrqMode::Message),
        ];
        // One device, configured line-based, handler seen on the MSI event: said, naming the device.
        let line = disagreement("gpu.sys", &[r"PCI\VEN_1022&DEV_2\3&2"], &devices, Observed::Message).expect("a disagreement");
        assert!(line.contains("its device (High Definition Audio Controller) is on a line-based interrupt"), "{line}");
        assert!(line.contains("message-signaled interrupts"), "{line}");
        // ...and the other way round, with the id in another case (the registry is case-blind).
        let line = disagreement("nvlddmkm.sys", &[r"pci\ven_10de&dev_1\3&1"], &devices, Observed::Line).unwrap();
        assert!(line.contains("on message-signaled interrupts, but the trace saw") && line.ends_with("line-based interrupts."), "{line}");
        // Two devices on the same mode: still certain, and counted.
        let both = [r"PCI\VEN_1022&DEV_2\3&2", r"PCI\VEN_1022&DEV_2\3&3"];
        let line = disagreement("HDAudBus.sys", &both, &devices, Observed::Both).unwrap();
        assert!(line.contains("all 2 of its devices are") && line.contains("both kinds of interrupts"), "{line}");
        // Agreement says nothing.
        assert_eq!(disagreement("HDAudBus.sys", &both, &devices, Observed::Line), None);
        assert_eq!(disagreement("stornvme.sys", &[r"PCI\VEN_144D&DEV_3\4&1"], &devices, Observed::Message), None);
        // A driver serving devices on different modes: which one fired is not in the event.
        let mixed = [r"PCI\VEN_10DE&DEV_1\3&1", r"PCI\VEN_1022&DEV_2\3&2"];
        assert_eq!(disagreement("x.sys", &mixed, &devices, Observed::Line), None);
        assert_eq!(disagreement("x.sys", &mixed, &devices, Observed::Message), None);
        // A device the interrupt list does not have (not PCI, or no interrupt resources) could be
        // the one that fired: nothing is said.
        assert_eq!(disagreement("x.sys", &[r"PCI\VEN_1022&DEV_2\3&2", r"ACPI\PNP0303\0"], &devices, Observed::Message), None);
        assert_eq!(disagreement("Wdf01000.sys", &[], &devices, Observed::Message), None, "serves no device of its own");
    }

    /// Prints what this machine really has. No count asserted: CI runners have no PCI devices.
    #[test]
    fn reading_this_pcs_interrupt_modes_does_not_panic() {
        let start = std::time::Instant::now();
        let found = devices();
        println!("{} PCI devices hold interrupt resources ({:?})", found.len(), start.elapsed());
        for d in found.iter().filter(|d| d.mode == IrqMode::LineBased) {
            println!("  LINE-BASED  {:<52} hardware={:?} MSISupported={:?}", d.name, d.support, d.opt_in);
        }
        for d in found.iter().filter(|d| d.message_limit.is_some()) {
            println!("  MessageNumberLimit = {:?} on {}", d.message_limit, d.name);
        }
        println!("  on message-signaled interrupts: {}", found.iter().filter(|d| d.mode == IrqMode::Message).count());
        println!("  line-based although the hardware offers MSI: {}", found.iter().filter(|d| d.legacy_despite_hardware()).count());
    }
}
