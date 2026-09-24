//! The kernel drivers that RGB, fan-control, monitoring and overclocking utilities install so they
//! can reach motherboard chips directly, and which product each one belongs to.
//!
//! WHY THIS MATTERS. Talking to those chips is not just "unusual": the chipset can turn an ordinary
//! I/O write into a System Management Interrupt, and on a normal UEFI PC servicing one of those
//! parks every processor core until the firmware is done. Windows can neither interrupt it nor see
//! it. See `summary::platform` for the wording; the sources are in the table below.
//!
//! WHERE THE TABLE COMES FROM. Every row is tied to a published source, named per row:
//!
//! * `MS-BL`  - Microsoft's vulnerable-driver blocklist, `DriverPolicy_Enforced.xml` inside
//!   <https://aka.ms/VulnerableDriverBlockList>, documented at
//!   <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules>.
//!   First-party and authoritative for the FILE NAME, but it keys on the PE version resource, and
//!   Microsoft states the list "isn't guaranteed to block every driver found to have vulnerabilities".
//! * `CVE`    - a CVE record from MITRE's CVE Services API (`https://cveawg.mitre.org/api/cve/<ID>`);
//!   the CNA-authored text usually names both the `.sys` and the retail product.
//! * `vendor` - the vendor's own advisory or page, or a coordination body (CERT/CC VU#380058 for
//!   SignalRGB), or the upstream project's own source tree / README.
//! * `catalog` - LOLDrivers <https://github.com/magicsword-io/LOLDrivers> (Apache-2.0; see
//!   THIRD-PARTY-NOTICES.md), read from its per-driver YAML (Company / Product / Description /
//!   signer fields). Community-curated: good for file names and signers, often thin or absent on
//!   product attribution.
//!
//! Eclypsium's Screwed-Drivers list is NOT a source: it is GPL-3.0, which cannot be relicensed
//! under this project's MIT license. Every fact once taken from it was re-sourced on 2026-09-24
//! from LOLDrivers, Microsoft or the vendor, or dropped. Do not add it back.
//!
//! NOTHING IS HERE FROM MEMORY. Products whose driver file could not be tied to a citable source
//! are deliberately absent, and must stay absent: NZXT CAM, Lian Li L-Connect, SteelSeries GG,
//! Logitech G HUB, HWMonitor, current-generation Corsair iCUE, Razer's hardware-access driver (if
//! it has one), Intel XTU (community sites name `iocbios2.sys`; no Intel advisory, blocklist entry
//! or catalog entry does), and Gigabyte RGB Fusion specifically (`gdrv.sys` is verified for APP
//! Center / AORUS Graphics Engine / Xtreme Gaming Engine / OC GURU II, not for RGB Fusion).
//! Four needles that used to be in `modules.rs` had no source at all - `asupio`, `gpcidrv`,
//! `iocbios`, `lghub` - and one, `aida`, could never match: AIDA64's driver is `kerneld.x64`.
//!
//! No hashes and no binaries are shipped: this is names, products and vendors only.

/// How sure we are of a row, and who says so. Carried into the report's detail lines, because
/// "Microsoft's own blocklist names this file" is a different sentence from "a community catalog
/// lists it".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    /// Microsoft's vulnerable-driver blocklist.
    Blocklist,
    /// A CVE record naming both the driver and the product.
    Cve,
    /// The vendor's own advisory or page, a coordination body, or the project's source tree.
    Vendor,
    /// LOLDrivers. Community-curated.
    Catalog,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Blocklist => "Microsoft driver blocklist",
            Source::Cve => "CVE record",
            Source::Vendor => "vendor / project",
            Source::Catalog => "community catalog",
        }
    }
}

pub struct HwTool {
    /// Lower-case. The whole file name, or - when `stem` - a prefix of it, because some vendors
    /// add a per-install or per-session suffix (HWiNFO extracts `HWiNFO_x64_<n>.sys` into %TEMP%).
    needle: &'static str,
    stem: bool,
    /// The product(s) this file is known to ship with.
    pub product: &'static str,
    pub vendor: &'static str,
    /// What kind of access it gives, in the words of the source. "not verified" where the file name
    /// and vendor are sourced but the primitive set is not.
    pub access: &'static str,
    pub source: Source,
    /// Sandboxed by design: signed bytecode modules rather than a raw wormhole. These are the fix
    /// the ecosystem moved to in 2025, not a red flag, so the report must not treat them alike.
    pub sandboxed: bool,
}

const fn tool(needle: &'static str, product: &'static str, vendor: &'static str, access: &'static str, source: Source) -> HwTool {
    HwTool { needle, stem: false, product, vendor, access, source, sandboxed: false }
}

const fn stem(needle: &'static str, product: &'static str, vendor: &'static str, access: &'static str, source: Source) -> HwTool {
    HwTool { needle, stem: true, product, vendor, access, source, sandboxed: false }
}

/// Access phrases, so the same wording is not retyped per row.
const MSR_IO_MEM: &str = "processor registers (MSR), I/O ports and physical memory";
const PORT_IO: &str = "I/O ports";
const PHYS_MEM: &str = "physical memory";
const NOT_VERIFIED: &str = "low-level hardware access; the exact set is not verified";

/// Matched against the FILE name of a loaded kernel module (not the service name: on the
/// development PC `Asusgio3` loads `AsIO3.sys`, `MSIO` loads `MsIo64.sys` and `NTIOLib_MysticLight`
/// loads `NTIOLib_X64.sys`, so a service-name table would have missed every one of them).
const TOOLS: &[HwTool] = &[
    // --- OpenLibSys / WinRing0 and its renames -------------------------------------------------
    // MS-BL carries FileName="WinRing0.sys" plus hash rules named WinRing0x64/a64/_1_2_2.sys.
    // CVE-2020-14979: "The WinRing0.sys and WinRing0x64.sys drivers 1.2.0 in EVGA Precision X1
    // through 1.0.6 allow local users ... to read and write to arbitrary memory locations."
    // LibreHardwareMonitor <=v0.9.3, OpenRGB <=1.0rc1 and FanControl <=V237 shipped it (upstream
    // source trees). They have since moved to PawnIO; see the last row.
    stem(
        "winring0",
        "LibreHardwareMonitor, OpenRGB, EVGA Precision X1, FanControl (older versions)",
        "OpenLibSys",
        MSR_IO_MEM,
        Source::Cve,
    ),
    // FanControl's README: "WinRing0 (FanControl.sys) used in V237 and below". A rename, so a
    // WinRing0 pattern alone would never match it.
    tool("fancontrol.sys", "FanControl V237 and older (WinRing0 under another name)", "Rem0o / OpenLibSys", MSR_IO_MEM, Source::Vendor),
    tool("openhardwaremonitorlib.sys", "Open Hardware Monitor (WinRing0 under another name)", "OpenLibSys", MSR_IO_MEM, Source::Catalog),
    // MS-BL FileName="OpenLibSys.sys".
    tool("openlibsys.sys", "OpenLibSys (the predecessor of WinRing0)", "OpenLibSys", MSR_IO_MEM, Source::Blocklist),
    // --- ASUS ----------------------------------------------------------------------------------
    // Cisco Talos on Armoury Crate / AI Suite: "Read/write to Model-specific registers (MSR)",
    // "Map arbitrary physical memory ... into our process virtual memory", "Read/write I/O ports".
    // CVE-2025-3464 / CVE-2025-1533. AsIO3.sys is loaded on the development PC.
    // Exact names, never a prefix: "asio" also spells the *audio* ASIO drivers, which are unrelated.
    tool("asio.sys", "ASUS Armoury Crate / AI Suite", "ASUSTeK", MSR_IO_MEM, Source::Cve),
    tool("asio2.sys", "ASUS Armoury Crate / AI Suite", "ASUSTeK", MSR_IO_MEM, Source::Cve),
    tool("asio3.sys", "ASUS Armoury Crate / AI Suite", "ASUSTeK", MSR_IO_MEM, Source::Cve),
    tool("asio3_64.sys", "ASUS Armoury Crate / AI Suite", "ASUSTeK", MSR_IO_MEM, Source::Cve),
    tool("asio32.sys", "ASUS Armoury Crate / AI Suite", "ASUSTeK", MSR_IO_MEM, Source::Blocklist),
    tool("asio64.sys", "ASUS Armoury Crate / AI Suite", "ASUSTeK", MSR_IO_MEM, Source::Blocklist),
    // MS-BL FileName="IOMap.sys" (the PE name; the file on disk is IOMap64.sys). Loaded here too.
    tool("iomap64.sys", "an ASUS utility (\"ASUS Kernel Mode Driver for NT\")", "ASUSTeK", NOT_VERIFIED, Source::Blocklist),
    tool("iomap.sys", "an ASUS utility (\"ASUS Kernel Mode Driver for NT\")", "ASUSTeK", NOT_VERIFIED, Source::Blocklist),
    // CVE-2024-33222 names ATSZIO64.sys in "ASUS ATSZIO Driver"; MS-BL FileName="ATSZIO.sys".
    tool("atszio.sys", "ASUS ATSZIO Driver (ships with ASUS system tools)", "ASUSTeK", MSR_IO_MEM, Source::Cve),
    tool("atszio64.sys", "ASUS ATSZIO Driver (ships with ASUS system tools)", "ASUSTeK", MSR_IO_MEM, Source::Cve),
    // CVE-2024-55408.
    tool("asussaio.sys", "ASUS System Analysis IO", "ASUSTeK", "PCI config space, SMBus, I/O ports and MSRs", Source::Cve),
    // MS-BL <Deny ID="ID_DENY_ASMMAP" FriendlyName="Asus Memory Mapping Driver">. Which retail app
    // installs it is not verified.
    tool("asmmap.sys", "an ASUS utility (\"Asus Memory Mapping Driver\")", "ASUSTeK", PHYS_MEM, Source::Blocklist),
    tool("asmmap64.sys", "an ASUS utility (\"Asus Memory Mapping Driver\")", "ASUSTeK", PHYS_MEM, Source::Blocklist),
    // MS-BL FriendlyName="GLCKIO2.sys"; signer "ASUSTeK Computer Inc." per LOLDrivers
    // (yaml/868c6920-f6cb-4088-8277-095a1358abe1.yaml). The widely repeated "Gigabyte RGB Fusion"
    // attribution has NO citable source, so it is not made here, and neither is any product.
    tool("glckio2.sys", "an ASUSTeK-signed hardware utility (which product is not verified)", "ASUSTeK", PORT_IO, Source::Blocklist),
    // --- ENE Technology (bundled by motherboard-vendor RGB stacks) -----------------------------
    // MS-BL blocks the whole signer: <CertOemID Value="ENE Technology Inc." />. Which retail RGB
    // app installs them (ASUS Aura is the usual claim) is NOT verified, so it is not named.
    tool("ene.sys", "a motherboard lighting / sensor utility (ENE-signed)", "ENE Technology", NOT_VERIFIED, Source::Blocklist),
    stem("eneio", "a motherboard lighting / sensor utility (ENE-signed)", "ENE Technology", NOT_VERIFIED, Source::Blocklist),
    tool("enetechio64.sys", "a motherboard lighting / sensor utility (ENE-signed)", "ENE Technology", NOT_VERIFIED, Source::Blocklist),
    // --- Corsair -------------------------------------------------------------------------------
    // CVE-2020-8808: "The CorsairLLAccess64.sys and CorsairLLAccess32.sys drivers in CORSAIR iCUE
    // before 3.25.60 allow ... arbitrary physical memory ... via a function call such as
    // MmMapIoSpace." What CURRENT iCUE installs is not verified and is deliberately not guessed.
    tool("corsairllaccess64.sys", "CORSAIR iCUE before 3.25.60", "Corsair", PHYS_MEM, Source::Cve),
    tool("corsairllaccess32.sys", "CORSAIR iCUE before 3.25.60", "Corsair", PHYS_MEM, Source::Cve),
    // --- MSI -----------------------------------------------------------------------------------
    // CVE-2019-16098: RTCore64.sys/RTCore32.sys in MSI Afterburner 4.6.2.15658 "allows any
    // authenticated user to read and write to arbitrary memory, I/O ports, and MSRs".
    stem("rtcore", "MSI Afterburner (4.6.2.15658 and older)", "Micro-Star / RivaTuner", MSR_IO_MEM, Source::Cve),
    // MS-BL FileName="NTIOLib.sys". LOLDrivers: NTIOLib_X64.sys and NBIOLib_X64.sys, Company
    // "MSI", signer MICRO-STAR INTERNATIONAL CO., LTD., descriptions including "NTIOLib For
    // MSIRatio_CC" and "MSI ComCenService Driver" (yaml/54d67d79-..., yaml/6fc3034f-...). Both
    // NTIOLib_X64.sys copies are loaded on the development PC (MSI Center + Mystic Light).
    stem("ntiolib", "MSI Center, Mystic Light, Dragon Center / Command Center", "Micro-Star", PHYS_MEM, Source::Blocklist),
    stem("nbiolib", "an MSI utility (built on MSI's NTIOLib driver)", "Micro-Star", PHYS_MEM, Source::Catalog),
    // CVE-2020-17382 + Core Security advisory: MSI Ambient Link, "MICSYS IO driver". Loaded here.
    stem("msio", "MSI Ambient Link / MSI AmbiLighter", "MICSYS Technology", PORT_IO, Source::Cve),
    // --- GIGABYTE ------------------------------------------------------------------------------
    // CVE-2018-19320 names GIGABYTE APP Center v1.05.21 and earlier, AORUS GRAPHICS ENGINE <1.57,
    // XTREME GAMING ENGINE <1.26 and OC GURU II v2.08; "ring0 memcpy-like functionality".
    tool("gdrv.sys", "GIGABYTE APP Center, AORUS / XTREME Gaming Engine, OC GURU II", "GIGA-BYTE", PHYS_MEM, Source::Cve),
    tool("gdrv2.sys", "GIGABYTE APP Center, AORUS / XTREME Gaming Engine, OC GURU II", "GIGA-BYTE", PHYS_MEM, Source::Blocklist),
    tool("gvcidrv64.sys", "a GIGABYTE utility", "GIGA-BYTE", NOT_VERIFIED, Source::Catalog),
    // --- monitoring ----------------------------------------------------------------------------
    // MS-BL FileName="cpuz.sys"; catalog entries cpuz_x64.sys / cpuz141.sys, PE Company "CPUID".
    // HWMonitor is from the same vendor but ITS driver file name is not verified anywhere.
    stem("cpuz", "CPU-Z", "CPUID", MSR_IO_MEM, Source::Blocklist),
    // MS-BL FileName="HWiNFO32.SYS"/"HWiNFO64A.SYS"/"HWiNFO64I.SYS". A stem, because HWiNFO
    // extracts %TEMP%\HWiNFO_x64_<n>.sys with a session number in the name.
    stem("hwinfo", "HWiNFO / HWiNFO64", "REALiX", NOT_VERIFIED, Source::Blocklist),
    // MS-BL FileName="AMDRyzenMasterDriver.sys"; CVE-2023-20564. Loaded twice here, from two paths.
    tool("amdryzenmasterdriver.sys", "AMD Ryzen Master (and the Ryzen Master SDK)", "AMD", NOT_VERIFIED, Source::Blocklist),
    // CVE-2025-7771: ThrottleStop.sys "exposes two IOCTL interfaces that allow arbitrary read and
    // write access to physical memory via the MmMapIoSpace function". ThrottleBlood.sys is the
    // documented rename (Kaspersky Securelist).
    tool("throttlestop.sys", "ThrottleStop", "TechPowerUp", PHYS_MEM, Source::Cve),
    tool("throttleblood.sys", "ThrottleStop under another name", "TechPowerUp", PHYS_MEM, Source::Vendor),
    // CERT/CC VU#380058: "read/write access to the PCI configuration space of system devices".
    tool("signalio.sys", "SignalRGB", "WhirlwindFX", "PCI config space", Source::Vendor),
    tool("signalrgbdriver.sys", "SignalRGB", "WhirlwindFX", "PCI config space", Source::Vendor),
    // aida64.com's own driver-update news post names the file: "replacing the existing file
    // (kerneld.x64)". Note: no .sys extension. The catalog's `kerneld.amd64` entry carries no PE
    // metadata at all, so its AIDA64 attribution is not verified and it is left out.
    tool("kerneld.x64", "AIDA64", "FinalWire", NOT_VERIFIED, Source::Vendor),
    tool("argusmonitor.sys", "Argus Monitor", "Argotronic", NOT_VERIFIED, Source::Catalog),
    tool("speedfan.sys", "SpeedFan", "Almico Software", PORT_IO, Source::Catalog),
    stem("sfdrvx", "SpeedFan", "Almico Software", PORT_IO, Source::Catalog),
    tool("giveio.sys", "SpeedFan", "Almico Software", PORT_IO, Source::Catalog),
    // Catalog: PE Company "Logitech", Product "LgCoreTemp". WHICH Logitech product ships it is not
    // verified - in particular it is NOT confirmed to be G HUB - so no product is claimed.
    tool("lgcoretemp.sys", "a Logitech utility (which one is not verified)", "Logitech", NOT_VERIFIED, Source::Catalog),
    tool("evga_kernel_driver-x64.sys", "an EVGA utility", "EVGA", NOT_VERIFIED, Source::Catalog),
    tool("smarteio64.sys", "an EVGA utility", "EVGA", NOT_VERIFIED, Source::Catalog),
    // --- generic I/O libraries various tools bundle ---------------------------------------------
    // MS-BL FriendlyName="PassMark DirectIo.sys".
    stem("directio", "PassMark tooling", "PassMark Software", PORT_IO, Source::Blocklist),
    // MS-BL FriendlyName="PartnerTech WinIO32A.sys" and siblings. Which consumer app ships them is
    // not verified. The stem also covers WINIODrv.sys.
    stem("winio", "a tool built on the WinIo library", "(rebranded by several vendors)", MSR_IO_MEM, Source::Blocklist),
    // LOLDrivers: AsrDrv*.sys / AsrOmgDrv.sys, Company "ASRock Incorporation", Product "ASRock IO
    // Driver", signer ASROCK Incorporation (yaml/51c342f3-..., yaml/6a50e368-..., yaml/3f39af20-...);
    // AppShopDrv103.sys, Company "ASRock Incorporation", Product "AppShopDrv103 Driver"
    // (yaml/29d2c408-...). Which ASRock app installs each is not verified, so none is named.
    stem("asrdrv", "an ASRock utility (\"ASRock IO Driver\")", "ASRock", PHYS_MEM, Source::Catalog),
    tool("asromgdrv.sys", "an ASRock utility (\"ASRock IO Driver\")", "ASRock", PHYS_MEM, Source::Catalog),
    tool("appshopdrv103.sys", "an ASRock utility (\"AppShopDrv103 Driver\")", "ASRock", PHYS_MEM, Source::Catalog),
    // LOLDrivers: Company "ATI Technologies Inc.", Product "ATI Diagnostics", Description "ATI
    // Diagnostics Hardware Abstraction Sys"; one sample describes itself as an overclocking tool
    // (yaml/61514cbd-..., yaml/10b1fc3d-...).
    tool("atillk64.sys", "an ATI / AMD graphics diagnostics or overclocking tool", "ATI Technologies", NOT_VERIFIED, Source::Catalog),
    // MS-BL FriendlyName="Nvidia NVFlash FileAttribute". LOLDrivers: nvflsh64.sys signed by NVIDIA
    // Corporation (yaml/d4664202-...); nvoclock.sys, Product "NVIDIA System Utility Driver"
    // (yaml/837ad058-...).
    tool("nvflash.sys", "NVIDIA's graphics card flashing tool (NVFlash)", "NVIDIA", NOT_VERIFIED, Source::Blocklist),
    stem("nvflsh", "NVIDIA's graphics card flashing tool (NVFlash)", "NVIDIA", NOT_VERIFIED, Source::Catalog),
    tool("nvoclock.sys", "an NVIDIA system utility (\"NVIDIA System Utility Driver\")", "NVIDIA", NOT_VERIFIED, Source::Catalog),
    // Intel's own support article 000095828: the file "(in Resources > Extras folder)" of Intel
    // graphics driver packages, flagged by Microsoft's attack-surface-reduction rule, and "removed
    // as of graphics driver 31.0.101.4575". Intel spells it ppidrv64.sys in that article; the
    // blocklist and every other report spell it piddrv64.sys, which is what the stem matches.
    // https://www.intel.com/content/www/us/en/support/articles/000095828/graphics.html
    stem("piddrv", "Intel graphics driver packages older than 31.0.101.4575", "Intel", NOT_VERIFIED, Source::Vendor),
    // LOLDrivers: semav6msr.sys / semav6msr64.sys signed "Intel(R) Code Signing External"
    // (catalog entry with no product). Which Intel tool installs it is not verified: community
    // sites name three different ones, and no Intel source names any.
    // A stem, so the 64-bit semav6msr64.sys matches too (it used to be an exact "semav6msr.sys").
    stem("semav6msr", "an Intel utility (which one is not verified)", "Intel", "processor registers (MSR)", Source::Catalog),
    // MS-BL FriendlyName="HwRwDrv FileAttribute"; signed "Open Source Developer, Jun Liu" per
    // LOLDrivers, which also lists a Shuttle Inc.-signed build of the same driver.
    tool("hwrwdrv.sys", "a tool bundling the generic \"hardware read & write\" driver", "(various)", PHYS_MEM, Source::Catalog),
    // --- the sandboxed replacement --------------------------------------------------------------
    // File name from the project's own PawnIO.inf.in + CMakeLists. LibreHardwareMonitor >=v0.9.5,
    // FanControl >=V238 and OpenRGB >=1.0rc2 ship this instead of WinRing0. Seeing it is GOOD news.
    HwTool {
        needle: "pawnio.sys",
        stem: false,
        product: "LibreHardwareMonitor, FanControl or OpenRGB (current versions)",
        vendor: "namazso",
        access: "sandboxed: signed script modules, not raw hardware access",
        source: Source::Vendor,
        sandboxed: true,
    },
];

/// The row for one loaded driver file name, or `None`.
///
/// Case-insensitive, because nothing about these names is consistent: `HWiNFO32.SYS` and
/// `cpuz.sys` and `AsIO3.sys` all appear in Microsoft's own list, and the same machine spells its
/// driver directory both `C:\WINDOWS\system32\drivers` and `C:\Windows\system32\drivers`.
pub fn lookup(file_name: &str) -> Option<&'static HwTool> {
    // `\??\C:\path\x.sys` and `\SystemRoot\System32\drivers\x.sys` both reduce to `x.sys`; a module
    // list gives the bare name already, but a service ImagePath does not.
    let lower = file_name.trim().trim_matches('"').rsplit(['\\', '/']).next()?.to_ascii_lowercase();
    TOOLS.iter().find(|t| if t.stem { lower.starts_with(t.needle) } else { lower == t.needle })
}

/// One hardware-access driver that is loaded right now.
pub struct Found {
    /// The file name as the loaded-module list spells it, e.g. `HWiNFO_x64_215.sys`.
    pub file: String,
    pub tool: &'static HwTool,
}

impl Found {
    /// "SignalRGB (SignalIo.sys)"
    pub fn label(&self) -> String {
        format!("{} ({})", self.tool.product, self.file)
    }
}

/// Which of these drivers are among `loaded` (file names of loaded kernel modules), one entry per
/// product: a machine can load the same product's driver twice (AMD Ryzen Master runs two services
/// from two directories on the development PC) and that is one program, not two.
pub fn present(loaded: &[String]) -> Vec<Found> {
    let mut out: Vec<Found> = Vec::new();
    for file in loaded {
        let Some(tool) = lookup(file) else { continue };
        if out.iter().any(|f| f.tool.product == tool.product) {
            continue;
        }
        out.push(Found { file: file.trim().to_string(), tool });
    }
    out.sort_by(|a, b| a.tool.product.cmp(b.tool.product));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_match_whatever_case_and_path_they_arrive_in() {
        assert_eq!(lookup("WinRing0x64.sys").unwrap().product, lookup("winring0.sys").unwrap().product);
        assert_eq!(lookup("AsIO3.sys").unwrap().vendor, "ASUSTeK");
        assert_eq!(lookup(r"\??\C:\WINDOWS\system32\drivers\MsIo64.sys").unwrap().vendor, "MICSYS Technology");
        assert_eq!(lookup(r"\SystemRoot\System32\drivers\NTIOLib_X64.sys").unwrap().vendor, "Micro-Star");
        // The stem rows: a per-session suffix must not defeat the match.
        assert_eq!(lookup("HWiNFO_x64_215.sys").unwrap().product, "HWiNFO / HWiNFO64");
        assert_eq!(lookup("HWiNFO64A.SYS").unwrap().product, "HWiNFO / HWiNFO64");
        assert!(lookup("cpuz141.sys").is_some() && lookup("AsrDrv103.sys").is_some());
        // AIDA64's driver is not called aida*, and has no .sys extension.
        assert_eq!(lookup("kerneld.x64").unwrap().product, "AIDA64");
        assert!(lookup("aida64.sys").is_none(), "the old 'aida' needle could never match a real install");
    }

    /// The same code under another file name is the normal case here, not the exception.
    #[test]
    fn the_known_renames_are_recognized() {
        for renamed in ["FanControl.sys", "OpenHardwareMonitorLib.sys", "ThrottleBlood.sys", "gdrv2.sys"] {
            assert!(lookup(renamed).is_some(), "{renamed}");
        }
    }

    /// The rows re-sourced away from a GPL-3.0 list (2026-09-24) say only what LOLDrivers, Microsoft
    /// or the vendor say, and the 64-bit Intel file is matched at all.
    #[test]
    fn re_sourced_rows_claim_no_more_than_their_sources() {
        let intel = lookup("semav6msr64.sys").expect("the 64-bit file LOLDrivers lists");
        assert!(intel.product.contains("not verified") && intel.vendor == "Intel", "{}", intel.product);
        let pid = lookup("piddrv64.sys").expect("Intel's graphics packages shipped it");
        assert_eq!(pid.source, Source::Vendor);
        assert!(!pid.product.contains("Processor Identification"), "no first-party source says so: {}", pid.product);
        let ati = lookup("atillk64.sys").unwrap();
        assert!(!ati.product.contains("flash"), "no remaining source says flashing: {}", ati.product);
        let asrock = lookup("AsrDrv106.sys").unwrap();
        assert!(!asrock.product.contains("A-Tuning"), "which ASRock app is not sourced: {}", asrock.product);
        assert!(lookup("glckio2.sys").unwrap().product.contains("not verified"));
    }

    /// Four needles with no source behind them, and one that matched the wrong thing.
    #[test]
    fn unsourced_and_wrong_needles_are_gone() {
        for unsourced in ["asupio.sys", "gpcidrv.sys", "iocbios2.sys", "lghub.sys", "lghub_updater.sys"] {
            assert!(lookup(unsourced).is_none(), "{unsourced} has no citable source and must not be in the table");
        }
        // "asio" as a prefix would have caught audio ASIO drivers, which have nothing to do with
        // ASUS I/O. Only the exact ASUS file names match.
        assert!(lookup("asio_sample_audio.sys").is_none());
        assert!(lookup("ASIOUSB64.sys").is_none());
    }

    #[test]
    fn one_entry_per_product_even_when_the_file_is_loaded_twice() {
        let loaded = ["AMDRyzenMasterDriver.sys".to_string(), "AMDRyzenMasterDriver.sys".to_string(), "ndis.sys".to_string()];
        let found = present(&loaded);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].label(), "AMD Ryzen Master (and the Ryzen Master SDK) (AMDRyzenMasterDriver.sys)");
        assert!(present(&["ndis.sys".to_string(), "nvlddmkm.sys".to_string()]).is_empty());
    }

    /// The sandboxed replacement is recognized, and marked so the report can say the opposite thing
    /// about it: it is what the ecosystem moved TO in 2025.
    #[test]
    fn pawnio_is_recognized_and_flagged_as_the_safe_one() {
        let p = lookup("PawnIO.sys").unwrap();
        assert!(p.sandboxed);
        assert!(!lookup("WinRing0x64.sys").unwrap().sandboxed);
    }

    #[test]
    fn every_row_says_where_it_came_from_and_nothing_is_blank() {
        for t in TOOLS {
            assert_eq!(t.needle, t.needle.to_ascii_lowercase(), "needles are matched lower-case: {}", t.needle);
            assert!(!t.product.is_empty() && !t.vendor.is_empty() && !t.access.is_empty(), "{}", t.needle);
            assert!(!t.source.label().is_empty());
        }
        // The two rows the report treats specially, and the one loaded on the development PC.
        assert_eq!(TOOLS.iter().filter(|t| t.sandboxed).count(), 1);
        assert!(TOOLS.len() > 40, "the sourced table is much larger than the 19 needles it replaces");
    }
}
