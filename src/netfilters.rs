//! Network filter drivers that sit in the path of every packet.
//!
//! Windows' own network code (`NETIO.SYS`, `ndis.sys`, `tcpip.sys`, `afd.sys`) hosts other
//! vendors' filters and runs their code inside itself, so a stall blamed on one of those files can
//! be a VPN, a "gaming network optimizer" or a security product doing the work. Naming the filter
//! is the only way to turn "update your network driver" into something actionable.
//!
//! HOW. Registry only: no elevation, no COM, no new API surface.
//!
//! * The NetService setup class is `{4D36E974-E325-11CE-BFC1-08002BE10318}`
//!   (`shared\devguid.h`, `GUID_DEVCLASS_NETSERVICE`; Microsoft, *Installation Requirements for
//!   Network Filter Drivers*,
//!   <https://learn.microsoft.com/en-us/windows-hardware/drivers/network/installation-requirements-for-network-filter-drivers>:
//!   "Class= NetService ClassGuid= {4D36E974-E325-11CE-BFC1-08002BE10318}").
//! * A component is a lightweight filter when its `Characteristics` has `NCF_LW_FILTER` (0x40000)
//!   set. Microsoft, *Configuring an INF File for a Modifying Filter Driver*,
//!   <https://learn.microsoft.com/en-us/windows-hardware/drivers/network/configuring-an-inf-file-for-a-modifying-filter-driver>:
//!   "Characteristics=0x40000 ... The 0x40000 value indicates that NCF_LW_FILTER (0x40000) is set."
//! * The binary comes from `Ndi\Service` -> `Services\<service>\ImagePath`. The service name is not
//!   the file name: Microsoft says so outright ("the name of a filter driver's service can be
//!   different from the name of the binary for the driver"), and on the development PC `ms_pacer`
//!   resolves through service `Psched` to `pacer.sys`.
//!
//! NOT DOCUMENTED, and marked as such: the literal key path
//! `Control\Network\{class}\{instance}\Ndi` appears on no Microsoft page - Learn says only that
//! `Ndi` is added to "the instance key for the component". It is what Windows 11 26200 really
//! stores (verified live), and every read here is guarded, so a different layout means an empty
//! list rather than a wrong answer. `FilterClass` / `FilterType`, which the INF documentation
//! describes, are simply not present in that key on this build, so nothing depends on them.
//!
//! WHAT IS DELIBERATELY NOT BUILT: Windows Filtering Platform callout enumeration. `FWPM_CALLOUT0`
//! (`shared\fwpmtypes.h`) carries a GUID, a friendly string, flags, an opaque vendor blob, a layer
//! GUID and a runtime id - no path, no image name, no module reference at all. It cannot answer
//! "which driver is in my network path", and `FwpmEngineOpen0` additionally fails with
//! ERROR_NOT_SUPPORTED from a non-elevated token, so it could not even be tested here.

use crate::modules;
use crate::reg;

const NET_SERVICE_CLASS: &str = "{4D36E974-E325-11CE-BFC1-08002BE10318}";
const NETWORK: &str = r"SYSTEM\CurrentControlSet\Control\Network";
const SERVICES: &str = r"SYSTEM\CurrentControlSet\Services";

/// `NCF_LW_FILTER`, the flag that marks an NDIS lightweight filter.
const NCF_LW_FILTER: u32 = 0x0004_0000;

/// How confident the "someone other than Microsoft wrote this" answer is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Vendor {
    /// The driver file's own version resource says Microsoft.
    Microsoft,
    /// The driver file's own version resource names someone else.
    ThirdParty,
    /// No driver file, or no readable version resource: judged by the component id's `ms_` / `vms_`
    /// prefix, which is a Microsoft naming convention and not a guarantee.
    GuessedMicrosoft,
    GuessedThirdParty,
}

impl Vendor {
    pub fn third_party(self) -> bool {
        matches!(self, Vendor::ThirdParty | Vendor::GuessedThirdParty)
    }

    pub fn guessed(self) -> bool {
        matches!(self, Vendor::GuessedMicrosoft | Vendor::GuessedThirdParty)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct NetFilter {
    /// "ms_pacer", "nordlwf".
    pub component_id: String,
    /// The service the component names, e.g. "Psched".
    pub service: String,
    /// Base name of the service's binary, e.g. "pacer.sys". Missing for a staged INF that has no
    /// installed service (three of the twelve on the development PC).
    pub file: Option<String>,
    /// `CompanyName` from that binary's version resource, when it could be read.
    pub company: Option<String>,
    pub vendor: Vendor,
}

impl NetFilter {
    /// "nordlwf.sys (NordVPN)" - or the component id when there is no file to name.
    pub fn label(&self) -> String {
        match (&self.file, &self.company) {
            (Some(f), Some(c)) => format!("{f} ({c})"),
            (Some(f), None) => f.clone(),
            (None, _) => self.component_id.clone(),
        }
    }
}

/// Every NDIS lightweight filter installed on this PC.
pub fn filters() -> Vec<NetFilter> {
    let mut out = Vec::new();
    let class_key = format!(r"{NETWORK}\{NET_SERVICE_CLASS}");
    for instance in reg::subkeys(&class_key) {
        let key = format!(r"{class_key}\{instance}");
        let characteristics = reg::hklm_dword(&key, "Characteristics").unwrap_or(0);
        if characteristics & NCF_LW_FILTER == 0 {
            continue;
        }
        let component_id = reg::hklm_path(&key, "ComponentId").unwrap_or_else(|| instance.clone());
        let service = reg::hklm_path(&format!(r"{key}\Ndi"), "Service").unwrap_or_default();
        let file = (!service.is_empty())
            .then(|| reg::hklm_path(&format!(r"{SERVICES}\{service}"), "ImagePath"))
            .flatten()
            .and_then(|p| driver_file(&p));
        let company = file
            .as_ref()
            .and_then(|_| reg::hklm_path(&format!(r"{SERVICES}\{service}"), "ImagePath"))
            .and_then(|p| modules::version_field(&modules::dos_path(&p), "CompanyName"));
        out.push(NetFilter { vendor: classify(&component_id, company.as_deref()), component_id, service, file, company });
    }
    out.sort_by(|a, b| a.component_id.cmp(&b.component_id));
    out
}

/// Who wrote a filter: its binary's `CompanyName` when there is one, otherwise the component id's
/// naming convention, flagged as the guess it is.
///
/// The convention is not a contract - Microsoft never promises that a third party will avoid `ms_`
/// - and a third-party filter's code runs inside Microsoft's own `netio.sys` either way, so the
///   report says "from another vendor", not "not Microsoft's".
pub fn classify(component_id: &str, company: Option<&str>) -> Vendor {
    if let Some(company) = company {
        return if company.to_ascii_lowercase().starts_with("microsoft") { Vendor::Microsoft } else { Vendor::ThirdParty };
    }
    let id = component_id.to_ascii_lowercase();
    if id.starts_with("ms_") || id.starts_with("vms_") {
        Vendor::GuessedMicrosoft
    } else {
        Vendor::GuessedThirdParty
    }
}

/// `"System32\drivers\pacer.sys"`, `\??\C:\...\nordlwf.sys` -> `pacer.sys` / `nordlwf.sys`.
/// Anything that is not a driver binary (a service hosted in `svchost.exe`) gives `None`.
fn driver_file(image_path: &str) -> Option<String> {
    let path = image_path.trim().trim_matches('"');
    let name = path.rsplit(['\\', '/']).next()?;
    name.to_ascii_lowercase().ends_with(".sys").then(|| name.to_string())
}

/// The Windows files whose stalls a third-party filter can be behind: `netio.sys` is the kernel
/// networking library that hosts the filter/WFP data path, `ndis.sys` is what actually calls a
/// lightweight filter, and `tcpip.sys` / `afd.sys` sit directly above them. A filter's own code
/// runs inside these, so its name never appears on the stack in their place.
pub fn hosts_filters(driver_file: &str) -> bool {
    let lower = driver_file.to_ascii_lowercase();
    ["netio.sys", "ndis.sys", "tcpip.sys", "afd.sys"].contains(&lower.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_paths_reduce_to_a_driver_file_or_nothing() {
        assert_eq!(driver_file(r"System32\drivers\pacer.sys").as_deref(), Some("pacer.sys"));
        assert_eq!(driver_file(r"system32\DRIVERS\nwifi.sys").as_deref(), Some("nwifi.sys"));
        assert_eq!(driver_file(r#""\??\C:\Program Files\NordVPN\nordlwf.sys""#).as_deref(), Some("nordlwf.sys"));
        assert_eq!(driver_file(r"C:\Windows\system32\svchost.exe -k netsvcs"), None);
        assert_eq!(driver_file(""), None);
    }

    /// The version resource decides; the `ms_` convention is only the fallback, and says so.
    #[test]
    fn third_party_filters_are_told_apart_by_who_wrote_the_binary() {
        assert_eq!(classify("ms_pacer", Some("Microsoft Corporation")), Vendor::Microsoft);
        assert_eq!(classify("nordlwf", Some("NordVPN S.A.")), Vendor::ThirdParty);
        // A vendor using an ms_-looking id is still caught, because the binary is what is read.
        assert_eq!(classify("ms_something", Some("Some Vendor Ltd")), Vendor::ThirdParty);
        // ...and Microsoft's own filter is not accused because a third party named it oddly.
        assert!(!classify("ms_wfplwf_upper", Some("Microsoft Corporation")).third_party());

        // No readable version resource: fall back to the naming convention, and admit the guess.
        assert_eq!(classify("ms_vwifi", None), Vendor::GuessedMicrosoft);
        assert_eq!(classify("vms_vsf", None), Vendor::GuessedMicrosoft);
        assert_eq!(classify("nordlwf", None), Vendor::GuessedThirdParty);
        assert!(Vendor::GuessedThirdParty.guessed() && Vendor::GuessedThirdParty.third_party());
        assert!(!Vendor::ThirdParty.guessed());
    }

    #[test]
    fn only_the_windows_files_that_host_other_vendors_code_count() {
        for host in ["NETIO.SYS", "netio.sys", "ndis.sys", "tcpip.sys", "afd.sys"] {
            assert!(hosts_filters(host), "{host}");
        }
        for other in ["nvlddmkm.sys", "rt640x64.sys", "fwpkclnt.sys", "netio2.sys"] {
            assert!(!hosts_filters(other), "{other}");
        }
    }

    #[test]
    fn labels_never_print_an_empty_string() {
        let f = |file: Option<&str>, company: Option<&str>| NetFilter {
            component_id: "ms_vwifi".into(),
            service: String::new(),
            file: file.map(String::from),
            company: company.map(String::from),
            vendor: Vendor::GuessedMicrosoft,
        };
        assert_eq!(f(Some("pacer.sys"), Some("Microsoft Corporation")).label(), "pacer.sys (Microsoft Corporation)");
        assert_eq!(f(Some("pacer.sys"), None).label(), "pacer.sys");
        assert_eq!(f(None, None).label(), "ms_vwifi");
    }

    /// Prints what this machine really has. No count asserted: a CI runner is a minimal VM.
    #[test]
    fn listing_this_pcs_filters_does_not_panic() {
        let found = filters();
        println!("{} NDIS lightweight filters installed", found.len());
        for f in &found {
            println!("  {:<20} service {:<14} {:<16} {:?}", f.component_id, f.service, f.file.as_deref().unwrap_or("-"), f.vendor);
        }
        println!("third-party: {}", found.iter().filter(|f| f.vendor.third_party()).count());
    }
}
