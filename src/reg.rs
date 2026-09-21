//! Reading the registry: the two string flavors the tool needs, a DWORD, and the subkeys of a
//! key. Everything is read-only; the tool never writes to the registry.

use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, RRF_RT_REG_DWORD,
    RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
};

use crate::util::{from_wide, wide};

/// A string value under HKEY_LOCAL_MACHINE, trimmed. For the machine description lines, where
/// the values are short and a stray space would show.
pub fn hklm_str(subkey: &str, value: &str) -> Option<String> {
    str_value::<256>(subkey, value, RRF_RT_REG_SZ).map(|s| s.trim().to_string())
}

/// A string value under HKEY_LOCAL_MACHINE that may be an expandable path (a driver's
/// ImagePath), with empty values treated as absent. For the device and PCI tables.
pub fn hklm_path(subkey: &str, value: &str) -> Option<String> {
    str_value::<1024>(subkey, value, RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ).filter(|s| !s.is_empty())
}

/// `N` is the buffer in UTF-16 units; anything longer is simply not returned.
fn str_value<const N: usize>(subkey: &str, value: &str, flags: u32) -> Option<String> {
    let mut buf = [0u16; N];
    let mut size = (buf.len() * 2) as u32;
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            wide(subkey).as_ptr(),
            wide(value).as_ptr(),
            flags,
            null_mut(),
            buf.as_mut_ptr() as *mut _,
            &mut size,
        )
    };
    (rc == ERROR_SUCCESS).then(|| from_wide(&buf))
}

/// A DWORD under HKEY_LOCAL_MACHINE. Absent and zero are different answers here: `MSISupported`
/// missing means "the driver package never asked for message-signaled interrupts", while
/// `MSISupported = 0` means someone wrote the opt-out deliberately. Never collapse the two.
pub fn hklm_dword(subkey: &str, value: &str) -> Option<u32> {
    dword(HKEY_LOCAL_MACHINE, subkey, value)
}

/// A DWORD under HKEY_CURRENT_USER (the per-user settings the GUI follows, such as the theme).
pub fn hkcu_dword(subkey: &str, value: &str) -> Option<u32> {
    dword(HKEY_CURRENT_USER, subkey, value)
}

fn dword(root: HKEY, subkey: &str, value: &str) -> Option<u32> {
    let mut out = 0u32;
    let mut size = 4u32;
    let rc = unsafe {
        RegGetValueW(
            root,
            wide(subkey).as_ptr(),
            wide(value).as_ptr(),
            RRF_RT_REG_DWORD,
            null_mut(),
            &mut out as *mut u32 as *mut _,
            &mut size,
        )
    };
    (rc == ERROR_SUCCESS).then_some(out)
}

/// The names of the subkeys of one HKEY_LOCAL_MACHINE key.
pub fn subkeys(path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut key: HKEY = null_mut();
    if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, wide(path).as_ptr(), 0, KEY_READ, &mut key) } != ERROR_SUCCESS {
        return out;
    }
    for index in 0..8192 {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// No value is asserted: this reads the real registry of whatever machine runs the test.
    #[test]
    fn hklm_reads_do_not_panic_and_absent_values_are_none() {
        let build = hklm_str(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild");
        println!("CurrentBuild = {build:?}");
        println!("CSDVersion (DWORD) = {:?}", hklm_dword(r"SYSTEM\CurrentControlSet\Control\Windows", "CSDVersion"));
        assert_eq!(hklm_dword(r"SOFTWARE\no such key at all", "nope"), None);
        assert_eq!(hklm_dword(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "no such value"), None);
        // A string value is not a DWORD, and must not be returned as one.
        assert_eq!(hklm_dword(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild"), None);
    }
}
