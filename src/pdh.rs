//! The little bit of PDH (Performance Data Helper) the tool needs: a query that closes itself,
//! English counter paths, and reading a wildcard counter's per-instance values.
//!
//! Both the CPU-clock sampler and the GPU sampler ask for `\Thing(*)\Counter` and get one value
//! per instance back, so the buffer dance lives here once.
//! <https://learn.microsoft.com/en-us/windows/win32/api/pdh/nf-pdh-pdhgetformattedcounterarrayw>

use std::ffi::c_void;
use std::ptr::{null, null_mut};

use windows_sys::Win32::System::Performance::{
    PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData, PdhGetFormattedCounterArrayW, PdhOpenQueryW, PDH_FMT_COUNTERVALUE_ITEM_W,
    PDH_FMT_DOUBLE,
};

use crate::util::{from_wide, wide};

/// The buffer was too small, which is how PDH reports the size it needs.
/// <https://learn.microsoft.com/en-us/windows/win32/perfctrs/pdh-error-codes>
const PDH_MORE_DATA: u32 = 0x8000_07D2;

/// An open PDH query. Dropping it closes the query and every counter added to it.
pub struct Query(*mut c_void);

impl Query {
    pub fn open() -> Option<Query> {
        let mut query = null_mut();
        (unsafe { PdhOpenQueryW(null(), 0, &mut query) } == 0).then_some(Query(query))
    }

    /// Adds a counter by its English path, so the tool works on a localized Windows.
    pub fn add(&self, path: &str) -> Option<Counter> {
        let mut counter = null_mut();
        (unsafe { PdhAddEnglishCounterW(self.0, wide(path).as_ptr(), 0, &mut counter) } == 0).then_some(Counter(counter))
    }

    /// Takes a reading of every counter. Rate counters need one before they mean anything.
    pub fn collect(&self) -> bool {
        unsafe { PdhCollectQueryData(self.0) == 0 }
    }
}

impl Drop for Query {
    fn drop(&mut self) {
        unsafe { PdhCloseQuery(self.0) };
    }
}

/// One counter in a `Query`; it lives as long as the query does and is closed with it.
pub struct Counter(*mut c_void);

impl Counter {
    /// The (instance name, value) pairs of a wildcard counter from the query's last reading.
    /// Empty when the counter has no valid instances.
    pub fn read(&self) -> Vec<(String, f64)> {
        let counter = self.0;
        let mut out = Vec::new();
        unsafe {
            let (mut size, mut count) = (0u32, 0u32);
            if PdhGetFormattedCounterArrayW(counter, PDH_FMT_DOUBLE, &mut size, &mut count, null_mut()) != PDH_MORE_DATA {
                return out;
            }
            // u64-backed so the item structs (which hold pointers and doubles) are aligned.
            let mut buf = vec![0u64; (size as usize).div_ceil(8)];
            let items = buf.as_mut_ptr() as *mut PDH_FMT_COUNTERVALUE_ITEM_W;
            if PdhGetFormattedCounterArrayW(counter, PDH_FMT_DOUBLE, &mut size, &mut count, items) != 0 {
                return out;
            }
            for item in std::slice::from_raw_parts(items, count as usize) {
                if item.FmtValue.CStatus != 0 || item.szName.is_null() {
                    continue;
                }
                let mut len = 0;
                while *item.szName.add(len) != 0 {
                    len += 1;
                }
                out.push((from_wide(std::slice::from_raw_parts(item.szName, len)), item.FmtValue.Anonymous.doubleValue));
            }
        }
        out
    }
}
