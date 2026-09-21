//! Once-a-second view of each GPU: how busy it is, how full its video memory is, and which
//! process is responsible. A CPU-side trace cannot see the GPU at all, yet "the game ran out of
//! VRAM" and "the GPU is simply the limit" are two of the most common reasons for stutter.
//!
//! Uses the same performance counters as Task Manager's GPU tab ("GPU Engine", "GPU Adapter
//! Memory", "GPU Process Memory"); adapter names and VRAM sizes come from the graphics kernel.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::pdh;
use crate::util::{from_wide, qpc};
use windows_sys::Wdk::Graphics::Direct3D::{
    D3DKMTCloseAdapter, D3DKMTEnumAdapters2, D3DKMTQueryAdapterInfo, D3DKMT_ADAPTERINFO, D3DKMT_ADAPTERREGISTRYINFO, D3DKMT_CLOSEADAPTER,
    D3DKMT_ENUMADAPTERS2, D3DKMT_QUERYADAPTERINFO, D3DKMT_SEGMENTSIZEINFO, KMTQAITYPE_ADAPTERREGISTRYINFO, KMTQAITYPE_GETSEGMENTSIZE,
};

/// A graphics adapter as the graphics kernel describes it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Adapter {
    /// "0x00000000_0x00016fcb", the form the performance counters use in instance names.
    pub luid: String,
    pub name: String,
    /// Dedicated video memory in bytes; small or zero for integrated graphics.
    pub vram: u64,
}

/// One adapter at one moment.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AdapterSample {
    pub luid: String,
    /// Load of the busiest engine (3D, copy, video...), %, like Task Manager's headline number.
    pub busy: f64,
    pub busiest_engine: String,
    /// Process with the most load on that engine.
    pub top_pid: Option<u32>,
    pub dedicated: u64,
    pub shared: u64,
    /// (pid, dedicated bytes, shared bytes) of the process holding the most dedicated memory.
    pub top_memory: Option<(u32, u64, u64)>,
}

#[derive(Clone, Debug, Default)]
pub struct GpuSample {
    pub ts: i64,
    pub adapters: Vec<AdapterSample>,
}

#[derive(Clone, Default)]
pub struct GpuLog {
    pub adapters: Vec<Adapter>,
    pub samples: Vec<GpuSample>,
}

pub type SharedLog = Arc<Mutex<GpuLog>>;

/// "pid_2804_luid_0x00000000_0x0001927e_phys_0_eng_0_engtype_3d" and its shorter relatives.
#[derive(Debug, Default, PartialEq)]
struct Instance {
    pid: Option<u32>,
    luid: String,
    engine: Option<u32>,
    engine_type: String,
}

fn parse_instance(name: &str) -> Option<Instance> {
    let lower = name.to_lowercase();
    let after = |key: &str| lower.find(key).map(|i| &lower[i + key.len()..]);
    let number = |s: &str| s.split('_').next().and_then(|n| n.parse::<u32>().ok());
    let luid_part = after("luid_")?;
    let mut pieces = luid_part.split('_');
    let luid = format!("{}_{}", pieces.next()?, pieces.next()?);
    if !luid.starts_with("0x") {
        return None;
    }
    Some(Instance {
        pid: if lower.starts_with("pid_") { after("pid_").and_then(number) } else { None },
        luid,
        engine: after("_eng_").and_then(number),
        engine_type: after("engtype_").unwrap_or("").to_string(),
    })
}

/// Folds one reading of the three counter sets into per-adapter samples.
fn fold(engines: &HashMap<String, f64>, adapter_mem: &[(String, f64, f64)], process_mem: &[(String, f64, f64)]) -> Vec<AdapterSample> {
    // (luid, engine) -> (total load, engine type, per-pid load)
    type EngineLoad = (f64, String, HashMap<u32, f64>);
    let mut per_engine: HashMap<(String, u32), EngineLoad> = HashMap::new();
    for (name, value) in engines {
        let Some(i) = parse_instance(name) else { continue };
        let (Some(engine), Some(pid)) = (i.engine, i.pid) else { continue };
        let e = per_engine.entry((i.luid, engine)).or_insert_with(|| (0.0, i.engine_type.clone(), HashMap::new()));
        e.0 += value;
        *e.2.entry(pid).or_default() += value;
    }
    let mut out: HashMap<String, AdapterSample> = HashMap::new();
    for ((luid, _), (load, engine_type, pids)) in per_engine {
        let s = out.entry(luid.clone()).or_insert_with(|| AdapterSample { luid, ..Default::default() });
        if load > s.busy || s.busiest_engine.is_empty() {
            s.busy = load.min(100.0);
            s.busiest_engine = engine_type;
            s.top_pid = pids.into_iter().filter(|(_, v)| *v > 0.0).max_by(|a, b| a.1.total_cmp(&b.1)).map(|(pid, _)| pid);
        }
    }
    for (name, dedicated, shared) in adapter_mem {
        let Some(i) = parse_instance(name) else { continue };
        let s = out.entry(i.luid.clone()).or_insert_with(|| AdapterSample { luid: i.luid, ..Default::default() });
        s.dedicated = *dedicated as u64;
        s.shared = *shared as u64;
    }
    for (name, dedicated, shared) in process_mem {
        let Some(i) = parse_instance(name) else { continue };
        let (Some(pid), Some(s)) = (i.pid, out.get_mut(&i.luid)) else { continue };
        if s.top_memory.is_none_or(|(_, d, _)| *dedicated as u64 > d) {
            s.top_memory = Some((pid, *dedicated as u64, *shared as u64));
        }
    }
    let mut v: Vec<AdapterSample> = out.into_values().collect();
    v.sort_by(|a, b| a.luid.cmp(&b.luid));
    v
}

struct Counters {
    query: pdh::Query,
    engine: pdh::Counter,
    adapter_dedicated: pdh::Counter,
    adapter_shared: pdh::Counter,
    process_dedicated: pdh::Counter,
    process_shared: pdh::Counter,
}

impl Counters {
    fn open() -> Option<Counters> {
        let query = pdh::Query::open()?;
        let all = (
            query.add(r"\GPU Engine(*)\Utilization Percentage"),
            query.add(r"\GPU Adapter Memory(*)\Dedicated Usage"),
            query.add(r"\GPU Adapter Memory(*)\Shared Usage"),
            query.add(r"\GPU Process Memory(*)\Dedicated Usage"),
            query.add(r"\GPU Process Memory(*)\Shared Usage"),
        );
        match all {
            (Some(engine), Some(adapter_dedicated), Some(adapter_shared), Some(process_dedicated), Some(process_shared)) => {
                query.collect(); // utilization is a rate: it needs a first reading to diff against
                Some(Counters { query, engine, adapter_dedicated, adapter_shared, process_dedicated, process_shared })
            }
            _ => None,
        }
    }

    fn read(counter: &pdh::Counter) -> HashMap<String, f64> {
        let mut out = HashMap::new();
        // Several processes can share an instance name only in theory; add rather than overwrite.
        for (name, value) in counter.read() {
            *out.entry(name).or_default() += value;
        }
        out
    }

    fn sample(&self) -> Option<GpuSample> {
        if !self.query.collect() {
            return None;
        }
        let pair = |a: &pdh::Counter, b: &pdh::Counter| -> Vec<(String, f64, f64)> {
            let shared = Self::read(b);
            Self::read(a)
                .into_iter()
                .map(|(name, dedicated)| (name.clone(), dedicated, shared.get(&name).copied().unwrap_or(0.0)))
                .collect()
        };
        let adapters = fold(
            &Self::read(&self.engine),
            &pair(&self.adapter_dedicated, &self.adapter_shared),
            &pair(&self.process_dedicated, &self.process_shared),
        );
        (!adapters.is_empty()).then(|| GpuSample { ts: qpc(), adapters })
    }
}

/// Names and VRAM sizes from the graphics kernel. Empty on failure; the samples still work then.
pub fn adapters() -> Vec<Adapter> {
    let mut out = Vec::new();
    unsafe {
        let mut infos: [D3DKMT_ADAPTERINFO; 16] = std::mem::zeroed();
        let mut e = D3DKMT_ENUMADAPTERS2 { NumAdapters: infos.len() as u32, pAdapters: infos.as_mut_ptr() };
        if D3DKMTEnumAdapters2(&mut e) != 0 {
            return out;
        }
        for info in &infos[..(e.NumAdapters as usize).min(infos.len())] {
            let query = |kind, data: *mut c_void, size: usize| {
                let mut q = D3DKMT_QUERYADAPTERINFO {
                    hAdapter: info.hAdapter,
                    Type: kind,
                    pPrivateDriverData: data,
                    PrivateDriverDataSize: size as u32,
                };
                D3DKMTQueryAdapterInfo(&mut q) == 0
            };
            let mut reg: D3DKMT_ADAPTERREGISTRYINFO = std::mem::zeroed();
            let mut seg: D3DKMT_SEGMENTSIZEINFO = std::mem::zeroed();
            let named = query(KMTQAITYPE_ADAPTERREGISTRYINFO, &mut reg as *mut _ as *mut c_void, size_of::<D3DKMT_ADAPTERREGISTRYINFO>());
            let sized = query(KMTQAITYPE_GETSEGMENTSIZE, &mut seg as *mut _ as *mut c_void, size_of::<D3DKMT_SEGMENTSIZEINFO>());
            D3DKMTCloseAdapter(&D3DKMT_CLOSEADAPTER { hAdapter: info.hAdapter });
            let name = if named { from_wide(&reg.AdapterString) } else { String::new() };
            // The software rasterizer shows up as an adapter too; it is never the problem.
            if name.is_empty() || name.contains("Microsoft Basic Render") {
                continue;
            }
            out.push(Adapter {
                luid: format!("0x{:08x}_0x{:08x}", info.AdapterLuid.HighPart, info.AdapterLuid.LowPart),
                name,
                vram: if sized { seg.DedicatedVideoMemorySize } else { 0 },
            });
        }
    }
    out
}

/// Samples until `stop` is set. If the counters are unavailable the log simply stays empty.
pub fn spawn(stop: Arc<AtomicBool>) -> SharedLog {
    let log: SharedLog = Arc::new(Mutex::new(GpuLog { adapters: adapters(), samples: Vec::new() }));
    let out = log.clone();
    let _ = std::thread::Builder::new().name("gpu".into()).spawn(move || {
        let Some(counters) = Counters::open() else { return };
        while !stop.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(1000));
            if let Some(s) = counters.sample() {
                out.lock().unwrap().samples.push(s);
            }
        }
    });
    log
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_instance_names_are_taken_apart() {
        let i = parse_instance("pid_2804_luid_0x00000000_0x0001927E_phys_0_eng_12_engtype_3D").unwrap();
        assert_eq!(i, Instance { pid: Some(2804), luid: "0x00000000_0x0001927e".into(), engine: Some(12), engine_type: "3d".into() });
        let i = parse_instance("pid_77_luid_0x00000000_0x00016fcb_phys_0").unwrap();
        assert_eq!((i.pid, i.engine, i.luid.as_str()), (Some(77), None, "0x00000000_0x00016fcb"));
        let i = parse_instance("luid_0x00000000_0x00016fcb_phys_0").unwrap();
        assert_eq!((i.pid, i.luid.as_str()), (None, "0x00000000_0x00016fcb"));
        assert!(parse_instance("_Total").is_none());
        assert!(parse_instance("luid_garbage").is_none());
    }

    #[test]
    fn engine_load_is_summed_per_engine_and_the_busiest_engine_wins() {
        let a = "luid_0x00000000_0x0000aaaa_phys_0";
        let engines: HashMap<String, f64> = [
            (format!("pid_10_{a}_eng_0_engtype_3D"), 70.0),
            (format!("pid_20_{a}_eng_0_engtype_3D"), 25.0),
            (format!("pid_10_{a}_eng_1_engtype_Copy"), 40.0),
            ("pid_30_luid_0x00000000_0x0000bbbb_phys_0_eng_0_engtype_3D".to_string(), 5.0),
        ]
        .into_iter()
        .collect();
        let adapter_mem = vec![(a.to_string(), 7.5e9, 1.0e9)];
        let process_mem = vec![(format!("pid_10_{a}"), 6.0e9, 9.0e8), (format!("pid_20_{a}"), 1.0e9, 0.0)];
        let v = fold(&engines, &adapter_mem, &process_mem);
        assert_eq!(v.len(), 2);
        let first = &v[0];
        assert_eq!((first.busy, first.busiest_engine.as_str(), first.top_pid), (95.0, "3d", Some(10)));
        assert_eq!((first.dedicated, first.shared), (7_500_000_000, 1_000_000_000));
        assert_eq!(first.top_memory, Some((10, 6_000_000_000, 900_000_000)));
        assert_eq!((v[1].busy, v[1].top_pid, v[1].dedicated), (5.0, Some(30), 0));
    }

    #[test]
    fn load_is_capped_at_one_hundred_percent() {
        let engines: HashMap<String, f64> = [
            ("pid_1_luid_0x0_0x1_phys_0_eng_0_engtype_3D".to_string(), 80.0),
            ("pid_2_luid_0x0_0x1_phys_0_eng_0_engtype_3D".to_string(), 45.0),
        ]
        .into_iter()
        .collect();
        assert_eq!(fold(&engines, &[], &[])[0].busy, 100.0);
    }

    /// No counts asserted: CI runners have no GPU and may lack the counters entirely.
    #[test]
    fn reading_this_pc_does_not_panic() {
        for a in adapters() {
            println!("{}  {}  {:.1} GB", a.luid, a.name, a.vram as f64 / 1e9);
        }
        let Some(counters) = Counters::open() else { return };
        std::thread::sleep(Duration::from_millis(400));
        if let Some(s) = counters.sample() {
            for a in s.adapters {
                println!("{a:?}");
            }
        }
    }
}
