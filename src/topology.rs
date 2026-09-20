//! What logical CPUs this PC has: processor groups, and on hybrid chips which cores are the
//! fast ones (P-cores) and which are the efficiency ones (E-cores).
//!
//! Windows splits machines with more than 64 logical CPUs into *processor groups* of at most
//! 64. Thread affinity is always group-relative, but ETW reports the CPU an event ran on as a
//! single system-wide index. Both numbers have to agree or a stall on CPU 70 would be matched
//! against DPCs on CPU 6.
//!
//! The mapping used here: the groups are numbered consecutively, so the system-wide index of a
//! processor is the number of active processors in all lower-numbered groups plus its own index
//! inside its group. Microsoft documents the conversion as a routine,
//! `KeGetProcessorIndexFromNumber` (wdm.h), which takes a (group, group-relative number) pair
//! and returns a "systemwide processor index", and gives exactly this example: "if a
//! multiprocessor system contains two groups, and each group contains 64 logical processors,
//! the processor numbers in each group range from 0 to 63, but the systemwide processor
//! indexes range from 0 to 127."
//! <https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/nf-wdm-kegetprocessorindexfromnumber>
//!
//! Microsoft does not publish the arithmetic, and one documented case could break it: "If the
//! system is capable of hot-adding processors, the operating system allows space in groups for
//! processors that might arrive while the system is running"
//! (<https://learn.microsoft.com/windows/win32/procthread/processor-groups>), so a group's
//! active count can be below its reserved size. On an ordinary machine the OS "minimizes the
//! number of groups" and fills them, and active == reserved. Nothing breaks if the assumption
//! ever fails: a stall would simply not line up with the trace's DPC/ISR records and the
//! verdict falls back to "no clear culprit".

use std::ptr::null_mut;
use std::sync::OnceLock;

use windows_sys::Win32::System::SystemInformation::{GetSystemCpuSetInformation, SYSTEM_CPU_SET_INFORMATION};
use windows_sys::Win32::System::Threading::{GetActiveProcessorCount, GetActiveProcessorGroupCount};

/// One logical CPU to pin a probe thread to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    pub group: u16,
    /// Index inside the group, 0..64. Microsoft on the CPU set fields: "The Group and
    /// LogicalProcessorIndex fields ... correspond to the Group field and Mask field of the
    /// GROUP_AFFINITY structure", so this is the bit to set in that mask.
    pub index: u8,
    /// System-wide processor index, which is what ETW reports and what the report shows.
    pub cpu: u16,
}

/// One record of `GetSystemCpuSetInformation`, reduced to what we use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuSet {
    pub group: u16,
    pub index: u8,
    /// Microsoft: "CPU Sets with higher numerical values of this field have home processors
    /// that are faster but less power-efficient than ones with lower values." All equal on a
    /// non-hybrid CPU.
    pub class: u8,
    /// Group-relative CoreIndex: "the same for all CPU Sets in the same group that share
    /// significant execution resources", i.e. the two hardware threads of one core share it.
    pub core: u8,
}

/// One logical CPU, as the rest of the program sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cpu {
    pub slot: Slot,
    pub class: u8,
    pub core: u8,
}

#[derive(Clone, Debug, Default)]
pub struct Topology {
    /// Active logical CPUs in each processor group, group 0 first.
    pub groups: Vec<u32>,
    /// Every active logical CPU, in system-wide index order.
    pub cpus: Vec<Cpu>,
}

/// Every active logical CPU as (group, group-relative index, system-wide index).
///
/// `groups[g]` is the number of *active* processors in group g. Groups need not be full: a
/// 96-CPU machine can be 2 groups of 48, and then group 1's indexes 0..48 are system-wide
/// 48..96.
pub fn processor_slots(groups: &[u32]) -> Vec<Slot> {
    let mut out = Vec::new();
    let mut base = 0u32;
    for (group, &n) in groups.iter().enumerate() {
        // A group holds at most 64 processors, so the index always fits in a u8 and in the bit
        // mask of a GROUP_AFFINITY.
        for index in 0..n.min(64) {
            out.push(Slot { group: group as u16, index: index as u8, cpu: (base + index).min(u16::MAX as u32) as u16 });
        }
        base += n.min(64);
    }
    out
}

/// Active processor count per group, as Windows reports it. `GetActiveProcessorGroupCount`
/// "returns the number of active processor groups in the system" and `GetActiveProcessorCount`
/// "the number of active processors in the specified group"
/// (<https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-getactiveprocessorcount>).
pub fn active_groups() -> Vec<u32> {
    unsafe { (0..GetActiveProcessorGroupCount()).map(|g| GetActiveProcessorCount(g)).collect() }
}

/// Walks the variable-size `SYSTEM_CPU_SET_INFORMATION` records in `buf`. Microsoft: "This is a
/// variable-sized structure designed for future expansion. When iterating over this structure,
/// use the size field to determine the offset to the next structure", and "Applications should
/// skip any structures with unrecognized types" -- which is what this does.
/// <https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-system_cpu_set_information>
///
/// Offsets of the CpuSet variant, from that page's field list and windows-sys 0.61's
/// `SYSTEM_CPU_SET_INFORMATION` (Size 32 on every current Windows, but each record carries its
/// own Size and we step by it, so a future longer record is read correctly):
///   0 Size u32 | 4 Type u32 (0 = CpuSetInformation) | 8 Id u32 | 12 Group u16
///   14 LogicalProcessorIndex u8 | 15 CoreIndex u8 | 16 LastLevelCacheIndex u8
///   17 NumaNodeIndex u8 | 18 EfficiencyClass u8 | 19 AllFlags u8 | 20 Reserved u32
///   24 AllocationTag u64
pub fn parse_cpu_sets(buf: &[u8]) -> Vec<CpuSet> {
    const CPU_SET_INFORMATION: u32 = 0;
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 8 <= buf.len() {
        let size = u32::from_le_bytes(buf[at..at + 4].try_into().unwrap()) as usize;
        let kind = u32::from_le_bytes(buf[at + 4..at + 8].try_into().unwrap());
        // A zero or unaligned size would loop forever; anything shorter than the fixed part is junk.
        if size < 24 || at + size > buf.len() {
            break;
        }
        if kind == CPU_SET_INFORMATION {
            let r = &buf[at..];
            out.push(CpuSet { group: u16::from_le_bytes([r[12], r[13]]), index: r[14], class: r[18], core: r[15] });
        }
        at += size;
    }
    out
}

fn cpu_sets() -> Vec<CpuSet> {
    unsafe {
        let mut needed = 0u32;
        GetSystemCpuSetInformation(null_mut(), 0, &mut needed, null_mut(), 0);
        if needed == 0 || needed > 1 << 20 {
            return Vec::new();
        }
        // u64-backed so the records are aligned like the struct Windows fills in.
        let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
        let p = buf.as_mut_ptr() as *mut SYSTEM_CPU_SET_INFORMATION;
        if GetSystemCpuSetInformation(p, needed, &mut needed, null_mut(), 0) == 0 {
            return Vec::new();
        }
        let bytes = std::slice::from_raw_parts(buf.as_ptr() as *const u8, (needed as usize).min(buf.len() * 8));
        parse_cpu_sets(bytes)
    }
}

impl Topology {
    /// Pure builder: group sizes plus whatever `GetSystemCpuSetInformation` said (possibly
    /// nothing, in which case every CPU is treated as one uniform class).
    pub fn build(groups: &[u32], sets: &[CpuSet]) -> Topology {
        let cpus = processor_slots(groups)
            .into_iter()
            .map(|slot| {
                let found = sets.iter().find(|s| s.group == slot.group && s.index == slot.index);
                Cpu { slot, class: found.map_or(0, |s| s.class), core: found.map_or(slot.index, |s| s.core) }
            })
            .collect();
        Topology { groups: groups.to_vec(), cpus }
    }

    pub fn load() -> Topology {
        Topology::build(&active_groups(), &cpu_sets())
    }

    pub fn total(&self) -> usize {
        self.cpus.len()
    }

    /// True when the CPU has cores of different speeds (Intel 12th gen and later, some ARM).
    pub fn hybrid(&self) -> bool {
        self.cpus.first().is_some_and(|f| self.cpus.iter().any(|c| c.class != f.class))
    }

    fn top_class(&self) -> u8 {
        self.cpus.iter().map(|c| c.class).max().unwrap_or(0)
    }

    fn find(&self, cpu: u16) -> Option<&Cpu> {
        // Built in system-index order, so the index is the answer; the search is belt and braces.
        match self.cpus.get(cpu as usize) {
            Some(c) if c.slot.cpu == cpu => Some(c),
            _ => self.cpus.iter().find(|c| c.slot.cpu == cpu),
        }
    }

    /// "P-core" / "E-core", or None on a CPU whose cores are all the same (nothing to say).
    /// With three classes (rare), only the top one counts as a performance core.
    pub fn core_type(&self, cpu: u16) -> Option<&'static str> {
        if !self.hybrid() {
            return None;
        }
        let top = self.top_class();
        self.find(cpu).map(|c| if c.class == top { "P-core" } else { "E-core" })
    }

    pub fn is_efficiency(&self, cpu: u16) -> bool {
        self.core_type(cpu) == Some("E-core")
    }

    /// Logical CPUs that are efficiency cores.
    pub fn efficiency_cpus(&self) -> usize {
        let top = self.top_class();
        self.cpus.iter().filter(|c| c.class != top).count()
    }

    /// One line about the CPU layout, only when there is something unusual to say: a hybrid
    /// chip, or more than one processor group. None on an ordinary machine.
    pub fn note(&self) -> Option<String> {
        let groups = match self.groups.len() {
            0 | 1 => String::new(),
            n => format!("; {n} processor groups ({})", self.groups.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(" + ")),
        };
        if self.hybrid() {
            let top = self.top_class();
            let part = |perf: bool| {
                let cpus: Vec<&Cpu> = self.cpus.iter().filter(|c| (c.class == top) == perf).collect();
                let mut cores: Vec<(u16, u8)> = cpus.iter().map(|c| (c.slot.group, c.core)).collect();
                cores.sort_unstable();
                cores.dedup();
                let (n, threads) = (cores.len(), cpus.len());
                let name = if perf { "P-core" } else { "E-core" };
                let s = if n == 1 { "" } else { "s" };
                if threads > n {
                    format!("{n} {name}{s} ({threads} threads)")
                } else {
                    format!("{n} {name}{s}")
                }
            };
            Some(format!("{} + {}{groups}", part(true), part(false)))
        } else if !groups.is_empty() {
            Some(format!("{} logical CPUs{groups}", self.total()))
        } else {
            None
        }
    }
}

/// The live machine's layout, read once.
pub fn topology() -> &'static Topology {
    static TOPO: OnceLock<Topology> = OnceLock::new();
    TOPO.get_or_init(Topology::load)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(group: u16, index: u8, class: u8, core: u8) -> CpuSet {
        CpuSet { group, index, class, core }
    }

    /// Two full groups plus a partial one: the system-wide index keeps counting across groups.
    #[test]
    fn slots_are_numbered_consecutively_across_groups() {
        let slots = processor_slots(&[64, 64, 32]);
        assert_eq!(slots.len(), 160);
        assert_eq!(slots[0], Slot { group: 0, index: 0, cpu: 0 });
        assert_eq!(slots[63], Slot { group: 0, index: 63, cpu: 63 });
        assert_eq!(slots[64], Slot { group: 1, index: 0, cpu: 64 });
        assert_eq!(slots[127], Slot { group: 1, index: 63, cpu: 127 });
        assert_eq!(slots[128], Slot { group: 2, index: 0, cpu: 128 });
        assert_eq!(slots[159], Slot { group: 2, index: 31, cpu: 159 });
        // Every index stays inside its group's 64-bit affinity mask.
        assert!(slots.iter().all(|s| s.index < 64));
    }

    /// Groups need not be full: 96 CPUs as 2 x 48 still number 0..96 system-wide.
    #[test]
    fn partial_groups_still_number_consecutively() {
        let slots = processor_slots(&[48, 48]);
        assert_eq!(slots[47], Slot { group: 0, index: 47, cpu: 47 });
        assert_eq!(slots[48], Slot { group: 1, index: 0, cpu: 48 });
        assert_eq!(slots.last(), Some(&Slot { group: 1, index: 47, cpu: 95 }));
    }

    #[test]
    fn one_group_is_the_ordinary_case() {
        let slots = processor_slots(&[32]);
        assert_eq!(slots.len(), 32);
        assert!(slots.iter().enumerate().all(|(i, s)| s.group == 0 && s.index as usize == i && s.cpu as usize == i));
        assert_eq!(processor_slots(&[]), vec![]);
    }

    fn record(size: u32, kind: u32, group: u16, index: u8, core: u8, class: u8) -> Vec<u8> {
        let mut r = vec![0u8; size as usize];
        r[0..4].copy_from_slice(&size.to_le_bytes());
        r[4..8].copy_from_slice(&kind.to_le_bytes());
        r[12..14].copy_from_slice(&group.to_le_bytes());
        r[14] = index;
        r[15] = core;
        r[18] = class;
        r
    }

    /// 2 P-cores with SMT (class 1) + 4 E-cores (class 0), the shape of an Intel 12th gen part.
    fn hybrid_records() -> Vec<u8> {
        let mut buf = Vec::new();
        for i in 0..4u8 {
            buf.extend(record(32, 0, 0, i, i / 2, 1));
        }
        for i in 0..4u8 {
            buf.extend(record(32, 0, 0, 4 + i, 2 + i, 0));
        }
        buf
    }

    #[test]
    fn hybrid_records_are_parsed_and_labeled() {
        let sets = parse_cpu_sets(&hybrid_records());
        assert_eq!(sets.len(), 8);
        assert_eq!(sets[0], set(0, 0, 1, 0));
        assert_eq!(sets[7], set(0, 7, 0, 5));

        let topo = Topology::build(&[8], &sets);
        assert!(topo.hybrid());
        assert_eq!(topo.core_type(0), Some("P-core"));
        assert_eq!(topo.core_type(3), Some("P-core"));
        assert_eq!(topo.core_type(4), Some("E-core"));
        assert_eq!(topo.core_type(7), Some("E-core"));
        assert_eq!(topo.core_type(99), None, "a CPU we know nothing about gets no label");
        assert_eq!(topo.efficiency_cpus(), 4);
        assert_eq!(topo.note().as_deref(), Some("2 P-cores (4 threads) + 4 E-cores"));
    }

    /// The development machine's shape: one group, every core the same. Nothing may be said.
    #[test]
    fn a_uniform_cpu_says_nothing_about_core_types() {
        let sets: Vec<CpuSet> = (0..32u8).map(|i| set(0, i, 0, i / 2)).collect();
        let topo = Topology::build(&[32], &sets);
        assert!(!topo.hybrid());
        assert!((0..32).all(|c| topo.core_type(c).is_none()));
        assert!(!topo.is_efficiency(0));
        assert_eq!(topo.efficiency_cpus(), 0);
        assert_eq!(topo.note(), None, "an ordinary PC gets no topology line at all");
    }

    #[test]
    fn several_groups_are_worth_a_note_even_when_uniform() {
        let sets: Vec<CpuSet> = (0..2u16).flat_map(|g| (0..64u8).map(move |i| set(g, i, 0, i / 2))).collect();
        let topo = Topology::build(&[64, 64], &sets);
        assert!(!topo.hybrid());
        assert_eq!(topo.total(), 128);
        assert_eq!(topo.note().as_deref(), Some("128 logical CPUs; 2 processor groups (64 + 64)"));
    }

    #[test]
    fn efficiency_class_is_matched_per_group_not_by_position() {
        // Group 1's CPUs are the slow ones; their group-relative indexes repeat group 0's.
        let mut sets: Vec<CpuSet> = (0..4u8).map(|i| set(0, i, 2, i)).collect();
        sets.extend((0..4u8).map(|i| set(1, i, 0, i)));
        let topo = Topology::build(&[4, 4], &sets);
        assert_eq!(topo.core_type(0), Some("P-core"));
        assert_eq!(topo.core_type(4), Some("E-core"), "system CPU 4 is group 1 index 0");
        assert_eq!(topo.note().as_deref(), Some("4 P-cores + 4 E-cores; 2 processor groups (4 + 4)"));
    }

    #[test]
    fn truncated_or_garbage_buffers_are_survived() {
        assert_eq!(parse_cpu_sets(&[]), vec![]);
        assert_eq!(parse_cpu_sets(&[0; 7]), vec![], "shorter than one Size + Type");
        // A record claiming to be longer than the buffer is dropped, not read past.
        let mut short = record(32, 0, 0, 0, 0, 1);
        short.truncate(20);
        assert_eq!(parse_cpu_sets(&short), vec![]);
        // Size 0 would loop forever.
        assert_eq!(parse_cpu_sets(&[0u8; 32]), vec![]);
        // A record of an unknown Type is skipped by its own Size, and parsing continues.
        let mut mixed = record(40, 7, 0, 0, 0, 0);
        mixed.extend(record(32, 0, 0, 3, 1, 1));
        assert_eq!(parse_cpu_sets(&mixed), vec![set(0, 3, 1, 1)]);
        // Half a record at the end of a good one.
        let mut tail = record(32, 0, 0, 0, 0, 0);
        tail.extend([32, 0, 0, 0, 0]);
        assert_eq!(parse_cpu_sets(&tail), vec![set(0, 0, 0, 0)]);
    }

    /// No CPU set data at all (ancient Windows, or the call failing): still a usable topology.
    #[test]
    fn missing_cpu_set_data_degrades_to_a_uniform_machine() {
        let topo = Topology::build(&[16], &[]);
        assert_eq!(topo.total(), 16);
        assert!(!topo.hybrid());
        assert_eq!(topo.core_type(3), None);
        assert_eq!(topo.note(), None);
    }

    /// Prints what this PC actually looks like. Asserts only what must hold everywhere,
    /// because CI runners are small VMs.
    #[test]
    fn live_topology_is_consistent() {
        let topo = Topology::load();
        println!("groups: {:?}", topo.groups);
        println!("note: {:?}", topo.note());
        for c in &topo.cpus {
            println!("  CPU {:>3}  group {} index {:>2}  core {:>2}  class {}", c.slot.cpu, c.slot.group, c.slot.index, c.core, c.class);
        }
        assert_eq!(topo.total(), topo.groups.iter().map(|n| *n as usize).sum::<usize>());
        assert!(topo.cpus.iter().enumerate().all(|(i, c)| c.slot.cpu as usize == i));
        assert!(topo.cpus.iter().all(|c| c.slot.index < 64));
        if !topo.hybrid() {
            assert!(topo.cpus.iter().all(|c| topo.core_type(c.slot.cpu).is_none()));
        }
    }
}
