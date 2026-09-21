//! WTFIsStalling: finds the driver, app or hardware behind hitches and micro-stalls.
//!
//! `engine` runs a monitoring session; `src/bin/gui.rs` and `src/bin/cli.rs` are thin
//! front ends over it.

pub mod analyze;
pub mod baseline;
pub mod cpuclock;
pub mod devices;
pub mod disks;
pub mod diskwait;
pub mod diskwhy;
pub mod engine;
pub mod etw;
pub mod evlog;
pub mod files;
pub mod gpu;
pub mod health;
pub mod hwaccess;
pub mod interrupts;
pub mod intr;
pub mod modules;
pub mod netfilters;
pub mod overhead;
pub mod pci;
pub mod pdh;
pub mod period;
pub mod probe;
pub mod procs;
pub mod quiet;
pub mod reg;
pub mod state;
pub mod summary;
pub mod switches;
pub mod topology;
pub mod util;
