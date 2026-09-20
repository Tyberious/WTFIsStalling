//! WTFIsStalling: finds the driver, app or hardware behind hitches and micro-stalls.
//!
//! `engine` runs a monitoring session; `src/bin/gui.rs` and `src/bin/cli.rs` are thin
//! front ends over it.

pub mod analyze;
pub mod cpuclock;
pub mod disks;
pub mod diskwhy;
pub mod engine;
pub mod etw;
pub mod evlog;
pub mod modules;
pub mod period;
pub mod probe;
pub mod procs;
pub mod state;
pub mod summary;
pub mod util;
