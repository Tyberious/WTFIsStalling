# WTFIsStalling

[![CI](https://github.com/Tyberious/WTFIsStalling/actions/workflows/ci.yml/badge.svg)](https://github.com/Tyberious/WTFIsStalling/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/Tyberious/WTFIsStalling?sort=semver&label=release&cacheSeconds=1800)](https://github.com/Tyberious/WTFIsStalling/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/Tyberious/WTFIsStalling/total?label=downloads&cacheSeconds=1800)](https://github.com/Tyberious/WTFIsStalling/releases)
[![License: MIT](https://img.shields.io/github/license/Tyberious/WTFIsStalling)](LICENSE)
![Platform: Windows 10 / 11 x64](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011%20x64-0078D4)
![Built with Rust](https://img.shields.io/badge/built%20with-Rust-dea584?logo=rust)
[![Open issues](https://img.shields.io/github/issues/Tyberious/WTFIsStalling?cacheSeconds=1800)](https://github.com/Tyberious/WTFIsStalling/issues)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](CONTRIBUTING.md)
[![GitHub stars](https://img.shields.io/github/stars/Tyberious/WTFIsStalling?style=flat&cacheSeconds=1800)](https://github.com/Tyberious/WTFIsStalling/stargazers)

**Finds the driver, program or hardware behind hitches, micro-stalls and audio crackle on Windows.**

Someone tells you "my PC stutters every few seconds" and nothing in Task Manager explains it.
WTFIsStalling watches the Windows kernel while the problem happens and then tells you, in plain
language, what was responsible and what to try.

It is a single small `.exe`. No installer, no driver, no dependencies. It only observes; it changes
nothing on the system.

## Use it

1. Download `WTFIsStalling.exe` from [Releases](https://github.com/Tyberious/WTFIsStalling/releases) and run it.
   Say **Yes** to the administrator prompt (tracing the kernel requires it).
2. Click **Start monitoring**.
3. Use the PC until the hitch happens, ideally a few times. Run the game or app that has the problem.
   **When you feel a hitch, press Ctrl+Shift+F9** (works inside games) or click **I felt it!** The report
   then zooms in on the seconds before each press, with no thresholds.
4. Click **Stop**. Read the summary, or click **Copy report** and paste it to whoever is helping you.

> **"Windows protected your PC"?** That is SmartScreen reacting to a new, unsigned program that few
> people have downloaded yet, not a virus detection. Click **More info**, then **Run anyway**. If you
> would rather verify first, compare the file against `SHA256SUMS.txt` from the same release
> (`Get-FileHash WTFIsStalling.exe` in PowerShell), or build it yourself from this source.

The colored bar gives the verdict; the report underneath starts with the ranked findings and what to
try for each, followed by the supporting numbers and the event log. A copy is saved next to the exe as
`WTFIsStalling-<date>.txt`. The window follows the system light / dark theme.

| | |
| --- | --- |
| ![Cause found (dark theme)](docs/screenshot-result-dark.png) | ![Suspect found (light theme)](docs/screenshot-result-light.png) |

![While monitoring: press "I felt it!" or Ctrl+Shift+F9 when a hitch happens](docs/screenshot-monitoring.png)

*(Screenshots show built-in demo data.)*

## What it can pin down

| Cause | How it shows up |
| --- | --- |
| A misbehaving **driver** (GPU, network, Wi-Fi, USB, audio, storage, RGB/monitoring tools...) | Long DPC/ISR routines, attributed to the exact `.sys` file, with advice for the usual suspects |
| **Firmware / BIOS / SMI**, hypervisor, or a driver running with interrupts off | The CPU "goes dark": a stall with no OS-visible activity and missing profiler interrupts |
| A **program** starving the CPU | A normal-priority thread can't get a core; the report names who was on the CPUs |
| **CPU throttling** (heat or power limits) | Busy cores running well under their rated speed, or Windows reporting a performance cap, and whether stalls coincide |
| Something **polling on a timer** (RGB / monitoring / vendor utilities) | Stalls or long interrupt runs that repeat at a steady interval: "repeats about every 10.0 s" |
| **Paging** (not enough RAM, or a process being swapped in) | Hard page faults per process with how long each was frozen |
| A **slow or dying disk** | Per-disk request latency, slow requests and who issued them; the disk is named by drive letter, model, connection, size, firmware and how full it is, and the report says **why** it was slow: busy (and which program was moving the data), asleep and waking up, forced flushes, or idle-but-slow (the drive, cable or firmware) |
| **A drive that is failing, overheating or on a bad cable** | Each drive's own health data, read when monitoring starts and ends: NVMe critical warnings, media errors, wear, temperature and thermal throttling; SATA SMART bad sectors and CRC (cable) errors. Counters that moved *while monitoring* are flagged as the cause, lifetime totals only as background |
| **Drive errors Windows logged** | System event log, last 7 days: controller resets (129), retried I/O (153), bad blocks (7), paging errors (51), surprise disconnects (157) |
| **Graphics driver hangs** | "Display driver stopped responding and was reset" (event 4101) from the System event log, last 7 days |
| **Failing or unstable hardware** | WHEA errors from the System event log, last 7 days: corrected memory errors (unstable XMP/EXPO, bad DIMM), corrected processor errors (undervolt, PBO, overclock), PCI Express link errors with the device named (riser cables, GPU, NVMe), and fatal hardware errors that crashed the PC |

What it cannot see: stalls inside an application itself or on the GPU (shader compilation, VRAM
overflow, frame pacing). It can rule the rest out, though: if you flag a hitch and no CPU core was
interrupted for even a millisecond around it, the report says so, and that's where to look next.

## Example report (illustrative)

```
====================================================================================================
RESULT

  >>> PROBLEM FOUND: rtwlane.sys  -  Wi-Fi adapter driver
      Blamed for 14 stalls (worst 11.80 ms, 121 ms in total).  (+1 more finding below)

  Monitored 05:12  |  14 kernel-level stall(s), 0 CPU-starvation stall(s)  |  worst wake-up delay 11.80 ms ...

  1. [HIGH] rtwlane.sys  -  Wi-Fi adapter driver
       - Blamed for 14 stalls (worst 11.80 ms, 121 ms in total).
       - Its interrupt handling ran for up to 10.97 ms at a time (14 times over 1.00 ms). Healthy
         drivers stay under 0.5 ms; longer runs block everything else on that CPU core ...
     What to try:
       Update the Wi-Fi driver from the chip vendor (Intel/Realtek/MediaTek/Qualcomm), disable adapter
       power saving and background scanning/roaming aggressiveness; test with Wi-Fi off and Ethernet in.

  2. [MEDIUM] Disk 1 (D:), WDC WD40EZAZ-00SF3B0  -  responding slowly
       - 3 requests took longer than 200 ms (worst 840 ms). SATA hard drive, 4.0 TB, firmware
         80.00A80. D: 93% full.
       - Why: the disk was busy moving a lot of data (every time). The traffic came from steam.exe
         (3 GB, 97% of the traffic: Steam downloading, updating or verifying a game).
     What to try: ...
====================================================================================================
DETAILS
  (who caused the stalls, per-driver DPC/ISR table, hard page faults per process, disk latency,
   drive health, what the Windows event log held)

EVENT LOG (chronological)
[21:14:07.412] STALL #3  kernel-level (DPC/ISR/firmware)  11.80 ms  on CPU 4
    VERDICT: rtwlane.sys [Wi-Fi adapter driver] kept the CPU in DPC/ISR code for 93% of the stall
    ...
```

Findings come from stalls (who was blamed), drivers whose DPC/ISR routines run too long even without a
full stall, programs frozen by paging, disks answering slowly, what each drive reports about its own
health, and hardware, storage and graphics-driver errors in the Windows event log. **HIGH** means it
repeatedly or badly stalled the machine, or went wrong while you were monitoring; **MEDIUM** is a
suspect that can cause crackle and micro-stutter; **LOW** is a lead worth knowing about.

## How it works

Two independent sources, correlated on one clock (QPC):

* **Kernel ETW trace.** A private real-time system-logger session records every DPC and ISR (with the
  driver routine address and duration), hard page faults, disk I/O latency, thread creation (for
  thread → process mapping) and 1 kHz CPU profile samples. Routine addresses are resolved to the loaded
  driver; a built-in knowledge base plus each file's version resource explains what that driver is.
* **Latency probes.** A helper process in the REALTIME priority class runs one thread per CPU at
  priority 31, pinned, waking every millisecond and measuring how late each wake-up was. Nothing but
  DPCs, ISRs, code at raised IRQL, firmware (SMI) or a hypervisor can delay those threads, so a late
  wake-up *is* a kernel-level stall. A second, normal-priority probe detects plain CPU starvation.

When a probe reports a stall, the analyzer waits for the trace to catch up, looks at exactly what ran
on that CPU during that window and issues a verdict:

1. DPC/ISR time covers the stall → blame the driver that owns the routine.
2. Almost no profiler interrupts arrived and no DPC/ISR explains it → the CPU was taken away from
   Windows entirely: SMI/firmware, hypervisor, or interrupts disabled.
3. Otherwise → whichever kernel module or process the CPU samples show.

**Flagged moments.** Wake-up delays from 1 ms up are kept for 30 seconds even though they are far below
the stall threshold. When you press "I felt it", the worst one in the 3 seconds before the press goes
through the same verdict logic as a full stall; if there is none, the CPU side is cleared for that hitch.

**CPU clock.** Once a second the "Processor Information" counters are read per core. Only cores that are
busy are judged: an idle core clocking down is normal, a busy core at half speed is throttling.

**Why a disk was slow.** A completed disk request carries its duration, so its start is known too.
What else that disk finished while a slow request was outstanding tells a busy disk (the programs
moving the data are named) from one that had nothing else to do and was slow anyway, which points at
the drive, its cable or its firmware. A slow first request after seconds of silence is a drive waking
from sleep.

**Drive health and the Windows event log.** Each drive's temperature and health data (NVMe health log,
SATA SMART) is read when monitoring starts and again when it stops, so that counters which moved
during the run (thermal throttling, cable CRC errors) stand apart from lifetime totals. The System
event log is read for the last 7 days: storage resets and retries, WHEA hardware errors (PCI Express
errors are mapped to the device in that slot) and graphics driver resets. Drive serial numbers are
never read, so a report is safe to post.

Individually slow events (DPC ≥ 1 ms, hard fault ≥ 50 ms, disk request ≥ 200 ms) are logged even when no
probe stalls.

## Command line

`wtfis-cli.exe` is the same engine on the console, for scripting and for tuning thresholds:

```
wtfis-cli --duration 300 --stall-ms 2 --dpc-warn-us 500
```

Run `wtfis-cli --help` for all options. Press Enter to flag a hitch, Ctrl+C to stop and print the
summary.

## Building

Requires Rust (stable) on Windows, either toolchain (`x86_64-pc-windows-msvc` or `-gnu`).

```
cargo build --release
```

produces `target/release/WTFIsStalling.exe` (GUI) and `target/release/wtfis-cli.exe`. Both are
statically linked and need nothing but Windows 10 1803 or later, 64-bit.

```
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

RustRover / IntelliJ users get ready-made run targets from the `.run/` folder: the GUI (normal,
elevated-and-debuggable, or UI-only), 30-second CLI captures, and the same test / clippy / fmt checks
CI runs.

Working on the window without admin rights:

| Variable | Effect |
| --- | --- |
| `WTFIS_DEMO=problem\|warning\|ok` | Start/Stop shows a canned result instead of monitoring |
| `WTFIS_THEME=dark\|light` | Override the system theme |
| `WTFIS_SKIP_ELEVATION=1` | Don't elevate; real monitoring then fails with "access denied" (tests that path) |

## Contributing

Yes please. The most valuable contributions need no kernel knowledge at all: **teach the tool about
more drivers** (see `KB` in [`src/modules.rs`](src/modules.rs)) and **send reports from real problem
machines**. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
