# Changelog

What changed in each release, in short. The full notes, with details and download verification, are on the
[releases page](https://github.com/Tyberious/WTFIsStalling/releases). Dates are release dates.

## Unreleased (0.10.0)

### Added
- A short summary for Discord and forums: **Copy summary** in the app, `--summary` on the command line, and a
  `-summary.txt` file next to each report. It fits in one Discord message (2,000 characters, code block
  included) and holds hardware models, the counts and the top findings, never a name, path or serial number.

### Changed
- The report opens with the verdict: how the run measured (thresholds, which traces ran) moved to a "HOW THIS RUN
  MEASURED" block in DETAILS, and anything that changes how to read the result is a one-line note under the
  overview.
- The list of hardware-access tools no longer draws on any GPL-licensed source: every fact once taken from
  Eclypsium's Screwed-Drivers list was re-sourced from LOLDrivers, Microsoft or the vendor, and claims no such
  source confirms were made less specific (for example "an ASRock utility" instead of a product name).

### Fixed
- The 64-bit build of an Intel utility driver (`semav6msr64.sys`) was never recognized.
- Programs could be reported as "held up" for about 2 seconds at a flagged moment when their threads were only
  idle, waiting for their next message or event; on a PC running a browser or other Chromium-based apps this could
  become the top suspect. Such waits no longer count; waits on locks, disks and paging still do.
- The app window showed the full path of the saved report, including the Windows user name; it now shows the file
  name only.

## 0.9.0 (2026-09-24)

### Changed
- Short kernel-level stalls get the checks whole-PC freezes already had: which device interrupts stopped or kept
  arriving, whether the timer kept firing, and which slow disk requests coincided. A stall whose own measuring
  thread was waiting on a page read from disk is reported as that.
- CPU starvation is judged per processor, counting interrupt-level time as busy, so one pegged core on an otherwise
  idle PC is named instead of averaged away.
- Each stall says which priority range a waiting thread was in, and whether the processor was throttled or memory
  was nearly full at that moment.
- A whole-PC freeze that coincided with a slow request on a disk is noted on that disk's finding too; requests that
  were only slowed down by the freeze are not held against the drive.
- Severity weighs how many processors a kernel stall held: one of 32 no longer rates like the whole PC stopping.
- The files that waited on disk say which programs waited on them.
- Durations of 10 seconds and more are shown in seconds.
- The program you were using (the one whose window was in front, noted once a second; never window titles) is named
  first when it was among the programs kept waiting, and at a flagged moment the report says when it was not.
- The driver table says whether each driver's interrupts arrived message-signaled or on a shared line, and the
  device table shows each device's message-signaled interrupt limit where Windows has one set.
- The before/after comparison keeps up to 8 numbers per finding and prints the 3 most telling ones. Data files from
  0.7.0 and 0.8.0 still load.

### Fixed
- At a flagged moment, the list of waiting programs showed the whole run's waits instead of that moment's.
- A few report sentences had a long run of spaces in the middle.

## 0.8.0 (2026-09-24)

### Added
- A slow drive is explained all the way down: what the stuck request was (program code or memory being read back,
  the file cache, the file system's own bookkeeping, or a file's contents), which programs were stuck behind it,
  lock chains, and head thrashing on hard drives.
- How much of each slow request was spent inside the drive and how much waiting in Windows, plus retries, failed
  reads and writes, and drive resets during the run (`--no-storage-trace` turns this off).
- Module-level call stacks for disk requests and slow page faults: which drivers, including file-system filters
  such as antivirus, backup and cloud sync, were in the path. `--deep` also records where every waiting program
  was blocked.

### Fixed
- Privacy: Recycle Bin paths could show the Windows account's security ID and the names inside deleted folders,
  and a file name starting with `$` could make its folder path public.
- A hard drive kept busy seeking between programs was blamed on the drive itself.
- Ordinary file reads through the file cache were described as "paging", which read like a memory problem.

## 0.7.0 (2026-09-21)

### Added
- Whole-PC freezes are reported as one finding, and a driver is only blamed after checking that ordinary interrupt
  work really stopped.
- Reports for PCs with several problems at once: findings grouped by symptom, with a plan and an order of attack.
- Automatic before/after comparison with the previous run.
- Thread-switch tracing: "nothing woke it" is told apart from "it was woken and not given a processor"
  (`--no-switches`).
- Graphics-kernel tracing: how long the picture stopped updating and whether video memory had to be freed
  (`--no-gpu-trace`).
- File names for slow disk requests and page faults, with personal file names hidden.
- Hardware-access tools with the program behind each driver, third-party network filters, and devices on legacy
  line-based interrupts.
- The tool's own cost in every report, and light mode for small PCs (`--light`, `--no-light`).
- More than 64 logical processors, and P-core / E-core labels.

### Changed
- Repeated slow events fold into roll-up lines in the event log.

### Fixed
- Comparisons between runs of different lengths, the NVMe "busy" threshold, and "spare 0%" on drives that do not
  report it.

## 0.6.0 (2026-09-20)

### Added
- The graphics card: load, video memory and which program holds it; "video memory is full"; and, at flagged
  moments, whether the card was working flat out or waiting for the rest of the PC.

### Fixed
- Flagged moments with a firmware or unknown cause could be left out of the result.
- The Windows timer resolution stayed raised after Stop until the window was closed.
- A crash could leave the kernel trace running.
- Parts of Windows (`System`, svchost, Defender, dwm) were called programs you could close.

## 0.5.1 (2026-09-20)

### Added
- Stalls within 2 seconds of a logged hardware error (WHEA) are tied to it.
- Crashes and sudden power loss from the last 7 days, with blue-screen names.
- Firmware processor speed caps from the event log back up throttling findings.

### Fixed
- `SHA256SUMS.txt` works with `sha256sum -c` on Linux, macOS and Git Bash.

## 0.5.0 (2026-09-20)

### Added
- Drivers are named after the device they drive, with the driver's age.

### Fixed
- A graphics driver reset from the event log lands in the same finding as stalls blamed on that driver.

## 0.4.1 (2026-09-20)

### Changed
- Drives are never opened for reading or writing; SATA SMART comes from a query that needs no access to the disk.
- The executables carry a product name, description, version and icon, and every release has build provenance.

## 0.4.0 (2026-09-20)

### Added
- Why a disk was slow: busy, asleep, flushing, or slow with little asked of it.
- Drive health: temperature, the NVMe health log and SATA SMART, compared between the start and end of the run.
- What Windows logged in the last 7 days: hardware errors (WHEA), storage errors and graphics driver resets.

## 0.3.0 (2026-09-20)

### Added
- Slow disks are named: drive letters, model, connection, size, firmware and how full each volume is, with advice
  that fits the kind of drive.

## 0.2.0 (2026-09-20)

### Added
- "I felt it!" button and Ctrl+Shift+F9 to flag the moment of a hitch.
- The answer comes first: a colored verdict and ranked findings with what to try.
- Stalls and long interrupt runs that repeat on a timer, the signature of utilities polling hardware.
- CPU throttling detection.
- Follows the Windows light / dark theme.

### Fixed
- The 1-2 ms wake-up blips every healthy PC shows are no longer blamed on a driver.
- Interrupt time was counted twice, and the window showed the result as one endless line.

## 0.1.0 (2026-09-20)

- First release.
