# Contributing to WTFIsStalling

Thanks for helping. The goal of this project is simple: a person with a stuttering PC runs one exe and
gets a correct, plainly worded answer. Anything that makes the answer more correct or more
understandable is welcome.

## Ways to help, easiest first

### 1. Add a driver to the knowledge base

When the tool blames `something.sys` it looks it up in `KB` in [`src/modules.rs`](src/modules.rs). If
the driver isn't there, the report falls back to the file's vendor string and generic advice. Adding
an entry is a few lines:

```rust
(&["rtwlane", "rtwlanu"], Knowledge {
    what: "Realtek Wi-Fi adapter driver",
    advice: "What someone should actually try, most likely fix first.",
}),
```

Entries match by lower-case file name **prefix**. Keep `what` to a short noun phrase, and make
`advice` specific and safe: things a normal user can do and undo. Add an assertion to the
`knowledge_matches_by_case_insensitive_prefix` test.

### 2. Share a report from a problem machine

Open an issue with the "Report from a stalling PC" template and paste the report. Reports where the
tool was **wrong or unhelpful** are the most useful ones: a stall it didn't catch, a verdict that
blamed the wrong thing, advice that didn't apply. Say what the real cause turned out to be if you know.

Reports contain your CPU, motherboard, BIOS version, Windows build, driver file names and the names
of running programs. They contain no file contents, user names, network addresses or keystrokes.
Trim anything you'd rather not share.

### 3. Improve the analysis

Bigger ideas that would be great to have:

* GPU-side visibility (DxgKrnl ETW provider: present/flip timing, GPU scheduler stalls)
* Context-switch tracing to name the exact thread that was starved, and by whom
* File names for hard faults and slow disk I/O (FileIo rundown)
* CPU frequency / throttling / core-parking detection
* Processor groups (more than 64 logical CPUs)
* Translations of the summary text

Open an issue first for anything large so we can agree on the approach.

## Ground rules for code

* **Observe only.** The tool must never change system settings, install a driver, or write outside
  its own report file.
* **Stay light.** It runs while someone is reproducing a latency problem. No GPU rendering, no busy
  loops, no heavy dependencies. The ETW callback must stay allocation-light and must never block.
* **Be honest in verdicts.** If the evidence is weak, say "inconclusive". A confident wrong answer
  sends someone reinstalling the wrong driver.
* **The real-time probe process is dangerous by nature.** Threads at priority 31 that spin would
  freeze the machine. Any change to `src/probe.rs` must keep the guards that make the loop exit when
  waits fail or return early.
* Kernel event layouts and flag values come from the Windows SDK headers. Prefer constants from
  `windows-sys` over hand-typed numbers, and cite the structure name when parsing a payload.

## Workflow

```
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

CI runs the same three on every pull request. Then test for real: run the GUI as administrator,
monitor for a minute, and check the summary still makes sense. `wtfis-cli --debug` prints the count of
every kernel event type received, which is the quickest way to see whether a trace flag or parser
change did what you meant.

Useful for generating stalls on purpose: a CPU stress test (starvation), copying a huge file on a slow
disk (I/O), opening many browser tabs on a RAM-starved VM (hard faults), and on real hardware simply
running with RGB/monitoring utilities open (DPC latency).

## Code signing (maintainers)

Releases are signed through [SignPath Foundation](https://signpath.org/apply), which signs open-source
projects for free. The release workflow already contains the signing steps; they switch on by
themselves once these exist in the repository settings (Settings > Secrets and variables > Actions):

| Kind | Name | Value |
| --- | --- | --- |
| Variable | `SIGNPATH_ORGANIZATION_ID` | the organization ID SignPath shows after approval |
| Secret | `SIGNPATH_API_TOKEN` | an API token of a SignPath user allowed to submit signing requests |
| Variable (optional) | `SIGNPATH_PROJECT_SLUG` | defaults to `WTFIsStalling` |
| Variable (optional) | `SIGNPATH_SIGNING_POLICY_SLUG` | defaults to `release-signing` |

In SignPath, link the project to this GitHub repository as a trusted build system, and use an artifact
configuration that signs both `WTFIsStalling.exe` and `wtfis-cli.exe` inside the uploaded zip. The
workflow fails the release if a signature does not verify, so an unsigned file can never be published
by accident once signing is on. Build provenance attestation works without any of this.

## Layout

| File | Role |
| --- | --- |
| `src/engine.rs` | One monitoring run from start to summary; shared by both front ends |
| `src/etw/` | Kernel trace session (`mod.rs`) and event payload parsing (`events.rs`) |
| `src/probe.rs` | Latency probes and the real-time helper process |
| `src/analyze.rs` | Correlation and per-incident verdicts, including user-flagged moments |
| `src/summary/` | Ranked findings, verdict and report text built from a finished run |
| `src/baseline/` | The run record and its file format (`mod.rs`), and comparing two runs (`compare.rs`) |
| `src/period.rs` | Detects events that repeat on a timer |
| `src/cpuclock.rs` | Per-core effective speed sampling (throttling) |
| `src/modules.rs` | Kernel address → driver, and the driver knowledge base |
| `src/procs.rs` | PID → process name, and what is known about the processes people do not recognize |
| `src/pdh.rs` | The performance-counter query both samplers use |
| `src/reg.rs` | Reading the registry |
| `src/state.rs` | Records and ring buffers shared between the trace thread and the analyzer |
| `src/bin/gui.rs` | Win32 window |
| `src/bin/cli.rs` | Console front end |

`Analyzer::summarize` in [`src/summary/mod.rs`](src/summary/mod.rs) is the report's table of
contents: one call per section (`stalls`, `storage`, `hardware`, `gpu`, `wording`, `details`), in
the order the report is built. The order matters and the doc comment above it says why.

By contributing you agree that your contribution is licensed under the [MIT license](LICENSE).
