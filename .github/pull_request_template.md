## What and why

## How it was tested

- [ ] `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `cargo test`
- [ ] Ran a real monitoring session as administrator and the summary still makes sense
- [ ] (if `src/probe.rs` changed) the real-time loop still exits when waits fail or return early
