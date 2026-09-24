//! How a run was set up: what the engine switched on, what Windows refused, and the thresholds.
//! None of it is the answer, so the report no longer opens with it. The few facts that change how
//! the answer reads (a trace that could not start, call stacks refused) become one-line notes in
//! RESULT; the explanations go to DETAILS under "HOW THIS RUN MEASURED".

use super::{wrap_to, DETAIL_WIDTH};

/// What became of the thread-switch trace.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum SwitchTrace {
    /// Traced for the whole run.
    Traced,
    /// Asked for, and Windows would not deliver it.
    Refused,
    /// Left off because the run used the lighter settings.
    LightMode,
    /// Turned off by hand (--no-switches).
    #[default]
    Off,
}

/// Decided by the engine before monitoring began.
#[derive(Clone, Debug, Default)]
pub struct Setup {
    /// Kernel modules (drivers) whose addresses are known, so stalls can be attributed.
    pub modules: usize,
    /// Windows would not reveal kernel module addresses.
    pub modules_hidden: bool,
    pub stall_ms: f64,
    pub sched_stall_ms: f64,
    /// Why the run used the lighter settings, if it did.
    pub light: Option<&'static str>,
    /// How often the latency probes check, ms.
    pub probe_ms: f64,
    /// CPU sampling was asked for and could not be enabled.
    pub sampling_failed: bool,
    pub switches: SwitchTrace,
    /// In plain words, which events carry a call stack ("disk requests and hard page faults");
    /// `None` when no stacks were recorded.
    pub stacks: Option<String>,
    /// Windows refused call stacks with this Win32 error.
    pub stack_error: Option<u32>,
    /// Why the graphics-kernel trace could not start, when it was asked for and did not.
    pub gpu_failed: Option<String>,
    /// Why the storage driver trace could not start, when it was asked for and did not.
    pub storage_failed: Option<String>,
    /// Why the latency probe process could not start.
    pub probe_failed: Option<String>,
    /// The probes ran without real-time priority.
    pub no_realtime: bool,
}

impl Setup {
    /// One short line each for what changes how the result reads. Light mode is not here: the
    /// overview already carries it, with its reason.
    pub fn notes(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.probe_failed.is_some() {
            out.push("The latency probes could not start, so only individual slow events are reported.".to_string());
        }
        if self.no_realtime {
            out.push("The probes could not get real-time priority; busy high-priority apps may show up as kernel-level stalls.".into());
        }
        if self.modules_hidden {
            out.push("Windows would not reveal kernel module addresses; drivers show as raw addresses.".into());
        }
        if self.sampling_failed {
            out.push("CPU sampling could not be enabled, so which program was running during a stall is not known.".into());
        }
        if self.switches == SwitchTrace::Refused {
            out.push("Windows would not trace thread switches; the report cannot say whether a stalled thread was woken.".into());
        }
        if let Some(rc) = self.stack_error {
            out.push(format!("Windows refused call stacks (error {rc}); the report cannot say which drivers were in the path."));
        }
        if self.gpu_failed.is_some() {
            out.push("The graphics trace could not start; frame timing and video memory pressure were not measured.".into());
        }
        if self.storage_failed.is_some() {
            out.push("The storage driver trace could not start; where slow disk time went was not measured.".into());
        }
        out
    }

    /// The "HOW THIS RUN MEASURED" block for DETAILS, wrapped to the DETAILS width.
    pub fn measured_lines(&self) -> Vec<String> {
        let mut out = vec![String::new(), "HOW THIS RUN MEASURED".to_string()];
        let mut item = |label: &str, text: String| wrap_to(&text, &format!("  {label:<12}"), DETAIL_WIDTH, &mut out);
        item(
            "Thresholds:",
            format!(
                "{} ms kernel-level / {} ms CPU-starvation (how late a real-time / normal thread may wake before it counts as a \
                 stall); {} kernel modules monitored.",
                self.stall_ms, self.sched_stall_ms, self.modules
            ),
        );
        if let Some(why) = self.light {
            let ms = self.probe_ms;
            item(
                "Light mode:",
                format!(
                    "on, because {why}. The probes check every {ms:.0} ms instead of 1 ms, so measuring costs this PC less. Stalls \
                     shorter than about {ms:.0} ms can be missed."
                ),
            );
        }
        match self.switches {
            SwitchTrace::Traced => item(
                "Switches:",
                "tracing every thread switch, which is what tells 'nothing woke it' apart from 'it was woken and not run'. It \
                 is the most expensive thing this tool records: tens of thousands of events a second on a busy PC. The block \
                 below reports what it actually cost; 'wtfis-cli --no-switches' turns it off."
                    .into(),
            ),
            SwitchTrace::LightMode => item(
                "Switches:",
                "not traced in light mode (it is the most expensive thing this tool records), so the report cannot say whether \
                 a stalled thread was never woken or was woken and not given a processor."
                    .into(),
            ),
            SwitchTrace::Refused => {
                item("Switches:", "Windows would not trace them; the report cannot say whether a stalled thread was woken.".into())
            }
            SwitchTrace::Off => item("Switches:", "not traced (--no-switches).".into()),
        }
        match (&self.stacks, self.stack_error) {
            (_, Some(rc)) => item(
                "Stacks:",
                format!("Windows refused call stacks (Win32 error {rc}); the report cannot say which drivers were in the path."),
            ),
            (Some(what), None) => {
                item("Stacks:", format!("recording which drivers {what} went through (driver names only, never function names)."))
            }
            (None, None) => item("Stacks:", "none recorded.".into()),
        }
        if let Some(e) = &self.gpu_failed {
            item("GPU trace:", format!("could not be started ({e}); frame timing and video memory pressure are off."));
        }
        if let Some(e) = &self.storage_failed {
            item("Storage:", format!("the storage driver trace could not be started ({e}); where slow disk time went is not measured."));
        }
        if let Some(e) = &self.probe_failed {
            item("Probes:", format!("could not start the latency probe process ({e}); only individual slow events are reported."));
        }
        out
    }

    /// What a normal run on a desktop PC looks like, for the demo reports.
    pub fn demo() -> Setup {
        Setup {
            modules: 243,
            stall_ms: 5.0,
            sched_stall_ms: 25.0,
            probe_ms: crate::overhead::PROBE_MS_NORMAL,
            switches: SwitchTrace::Traced,
            stacks: Some("disk requests and hard page faults".into()),
            ..Setup::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warnings_that_change_the_reading_become_notes_and_the_rest_goes_to_details() {
        let calm = Setup::demo();
        assert!(calm.notes().is_empty(), "a normal run has nothing to warn about: {:?}", calm.notes());
        let lines = calm.measured_lines();
        assert_eq!(lines[1], "HOW THIS RUN MEASURED");
        assert!(lines.iter().any(|l| l.contains("5 ms kernel-level / 25 ms CPU-starvation")), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("tracing every thread switch")), "{lines:?}");
        assert!(lines.iter().all(|l| l.chars().count() <= DETAIL_WIDTH), "{lines:?}");

        let rough = Setup {
            stack_error: Some(5),
            gpu_failed: Some("access denied".into()),
            light: Some("this PC has few processor cores"),
            probe_ms: 2.0,
            switches: SwitchTrace::LightMode,
            ..Setup::demo()
        };
        let notes = rough.notes();
        assert!(notes.iter().any(|n| n.starts_with("Windows refused call stacks")), "{notes:?}");
        assert!(notes.iter().any(|n| n.starts_with("The graphics trace could not start")), "{notes:?}");
        assert!(!notes.iter().any(|n| n.contains("Light mode")), "light mode is already in the overview: {notes:?}");
        // Compared as prose, whatever the wrapping.
        let lines = rough.measured_lines().join(" ").split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(lines.contains("Stalls shorter than about 2 ms can be missed"), "{lines}");
        assert!(lines.contains("not traced in light mode"), "{lines}");
        for n in notes {
            assert!(!n.contains("    "), "no runs of spaces: {n}");
        }

        // In the report: the notes right under the overview, the explanations in DETAILS.
        let mut summary = super::super::Summary::demo(super::super::Health::Warning);
        summary.set_setup(&rough);
        let result = summary.result_lines();
        let at = |needle: &str| result.iter().position(|l| l.contains(needle)).unwrap_or_else(|| panic!("{needle}: {result:?}"));
        assert!(at("Monitored:") < at("Note:             Windows refused call stacks"), "{result:?}");
        assert!(at("Windows refused call stacks") < at("COMPARED WITH YOUR LAST RUN"), "{result:?}");
        assert!(result.iter().all(|l| l.chars().count() <= super::super::WIDTH), "{result:?}");
        assert!(!result.iter().any(|l| l.contains("HOW THIS RUN MEASURED") || l.contains("tracing every")), "{result:?}");
        let details = summary.detail_lines();
        assert!(details.iter().any(|l| l == "HOW THIS RUN MEASURED"), "{details:?}");
    }
}
