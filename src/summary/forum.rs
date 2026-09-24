//! The short summary: small enough to paste into one Discord message or a forum post, where the
//! full report (17-25 KB) does not fit. It is built only from what the report already says - the
//! verdict, the overview, the top findings and the comparison - so it can never disagree with it.

use super::{wrap_to, Health, Summary};

/// The hard cap, in characters, INCLUDING the ``` code fence around the text.
///
/// Discord, the tightest place people paste this: "The character cap per message is 2000. Messages
/// with more than 2000 characters will be converted into a text file. You can raise the character
/// cap limit to 4000 when you subscribe to Discord Nitro."
/// https://support.discord.com/hc/en-us/articles/360034632292-Sending-Messages
/// (Reddit comments take 10,000: `comment=VMarkdownLength(['text', 'comment'], max_length=10000)` in
/// Reddit's archived source, https://github.com/reddit-archive/reddit/blob/master/r2/r2/controllers/api.py)
///
/// Counted in UTF-16 code units with CRLF line breaks, which is never less than a count of
/// characters or of LF-only lines, whichever way a site counts.
pub const SUMMARY_MAX: usize = 2000;

/// Code blocks on a phone are narrow; 80 columns reads everywhere.
const SUMMARY_WIDTH: usize = 80;
/// At most this many findings are listed; the rest are counted.
const SUMMARY_FINDINGS: usize = 4;
/// A single sentence longer than this is left out rather than cut.
const LONGEST_SENTENCE: usize = 320;
/// Titles and hardware names longer than this are shortened at a word (they are names, not sentences).
const LONGEST_NAME: usize = 90;

/// The hardware a helper asks about first: models only. Never a user name, a computer name, a path or
/// a serial number.
#[derive(Clone, Debug, Default)]
pub struct Machine {
    /// "AMD Ryzen 7 5800X 8-Core Processor", as the processor names itself.
    pub cpu: String,
    pub logical_cpus: u32,
    pub ram_gb: f64,
    /// Graphics adapters by name, as the graphics kernel reports them.
    pub gpus: Vec<String>,
    /// "build 26100 (24H2)".
    pub windows: String,
}

/// How much of the report goes in; `LADDER` lists these from richest to leanest.
#[derive(Clone, Copy)]
struct Plan {
    /// Findings listed.
    findings: usize,
    /// ...of which this many (the first ones) show their evidence clause...
    evidence: usize,
    /// ...and this many their first "what to try" sentence.
    advice: usize,
    notes: bool,
    comparison: bool,
    hardware: bool,
}

/// Least important goes first: the lesser findings' advice, then the lesser findings, then the
/// notes, the comparison, the top finding's own advice and evidence, and last the hardware.
const LADDER: [Plan; 13] = [
    Plan { findings: 4, evidence: 4, advice: 4, notes: true, comparison: true, hardware: true },
    Plan { findings: 4, evidence: 4, advice: 1, notes: true, comparison: true, hardware: true },
    Plan { findings: 3, evidence: 3, advice: 1, notes: true, comparison: true, hardware: true },
    Plan { findings: 2, evidence: 2, advice: 1, notes: true, comparison: true, hardware: true },
    Plan { findings: 2, evidence: 1, advice: 1, notes: true, comparison: true, hardware: true },
    Plan { findings: 1, evidence: 1, advice: 1, notes: true, comparison: true, hardware: true },
    Plan { findings: 1, evidence: 1, advice: 1, notes: false, comparison: true, hardware: true },
    Plan { findings: 1, evidence: 1, advice: 1, notes: false, comparison: false, hardware: true },
    Plan { findings: 1, evidence: 1, advice: 0, notes: false, comparison: false, hardware: true },
    Plan { findings: 1, evidence: 0, advice: 0, notes: false, comparison: false, hardware: true },
    Plan { findings: 0, evidence: 0, advice: 0, notes: false, comparison: false, hardware: true },
    Plan { findings: 0, evidence: 0, advice: 0, notes: false, comparison: false, hardware: false },
    // Nothing left to drop but the overview's extra lines; see `render`.
    Plan { findings: 0, evidence: 0, advice: 0, notes: false, comparison: false, hardware: false },
];

/// The length that counts against `SUMMARY_MAX`.
pub fn summary_len(text: &str) -> usize {
    text.encode_utf16().count()
}

/// The first sentence of `text`: up to the first '.', '!' or '?' that is followed by a space and a
/// capital letter or a digit, and is not the end of a common abbreviation. Never cut elsewhere;
/// `None` when that sentence is too long to quote whole.
fn first_sentence(text: &str) -> Option<String> {
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let chars: Vec<char> = text.chars().collect();
    let mut end = chars.len();
    for i in 0..chars.len() {
        if !matches!(chars[i], '.' | '!' | '?') || chars.get(i + 1) != Some(&' ') {
            continue;
        }
        let next = chars.get(i + 2).copied().unwrap_or(' ');
        if !(next.is_uppercase() || next.is_ascii_digit()) {
            continue;
        }
        let word: String = chars[..=i].iter().rev().take_while(|c| **c != ' ').collect::<Vec<_>>().into_iter().rev().collect();
        if ["e.g.", "i.e.", "etc.", "vs.", "approx.", "No."].contains(&word.as_str()) {
            continue;
        }
        end = i + 1;
        break;
    }
    let sentence: String = chars[..end].iter().collect();
    (!sentence.is_empty() && sentence.chars().count() <= LONGEST_SENTENCE).then_some(sentence)
}

/// A name shortened at a word, marked with "...", when it is longer than `LONGEST_NAME`.
fn short_name(name: &str) -> String {
    let name = name.split_whitespace().collect::<Vec<_>>().join(" ");
    if name.chars().count() <= LONGEST_NAME {
        return name;
    }
    let mut out = String::new();
    for word in name.split(' ') {
        if out.chars().count() + 1 + word.chars().count() > LONGEST_NAME - 3 {
            break;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    if out.is_empty() {
        out = name.chars().take(LONGEST_NAME - 3).collect();
    }
    out + "..."
}

/// "Stalls detected:  12 whole-PC freezes" -> "Stalls detected: 12 whole-PC freezes".
fn tidy(line: &str) -> String {
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

impl Summary {
    /// The verdict's tag, as the RESULT block prints it.
    pub(super) fn tag(&self) -> &'static str {
        match self.health {
            Health::Problem => "PROBLEM FOUND",
            Health::Warning => "SUSPECT FOUND",
            Health::Ok => "ALL CLEAR",
            Health::NoData => "NO DATA",
        }
    }

    /// The short summary, fenced as a code block (monospace keeps the layout), CRLF line breaks,
    /// never longer than `SUMMARY_MAX`. `report_path` is only ever shown by its file name.
    pub fn forum_summary(&self, report_path: Option<&str>) -> String {
        let name = report_path
            .and_then(|p| std::path::Path::new(p).file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .filter(|n| !n.is_empty());
        let mut last = String::new();
        for (step, plan) in LADDER.iter().enumerate() {
            last = self.render(*plan, step == LADDER.len() - 1, name.as_deref());
            if summary_len(&last) <= SUMMARY_MAX {
                return last;
            }
        }
        // Unreachable with the lengths capped above (the leanest plan is a few hundred
        // characters); kept so that the promise holds whatever a future caller feeds in.
        let mut cut: Vec<&str> = last.split("\r\n").collect();
        while cut.len() > 3 && summary_len(&cut.join("\r\n")) > SUMMARY_MAX {
            cut.remove(cut.len() - 3);
        }
        cut.join("\r\n")
    }

    fn render(&self, plan: Plan, bare: bool, report_name: Option<&str>) -> String {
        let mut out: Vec<String> = Vec::new();
        let wrap = |text: &str, first: &str, out: &mut Vec<String>| wrap_to(text, first, SUMMARY_WIDTH, out);
        let mut dropped = false;

        // One line whatever its length, so the verdict reads as one; a code block wraps it if it must.
        out.push(format!("WTFIsStalling {} - {}: {}", env!("CARGO_PKG_VERSION"), self.tag(), short_name(&self.headline)));
        let m = &self.machine;
        if plan.hardware {
            if !m.cpu.is_empty() {
                wrap(&format!("CPU: {} ({} logical CPUs), {:.1} GB RAM", short_name(&m.cpu), m.logical_cpus, m.ram_gb), "", &mut out);
            }
            // Two adapters say everything a helper needs (the card and the integrated graphics).
            let gpus: Vec<String> = m.gpus.iter().take(2).map(|g| short_name(g)).collect();
            let mut parts = Vec::new();
            if !gpus.is_empty() {
                parts.push(format!("GPU: {}", gpus.join(" + ")));
            }
            if !m.windows.is_empty() {
                parts.push(format!("Windows {}", m.windows));
            }
            if !parts.is_empty() {
                wrap(&parts.join(" | "), "", &mut out);
            }
        } else if !m.cpu.is_empty() || !m.gpus.is_empty() || !m.windows.is_empty() {
            dropped = true;
        }

        // The overview, minus the worst wake-up delays (a number for the full report). The run
        // length and the stall counts always stay.
        let overview: Vec<String> = self.overview.iter().filter(|l| !l.starts_with("Worst wake-up:")).map(|l| tidy(l)).collect();
        let (counts, extra) = overview.split_at(overview.len().min(2));
        for line in counts {
            wrap(line, "", &mut out);
        }
        for line in extra {
            if bare {
                dropped = true;
                break;
            }
            wrap(line, "", &mut out);
        }
        if plan.notes {
            for note in &self.notes {
                wrap(note, "Note: ", &mut out);
            }
        } else if !self.notes.is_empty() {
            dropped = true;
        }

        let shown = self.findings.len().min(SUMMARY_FINDINGS).min(plan.findings);
        if shown == 0 && matches!(self.health, Health::Ok | Health::NoData) {
            if let Some(s) = first_sentence(&self.subline) {
                out.push(String::new());
                wrap(&s, "", &mut out);
            }
        }
        for (i, f) in self.findings.iter().take(shown).enumerate() {
            out.push(String::new());
            wrap(&format!("[{}] {}", f.severity.label(), short_name(&f.title)), &format!("{}. ", i + 1), &mut out);
            if i < plan.evidence {
                if let Some(s) = f.evidence.first().and_then(|e| first_sentence(e)) {
                    wrap(&s, "   ", &mut out);
                }
            } else if !f.evidence.is_empty() {
                dropped = true;
            }
            if i < plan.advice {
                if let Some(s) = first_sentence(&f.advice) {
                    wrap(&s, "   Try: ", &mut out);
                }
            } else if !f.advice.trim().is_empty() {
                dropped = true;
            }
        }

        if self.comparison.len() >= 2 {
            if plan.comparison {
                out.push(String::new());
                wrap(&format!("Compared with your last run: {}", self.comparison[1]), "", &mut out);
            } else {
                dropped = true;
            }
        }

        out.push(String::new());
        let more = self.findings.len() - shown;
        if more > 0 {
            out.push(format!("({more} more finding{} in the full report)", crate::util::plural(more as u64)));
        } else if dropped {
            out.push("(more detail in the full report)".into());
        }
        out.push(match report_name {
            Some(name) => format!("Full report: {name} (attached, or ask me for it)"),
            None => "Full report: ask me for it (it is too long for one message)".to_string(),
        });

        // Nothing inside may close the fence early.
        let body: Vec<String> = out.iter().map(|l| l.replace("```", "'''")).collect();
        format!("```\r\n{}\r\n```", body.join("\r\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Finding, Group, Severity};
    use super::*;

    fn long_finding(i: usize) -> Finding {
        let words = |w: &str, n: usize| vec![w; n].join(" ");
        Finding {
            key: format!("driver long{i}.sys"),
            group: Group::Interruptions,
            severity: Severity::High,
            title: format!("long{i}.sys  -  {}", words("Extraordinarily-long-device-name", 12)),
            evidence: vec![format!("{}. {}.", words("evidence", 30), words("More", 200)), "second".into()],
            advice: format!("{}. {}", words("advice", 45), words("Then", 300)),
            advice_items: Vec::new(),
            metrics: Vec::new(),
            impact: 0,
        }
    }

    #[test]
    fn the_demo_summaries_fit_one_discord_message_fence_included() {
        for health in [Health::Problem, Health::Warning, Health::Ok] {
            let s = Summary::demo(health).forum_summary(Some("WTFIsStalling-20260924-101500.txt"));
            assert!(summary_len(&s) <= SUMMARY_MAX, "{health:?}: {} > {SUMMARY_MAX}\n{s}", summary_len(&s));
            assert!(s.starts_with("```\r\n") && s.ends_with("\r\n```"), "fenced: {s}");
            assert_eq!(s.matches("```").count(), 2, "exactly one code block: {s}");
            assert!(!s.replace("\r\n", "").contains('\n'), "CRLF only");
            let lines: Vec<&str> = s.split("\r\n").collect();
            assert!(lines[1].starts_with(&format!("WTFIsStalling {} - ", env!("CARGO_PKG_VERSION"))), "{s}");
            // All but the verdict line, which stays one line whatever its length.
            assert!(lines.iter().skip(2).all(|l| l.chars().count() <= SUMMARY_WIDTH), "{s}");
            assert!(lines.iter().all(|l| !l.trim().contains("    ")), "no runs of spaces mid-line: {s}");
            assert_eq!(lines[lines.len() - 2], "Full report: WTFIsStalling-20260924-101500.txt (attached, or ask me for it)");
        }
        let problem = Summary::demo(Health::Problem).forum_summary(None);
        assert!(problem.contains("PROBLEM FOUND: The whole PC stopped responding, 12 times"), "{problem}");
        assert!(problem.contains("CPU: ") && problem.contains("GPU: ") && problem.contains("Windows build"), "{problem}");
        assert!(problem.contains("Monitored: 59:21\r\nStalls detected: 12 whole-PC freezes"), "{problem}");
        assert!(problem.contains("1. [HIGH] The whole PC stopped responding"), "{problem}");
        assert!(problem.contains("Compared with your last run: "), "{problem}");
        assert!(problem.contains("(1 more finding in the full report)"), "five findings, four listed: {problem}");
        assert!(problem.contains("Full report: ask me for it"), "{problem}");
    }

    #[test]
    fn a_worst_case_degrades_by_dropping_the_least_important_parts_and_never_cuts_a_sentence() {
        let mut s = Summary::demo(Health::Problem);
        s.findings = (0..40).map(long_finding).collect();
        s.headline = s.findings[0].title.clone();
        s.notes = (0..6).map(|i| format!("Note number {i}: {}", "the trace could not start ".repeat(4))).collect();
        s.machine = Machine {
            cpu: "Some-Vendor(R) Hyper-Mega-Core(TM) Processor ".repeat(6),
            logical_cpus: 256,
            ram_gb: 2048.0,
            gpus: vec!["A Graphics Adapter With A Very Long Marketing Name ".repeat(4); 5],
            windows: "build 26200 (25H2)".into(),
        };
        let text = s.forum_summary(Some("C:\\Users\\JohnSmith\\Desktop\\WTFIsStalling-20260924-101500.txt"));
        assert!(summary_len(&text) <= SUMMARY_MAX, "{} chars\n{text}", summary_len(&text));
        assert!(text.contains("1. [HIGH] long0.sys"), "the top finding survives: {text}");
        assert!(text.contains("more findings in the full report)"), "{text}");
        // Only whole sentences: every evidence or advice line quoted ends a sentence.
        assert!(text.contains("Try: advice advice") && !text.contains("Then"), "the advice up to its first sentence: {text}");
        assert!(text.contains("evidence evidence") && !text.contains("More"), "{text}");
        let lines: Vec<&str> = text.split("\r\n").collect();
        assert!(lines.iter().skip(2).all(|l| l.chars().count() <= SUMMARY_WIDTH), "{text}");
        assert!(!text.contains("JohnSmith") && !text.contains("C:\\"), "the report by its file name only: {text}");
    }

    #[test]
    fn a_path_in_a_finding_reaches_the_summary_only_as_the_report_already_shows_it() {
        let shown = crate::files::public_path("C:\\Users\\JohnSmith\\Documents\\TaxReturn_JohnSmith.pdf");
        assert!(!shown.contains("JohnSmith"), "{shown}");
        let mut s = Summary::demo(Health::Warning);
        s.findings[0].evidence[0] = format!("Waited 900 ms on {shown} while it was read.");
        s.headline = s.findings[0].title.clone();
        let text = s.forum_summary(Some("D:\\Reports\\JohnSmith\\WTFIsStalling-x.txt"));
        assert!(text.contains(&shown), "{text}");
        assert!(!text.contains("JohnSmith") && !text.contains("Reports\\"), "{text}");
        assert!(text.contains("Full report: WTFIsStalling-x.txt"), "{text}");
    }

    #[test]
    fn first_sentences_stop_at_a_sentence_and_nowhere_else() {
        assert_eq!(
            first_sentence("Blamed for 14 stalls (worst 11.80 ms). Update it.").as_deref(),
            Some("Blamed for 14 stalls (worst 11.80 ms).")
        );
        assert_eq!(first_sentence("Close tools, e.g. HWiNFO. Then run again.").as_deref(), Some("Close tools, e.g. HWiNFO."));
        assert_eq!(first_sentence("One sentence without an end").as_deref(), Some("One sentence without an end"));
        assert_eq!(first_sentence("Wait 2 s. 3 retries followed.").as_deref(), Some("Wait 2 s."));
        assert_eq!(first_sentence(&"word ".repeat(100)), None, "too long to quote whole");
        assert_eq!(first_sentence("   "), None);
    }
}
