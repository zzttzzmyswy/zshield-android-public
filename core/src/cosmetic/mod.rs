//! Cosmetic filtering: element hiding, scriptlets, and the streaming injection of both.
//!
//! For a document the network rules allowed, this module rewrites the HTML so the elements a list asked
//! to hide never render, and the scriptlets a list asked for run before the page's own code does.
//!
//! ```text
//! request ─▶ network rules (crate::http::decision) ─▶ allowed document?
//!                                                       │
//!                                       engine.url_cosmetic_resources(url)
//!                                                       │
//!                        ┌──────────────────────────────┼───────────────────────────┐
//!                        ▼                              ▼                           ▼
//!                hide_selectors                 injected_script            hidden_class_id_selectors
//!                (<style> after <head>)        (<script> after <head>)      (generic rules, from the
//!                                                                             class/id values the
//!                                                                             document contains)
//! ```
//!
//! Module map:
//!
//! - [`scan`] — where injected markup goes, and the incremental reader of `class`/`id` values;
//! - [`csp`] — extending the origin's `Content-Security-Policy` with a nonce so injected elements are
//!   allowed (and *not* doing it when `'unsafe-inline'` is what allows them);
//! - [`head`] — parsing and rewriting the response head (drop `Content-Length`/`Content-Encoding`, add
//!   chunked, extend `CSP`);
//! - [`inject`] — the streaming rewriter that ties the three together, including the verbatim give-up
//!   path;
//! - [`scriptlets`] — the uBlock Origin scriptlet bodies `##+js(...)` rules name, and the engine registry
//!   they are installed into;
//! - [`procedural`] — the rules CSS cannot express (`:has-text()`, `:upward()`, `:style()`, `:remove()`),
//!   and the one script that applies them;
//! - [`validate`] — telling a selector a browser will parse from one that would take its whole rule
//!   list down with it.
//!
//! # The one invariant
//!
//! **A document this code cannot rewrite is delivered exactly as the origin sent it.** Every decision
//! that can fail — is it HTML, is the coding one we decode, is there a place to insert — is made before
//! the first byte is written, and the origin's own bytes are held until then. A filter that silently
//! corrupts a page is worse than one that filters less.

pub mod chunked;
pub mod csp;
pub mod gzip;
pub mod head;
pub mod inject;
pub mod procedural;
pub mod scan;
pub mod scriptlets;
pub mod unhide;
pub mod validate;

pub use head::{Coding, OutFraming, ResponseHead};
pub use inject::{BodyInjector, CosmeticReport, Emitted, Plan, Rewriter};
pub use procedural::{Rule as ProceduralRule, Screen as ProceduralScreen, ScreenResult};
pub use validate::{SelectorValidator, Verdict};

/// Counters for cosmetic injection, exposed through `statsJson` (task card §5).
#[derive(Debug, Default)]
pub struct CosmeticStats {
    /// Documents that had at least one `<style>`/`<script>` inserted.
    pub injected: std::sync::atomic::AtomicU64,
    /// Documents that would have been injected into but were handed back unmodified.
    pub skipped: std::sync::atomic::AtomicU64,
    /// Documents that had the engine's scriptlet bundle inserted.
    pub scriptlets: std::sync::atomic::AtomicU64,
    /// Documents that carried a `<meta http-equiv="Content-Security-Policy">`, left alone.
    pub csp_meta: std::sync::atomic::AtomicU64,
    /// Selectors dropped because they could not be injected safely (`docs/JNI.md` §8.6).
    pub rejected_selectors: std::sync::atomic::AtomicU64,
    /// Documents that had at least one procedural rule applied (`docs/JNI.md` §"$popup").
    pub procedural: std::sync::atomic::AtomicU64,
    /// Procedural rules injected, summed over documents.
    pub procedural_rules: std::sync::atomic::AtomicU64,
    /// Procedural rules the selector screen refused, summed over documents.
    pub procedural_dropped: std::sync::atomic::AtomicU64,
}

/// A snapshot of [`CosmeticStats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CosmeticSnapshot {
    pub injected: u64,
    pub skipped: u64,
    pub scriptlets: u64,
    pub csp_meta: u64,
    pub rejected_selectors: u64,
    pub procedural: u64,
    pub procedural_rules: u64,
    pub procedural_dropped: u64,
}

impl CosmeticStats {
    pub fn snapshot(&self) -> CosmeticSnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        CosmeticSnapshot {
            injected: self.injected.load(Relaxed),
            skipped: self.skipped.load(Relaxed),
            scriptlets: self.scriptlets.load(Relaxed),
            csp_meta: self.csp_meta.load(Relaxed),
            rejected_selectors: self.rejected_selectors.load(Relaxed),
            procedural: self.procedural.load(Relaxed),
            procedural_rules: self.procedural_rules.load(Relaxed),
            procedural_dropped: self.procedural_dropped.load(Relaxed),
        }
    }

    /// Record the report of one finished rewriter.
    pub fn record(&self, report: CosmeticReport, injected_anyway: bool) {
        use std::sync::atomic::Ordering::Relaxed;
        if report.injected {
            self.injected.fetch_add(1, Relaxed);
        }
        if injected_anyway {
            self.scriptlets.fetch_add(1, Relaxed);
        }
        if report.csp_meta {
            self.csp_meta.fetch_add(1, Relaxed);
        }
        if report.rejected_selectors > 0 {
            self.rejected_selectors
                .fetch_add(report.rejected_selectors as u64, Relaxed);
        }
        if report.procedural {
            self.procedural.fetch_add(1, Relaxed);
            self.procedural_rules
                .fetch_add(report.procedural_rules as u64, Relaxed);
        }
        if !report.injected {
            self.skipped.fetch_add(1, Relaxed);
        }
    }
}

#[cfg(test)]
mod inject_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_counters_add_up() {
        let stats = CosmeticStats::default();
        stats.record(
            CosmeticReport {
                injected: true,
                scriptlet: true,
                procedural: true,
                procedural_rules: 2,
                specific: 2,
                generic: 3,
                csp_meta: false,
                rejected_selectors: 0,
            },
            true,
        );
        stats.record(CosmeticReport::default(), false);
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.injected, 1);
        assert_eq!(snapshot.skipped, 1);
        assert_eq!(snapshot.scriptlets, 1);
        assert_eq!(snapshot.csp_meta, 0);
        assert_eq!(snapshot.procedural, 1);
        assert_eq!(snapshot.procedural_rules, 2);
    }
}
