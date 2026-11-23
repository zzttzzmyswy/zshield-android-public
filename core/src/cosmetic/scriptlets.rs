//! The scriptlet resource set: the JavaScript bodies `##+js(...)` rules name.
//!
//! A `+js(set-constant, adsEnabled, false)` rule does not carry its own code: the engine looks the
//! name up in its **resource registry** and, when the name is unknown, silently produces no script at
//! all — the rule simply does nothing. So the bodies have to ship with the core, exactly like the
//! `$redirect` substitutes do ([`crate::http::resources`]).
//!
//! # Where the bodies come from
//!
//! uBlock Origin's scriptlets, generated into [`GENERATED`] by `scripts/gen-scriptlet-resources.mjs`
//! from the pinned revision recorded in `docs/THIRD_PARTY.md`. Generated rather than transcribed so
//! that the provenance is mechanical and a reviewer can regenerate the file and diff it.
//!
//! **License**: every uBO source file the generator reads is GPL-3.0-**or-later** ("either version 3
//! of the License, or (at your option) any later version"), not `-only` — the distinction is per file,
//! and the repository badge saying "GPLv3" does not settle it. That is what lets the combined work be
//! conveyed under this project's GPL-3.0-or-later.
//!
//! The per-file attribution lives in the generated file's **header comment** (one line per upstream
//! file, each with that file's own copyright) and in the packaged notices under
//! `app/src/main/assets/licenses/`. It is deliberately not a runtime table: a shipped binary carries
//! no comments, and per-entry fields would either bloat `.so` or be eliminated by the compiler — the
//! second case being the dangerous one, since the obligation would then rest on data nobody can
//! verify. The tests below assert the header is complete, and `NoticesTest` asserts the packaged copy
//! matches the header.
//!
//! Only **non-trusted** scriptlets are included: adblock-rust compiles every list with default
//! permissions, so a `trusted-` scriptlet could never be injected anyway (and they are the ones that
//! can write cookies and storage).
//!
//! # Cost
//!
//! The bodies are ~184 KiB of JavaScript in the binary. They are *not* parsed or compiled until a page
//! asks for one: [`ScriptletResources::init`] decodes the base64 bodies once at engine load, and the
//! engine concatenates only the dependencies of the scriptlets a document actually requested.
//!
//! Scriptlets run in the page's own world, injected as an inline `<script>` — which is why
//! [`crate::cosmetic::csp`] exists: a strict `script-src` would otherwise refuse them.

use std::sync::OnceLock;

use adblock::resources::{MimeType, Resource, ResourceType};

// The generated resource set (the `Generated` type and the `GENERATED` table), from
// `scripts/gen-scriptlet-resources.mjs`.
include!("scriptlet-resources.rs");

/// Every scriptlet resource, as the engine's registry wants them.
///
/// Built once per process and handed to every engine (`HttpFilter::new`/`replace`), because the engine
/// copies what it needs and the bodies never change while the app runs.
pub fn resources() -> &'static [Resource] {
    static RESOURCES: OnceLock<Vec<Resource>> = OnceLock::new();
    RESOURCES.get_or_init(|| {
        GENERATED
            .iter()
            .map(|generated| {
                use base64::Engine as _;
                Resource {
                    name: generated.name.to_string(),
                    aliases: generated.aliases.iter().map(|name| name.to_string()).collect(),
                    kind: ResourceType::Mime(MimeType::ApplicationJavascript),
                    // `Resource::content` is base64, which is what `ResourceStorage` decodes back to
                    // text; encoding here keeps the generated data plain source a reviewer can read.
                    content: base64::engine::general_purpose::STANDARD.encode(generated.code),
                    dependencies: generated
                        .dependencies
                        .iter()
                        .map(|name| name.to_string())
                        .collect(),
                    permission: Default::default(),
                }
            })
            .collect()
    })
}

/// How many scriptlets the core can inject, for the debug/log surface and the delivery note.
pub fn count() -> usize {
    GENERATED.iter().filter(|entry| entry.name.ends_with(".js")).count()
}

/// Every canonical scriptlet name, sorted. Used by the tests and the rule-coverage report.
pub fn names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = GENERATED.iter().map(|entry| entry.name).collect();
    names.sort_unstable();
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn every_resource_has_a_unique_name_and_unique_aliases() {
        // `ResourceStorage::add_resource` refuses a duplicate and the engine then silently drops the
        // resource, which would turn a rule into a no-op. The generator checks this too; this catches
        // a hand-edited regeneration.
        let mut seen: HashSet<&str> = HashSet::new();
        for entry in GENERATED {
            assert!(seen.insert(entry.name), "duplicate name {}", entry.name);
            for alias in entry.aliases {
                assert!(seen.insert(alias), "duplicate alias {alias}");
            }
        }
    }

    /// The generated file's header, which is where the upstream attribution now lives.
    ///
    /// `include!` pulls in the file as source, so its comments are not reachable from Rust; the test
    /// reads the file it was built from instead. That is the point: the record has to exist in the
    /// *distributed source*, not in a table the compiler may drop.
    fn generated_header() -> &'static str {
        const SOURCE: &str = include_str!("scriptlet-resources.rs");
        SOURCE.split("struct Generated").next().expect("header")
    }

    #[test]
    fn the_header_keeps_each_upstream_files_own_copyright() {
        // GPL-3.0 §5 requires the notices to travel with the moved code, and the bodies come from
        // files whose headers differ (2019 / 2022 / 2025 / 2026) — one blanket line would misreport
        // the newer ones. The generator emits one line per upstream file; this guards a hand edit.
        let header = generated_header();
        let mut origins = 0;
        for line in header.lines() {
            let Some(rest) = line.strip_prefix("//   src/js/") else { continue };
            assert!(
                !rest.is_empty(),
                "an attribution line has no upstream path: {line:?}"
            );
            assert!(
                rest.contains("Copyright (C) ") && rest.contains("Raymond Hill"),
                "an attribution line lost its upstream notice: {line:?}"
            );
            origins += 1;
        }
        assert_eq!(
            origins, 28,
            "expected one attribution line per upstream file, found {origins}"
        );
        for year in ["2019", "2022", "2025", "2026"] {
            assert!(
                header.contains(&format!("Copyright (C) {year}-present Raymond Hill")),
                "the {year} header (urlskip.js / jsonpath.js / prevent-navigation.js) was flattened"
            );
        }
        // The header must also state the licensing conclusion, not just the copyright lines.
        assert!(
            header.contains("GPL-3.0-or-later"),
            "the header does not state that these bodies are conveyed under GPL-3.0-or-later"
        );
        assert!(
            header.contains("1.76.0") && header.contains("aa9236cb351e369cbb68113dbe8175b87f3cd134"),
            "the header lost the pinned upstream revision"
        );
    }

    #[test]
    fn every_dependency_exists_and_is_not_a_scriptlet() {
        let names: HashSet<&str> = GENERATED.iter().map(|entry| entry.name).collect();
        for entry in GENERATED {
            for dependency in entry.dependencies {
                assert!(
                    names.contains(dependency),
                    "{} depends on missing {dependency}",
                    entry.name
                );
            }
        }
        // Helpers are the entries that a rule cannot name: no `.js` suffix.
        let helpers: Vec<&str> = GENERATED
            .iter()
            .filter(|entry| !entry.name.ends_with(".js"))
            .map(|entry| entry.name)
            .collect();
        assert!(!helpers.is_empty(), "the scriptlets must have their helper functions");
        for helper in helpers {
            assert!(helper.ends_with(".fn"), "unexpected helper name {helper}");
        }
    }

    #[test]
    fn every_scriptlet_declares_a_function_the_engine_can_call() {
        // adblock-rust extracts the name with `^function\s+([^\(\)\{\}\s]+)\s*\(`, and a resource that
        // does not match is treated as an old-style `{{1}}` template instead — which would inject the
        // *definition* and never call it.
        for entry in GENERATED.iter().filter(|entry| entry.name.ends_with(".js")) {
            let code = entry.code.trim_start();
            assert!(
                code.starts_with("function ") || code.starts_with("async function "),
                "{} must be a function declaration so the engine can find its name: {}",
                entry.name,
                &code[..code.len().min(60)]
            );
        }
    }

    #[test]
    fn the_registry_builds_and_the_common_scriptlets_are_present() {
        let resources = resources();
        assert_eq!(resources.len(), GENERATED.len());
        let named: HashSet<&str> = resources.iter().map(|r| r.name.as_str()).collect();
        // The names that carry the overwhelming majority of `##+js(...)` rules in the shipped lists
        // (scripts/report-scriptlet-coverage.mjs produces the ranking).
        for required in [
            "set-constant.js",
            "set-cookie.js",
            "abort-current-script.js",
            "abort-on-property-read.js",
            "prevent-setTimeout.js",
            "prevent-addEventListener.js",
            "prevent-window-open.js",
            "prevent-fetch.js",
            "set-local-storage-item.js",
            "adjust-setInterval.js",
            "abort-on-property-write.js",
            "remove-class.js",
            "remove-attr.js",
            "json-prune.js",
            "prevent-xhr.js",
        ] {
            assert!(named.contains(required), "missing scriptlet {required}");
        }
        assert!(count() >= 60, "only {} scriptlets", count());
    }

    #[test]
    fn the_shipped_aliases_resolve_to_their_canonical_name() {
        let resources = resources();
        let find = |name: &str| resources.iter().find(|r| r.name == name).expect(name);
        // uBO's short spellings, which is what the lists actually write.
        assert!(find("abort-current-script.js").aliases.iter().any(|a| a == "acs.js"));
        assert!(find("abort-on-property-read.js").aliases.iter().any(|a| a == "aopr.js"));
        assert!(find("set-constant.js").aliases.iter().any(|a| a == "set.js"));
        assert!(find("remove-attr.js").aliases.iter().any(|a| a == "ra.js"));
    }

    #[test]
    fn a_scriptlet_ends_up_in_the_injected_script_the_engine_builds() {
        // The whole point of the registry: a rule that names a scriptlet must produce callable code.
        let mut set = adblock::lists::FilterSet::new(false);
        set.add_filter_list(
            "example.com##+js(set-constant, adblockDetected, false)".to_string(),
            adblock::lists::ParseOptions::default(),
        );
        let mut engine = adblock::Engine::new_with_filter_set(set);
        engine.use_resources(resources().to_vec());
        let cosmetic = engine.url_cosmetic_resources("https://example.com/page");
        assert!(
            !cosmetic.injected_script.is_empty(),
            "the rule must produce a script; the registry was not used"
        );
        // `set-constant` is invoked through its function name, with the rule's arguments.
        assert!(
            cosmetic.injected_script.contains("setConstant(\"adblockDetected\""),
            "the script must call the scriptlet: {}",
            &cosmetic.injected_script[..cosmetic.injected_script.len().min(200)]
        );
        assert!(
            cosmetic.injected_script.contains("function setConstantFn"),
            "the dependency definition must be included"
        );
    }

    #[test]
    fn an_empty_set_of_resources_means_no_script_is_produced() {
        // The failure mode this module exists to prevent, asserted so a regression is visible: without
        // the registry adblock-rust silently drops the injection.
        let mut set = adblock::lists::FilterSet::new(false);
        set.add_filter_list(
            "example.com##+js(set-constant, adblockDetected, false)".to_string(),
            adblock::lists::ParseOptions::default(),
        );
        let engine = adblock::Engine::new_with_filter_set(set);
        let cosmetic = engine.url_cosmetic_resources("https://example.com/page");
        assert!(cosmetic.injected_script.is_empty());
    }
}
