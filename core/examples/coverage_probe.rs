//! Host-side rule-coverage probe (M5a).
//!
//! Usage:
//!   cargo run --release --example coverage_probe -- <catalog.json> <list-dir> <output.json>
//!
//! Answers one question per filter-list line: **what does the shipped core actually do with it?**
//! The classification is not a guess about syntax — it is the verdict of the two parsers the app
//! itself runs (`zshield::dns::filter` for the DNS layer, `adblock::lists` for the engine) plus this
//! core's own registries (scriptlet resources, `$removeheader`). A rule that adblock-rust parses but
//! this core never consumes is therefore reported as **ineffective**, not as supported — that
//! distinction is the whole point of the report, because several syntax families parse cleanly and
//! then do nothing (`procedural` actions, scriptlet names that ship no body).
//!
//! # Categories are a partition
//!
//! Every line that is not blank, not a `!`/`[Header]` comment and not a `# `-style comment lands in
//! exactly one of nine buckets, so the sum equals the list's valid-rule line count. The acceptance
//! criterion for the report is that reconciliation, and the probe asserts it per list.
//!
//! | bucket | meaning |
//! |---|---|
//! | `dns` | the DNS layer matches it (`||a.com^`, hosts entries) — works with no HTTPS filtering |
//! | `network` | the adblock engine matches it and this core applies the result — works |
//! | `elemhide` | `##` / `#@#` element hiding with a plain CSS selector — works |
//! | `scriptlet` | `##+js(name, ...)`; effective only when the body ships (tracked as a sub-count) |
//! | `procedural` | `:has-text()`-family rules this build still cannot apply (empty since M5b) |
//! | `proceduralApplied` | `:style()`, `:remove()`, `:remove-attr()`, `:has-text()`, … — applied by the injected runtime |
//! | `extras` | `$popup`, `$denyallow`, `$removeparam=<regex>` — evaluated by this core (`https::extras`) |
//! | `adguardModifier` | a `$modifier` the pinned engine's parser rejects outright |
//! | `parseFailure` | rejected for any other reason |
//!
//! # Why the modifier verdicts are probed, not hard-coded
//!
//! Which `$modifier` names the engine knows is a property of the pinned `adblock` crate, and a table
//! copied into this file would silently rot on an upgrade. Instead the probe feeds `||probe.example^$<name>`
//! and `||probe.example^$<name>=x` through the same parser and records the verdict: a name the parser
//! rejects is an unimplemented modifier, evidence included. `$removeheader` is excluded from that
//! inference because this core implements it outside the engine (`https::modifiers`).

// The report is a JSON contract with `docs/coverage.json` and the scripts that consume it, so its
// field names are camelCase on purpose (matching every other JSON surface in this core) rather than
// the snake_case Rust would prefer.
#![allow(non_snake_case)]

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use adblock::lists::{parse_filter, ParseOptions, ParsedLine};
use serde::Serialize;

/// The seven buckets. `as_str` is the JSON key, so the names are part of the report's contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Bucket {
    Dns,
    Network,
    ElemHide,
    Scriptlet,
    Procedural,
    /// A procedural rule this core now applies (`:style()`, `:remove()`, `:has-text()`, …) — M5b §2.
    ProceduralApplied,
    /// A `$modifier` the pinned engine rejects but this core evaluates itself — M5b §3/§5/§6.
    Extras,
    AdguardModifier,
    ParseFailure,
}

impl Bucket {
    const ALL: [Bucket; 9] = [
        Bucket::Dns,
        Bucket::Network,
        Bucket::ElemHide,
        Bucket::Scriptlet,
        Bucket::Procedural,
        Bucket::ProceduralApplied,
        Bucket::Extras,
        Bucket::AdguardModifier,
        Bucket::ParseFailure,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Bucket::Dns => "dns",
            Bucket::Network => "network",
            Bucket::ElemHide => "elemhide",
            Bucket::Scriptlet => "scriptlet",
            Bucket::Procedural => "procedural",
            Bucket::ProceduralApplied => "proceduralApplied",
            Bucket::Extras => "extras",
            Bucket::AdguardModifier => "adguardModifier",
            Bucket::ParseFailure => "parseFailure",
        }
    }
}

/// Per-list, per-bucket counters plus the sub-splits the report quotes.
#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ListCoverage {
    id: String,
    /// Bytes read from disk.
    bytes: u64,
    /// Every line, comments and blanks included.
    lines: u64,
    /// Lines that carry a rule (everything the categories partition).
    validRules: u64,
    counts: BTreeMap<String, u64>,
    /// Element-hiding split: a rule with a hostname restriction vs. a purely generic one.
    elemhideSpecific: u64,
    elemhideGeneric: u64,
    elemhideException: u64,
    /// `##+js` split: bodies this core ships vs. names it has no body for.
    scriptletShipped: u64,
    scriptletMissing: u64,
    /// `*.domain` (OISD/HaGeZi DNS lists): a whole-domain block the DNS layer *could* do but only
    /// matches when it reaches the engine, so it costs a decrypt or a per-connection SNI check
    /// instead of a DNS answer. Counted so the report can quantify that traffic cost.
    wildcardHostRules: u64,
    /// How much of the parsed-but-ineffective set could be recovered by implementing the feature.
    proceduralByOperator: BTreeMap<String, u64>,
}

/// One aggregated shape of ineffective rule, for the "what to implement next" ranking.
#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Shape {
    /// Normalized syntax form, e.g. `##…:has-text(…)` or `||…^$replace=…`.
    shape: String,
    count: u64,
    /// Which bucket it came from.
    bucket: String,
    /// The lists it occurs in, with this shape's count in each.
    lists: BTreeMap<String, u64>,
    /// One real rule, so a reader can recognise the form.
    example: String,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct Report {
    /// When the lists were fetched, from the fetch manifest. Empty when the manifest is absent.
    listsFetchedAt: String,
    engine: String,
    listCount: usize,
    totals: BTreeMap<String, u64>,
    elemhideSpecific: u64,
    elemhideGeneric: u64,
    elemhideException: u64,
    scriptletShipped: u64,
    scriptletMissing: u64,
    /// `*.domain` lines: a whole-domain block the network layer matches, which the DNS layer could
    /// answer far more cheaply.
    wildcardHostRules: u64,
    /// Buckets that change the page today.
    effectiveRules: u64,
    /// Buckets that parse but produce no action.
    ineffectiveRules: u64,
    /// Every `$option` whose real list line starts parsing once it is removed — the option is a name
    /// this build's engine does not know.
    unimplementedModifiers: Vec<ModifierVerdict>,
    lists: Vec<ListCoverage>,
    topIneffectiveShapes: Vec<Shape>,
    /// Set when a list file named by the catalog was missing or unreadable.
    missingLists: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ModifierVerdict {
    option: String,
    /// The line that was fed to the parser.
    probe: String,
    accepted: bool,
    /// The parser's own message when it rejected the probe.
    error: String,
}

fn main() {
    let mut args = std::env::args().skip(1);
    let catalog = args.next().unwrap_or_else(|| {
        eprintln!("usage: coverage_probe <catalog.json> <list-dir> <output.json>");
        std::process::exit(2);
    });
    let list_dir = args.next().unwrap_or_else(|| {
        eprintln!("usage: coverage_probe <catalog.json> <list-dir> <output.json>");
        std::process::exit(2);
    });
    let output = args.next().unwrap_or_else(|| {
        eprintln!("usage: coverage_probe <catalog.json> <list-dir> <output.json>");
        std::process::exit(2);
    });

    let report = analyse(Path::new(&catalog), Path::new(&list_dir));
    let json = serde_json::to_string_pretty(&report).expect("serialize");
    std::fs::write(&output, json + "\n").expect("write report");
    print_summary(&report);
}

/// The catalog entry the probe needs: the id, which is also the file name of the downloaded list.
#[derive(Debug, serde::Deserialize)]
struct Catalog {
    lists: Vec<CatalogEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct CatalogEntry {
    id: String,
}

fn analyse(catalog_path: &Path, list_dir: &Path) -> Report {
    let catalog: Catalog = serde_json::from_str(
        &std::fs::read_to_string(catalog_path).expect("read catalog.json"),
    )
    .expect("parse catalog.json");

    let scriptlets = ShippedScriptlets::load();
    let mut report = Report {
        engine: format!("adblock {}", env!("CARGO_PKG_VERSION")),
        listCount: catalog.lists.len(),
        ..Report::default()
    };
    report.listsFetchedAt = read_manifest_timestamp(list_dir);

    // One entry per `$option` this build's engine refuses, filled from the *real* list lines that
    // tripped it — the failing line and the line that parses once the option is removed are the
    // evidence, which is stronger than any synthetic probe.
    let mut modifier_evidence: HashMap<String, ModifierVerdict> = HashMap::new();
    let mut shapes: HashMap<(String, &'static str), Shape> = HashMap::new();

    for entry in &catalog.lists {
        let path = list_dir.join(format!("{}.txt", entry.id));
        let text = match std::fs::read(&path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(_) => {
                report.missingLists.push(entry.id.clone());
                continue;
            }
        };
        let mut coverage = ListCoverage {
            id: entry.id.clone(),
            bytes: std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0),
            ..ListCoverage::default()
        };
        for bucket in Bucket::ALL {
            coverage.counts.insert(bucket.as_str().to_string(), 0);
        }

        for raw in text.lines() {
            coverage.lines += 1;
            let line = raw.trim();
            let Some(kind) = classify(line, &scriptlets, &mut modifier_evidence) else {
                continue;
            };
            coverage.validRules += 1;
            if let Some(host) = line.strip_prefix("*.") {
                if !host.is_empty() && !host.contains('/') && !host.contains('#') {
                    coverage.wildcardHostRules += 1;
                }
            }
            *coverage
                .counts
                .entry(kind.bucket.as_str().to_string())
                .or_insert(0) += 1;

            match &kind.detail {
                Detail::ElemHide { specific, exception } => {
                    if *exception {
                        coverage.elemhideException += 1;
                    } else if *specific {
                        coverage.elemhideSpecific += 1;
                    } else {
                        coverage.elemhideGeneric += 1;
                    }
                }
                Detail::Scriptlet { shipped, operator } => {
                    if *shipped {
                        coverage.scriptletShipped += 1;
                    } else {
                        coverage.scriptletMissing += 1;
                        mark(&mut shapes, kind.bucket, operator, line, &entry.id);
                    }
                }
                Detail::Operator(operator) => {
                    *coverage
                        .proceduralByOperator
                        .entry(operator.clone())
                        .or_insert(0) += 1;
                    mark(&mut shapes, kind.bucket, operator, line, &entry.id);
                }
                Detail::Modifier(option) => {
                    mark(&mut shapes, kind.bucket, option, line, &entry.id);
                }
                Detail::Plain => {}
            }
        }

        report.elemhideSpecific += coverage.elemhideSpecific;
        report.elemhideGeneric += coverage.elemhideGeneric;
        report.elemhideException += coverage.elemhideException;
        report.scriptletShipped += coverage.scriptletShipped;
        report.scriptletMissing += coverage.scriptletMissing;
        report.wildcardHostRules += coverage.wildcardHostRules;
        for (bucket, count) in &coverage.counts {
            *report.totals.entry(bucket.clone()).or_insert(0) += count;
        }
        report.lists.push(coverage);
    }

    report.effectiveRules = ["dns", "network", "elemhide", "proceduralApplied", "extras"]
        .iter()
        .map(|key| report.totals.get(*key).copied().unwrap_or(0))
        .sum::<u64>()
        + report.scriptletShipped;
    report.ineffectiveRules = report.scriptletMissing
        + report
            .totals
            .get("procedural")
            .copied()
            .unwrap_or(0)
        + report
            .totals
            .get("adguardModifier")
            .copied()
            .unwrap_or(0)
        + report
            .totals
            .get("parseFailure")
            .copied()
            .unwrap_or(0);

    report.unimplementedModifiers = modifier_evidence.into_values().collect();
    report
        .unimplementedModifiers
        .sort_by(|a, b| a.option.cmp(&b.option));

    let mut shapes: Vec<Shape> = shapes.into_values().collect();
    shapes.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.shape.cmp(&b.shape)));
    shapes.truncate(60);
    report.topIneffectiveShapes = shapes;
    report
}

fn mark(
    shapes: &mut HashMap<(String, &'static str), Shape>,
    bucket: Bucket,
    key: &str,
    line: &str,
    list_id: &str,
) {
    let shape = describe(bucket, key);
    let entry = shapes
        .entry((shape.clone(), bucket.as_str()))
        .or_insert_with(|| Shape {
            shape,
            bucket: bucket.as_str().to_string(),
            example: line.chars().take(160).collect(),
            ..Shape::default()
        });
    entry.count += 1;
    *entry.lists.entry(list_id.to_string()).or_insert(0) += 1;
}

/// A human-readable name for one ineffective syntax shape.
///
/// The `$` is added here rather than at the call sites so a modifier appears exactly once in the
/// ranking regardless of which branch attributed it (an option probe, or the engine's own
/// "recognised but not in this form" error).
fn describe(bucket: Bucket, key: &str) -> String {
    match bucket {
        Bucket::Procedural | Bucket::ProceduralApplied => format!("##…{key}"),
        Bucket::Extras | Bucket::AdguardModifier => {
            if key.starts_with('$') || key.starts_with('#') {
                format!("…{key}")
            } else {
                format!("…${key}")
            }
        }
        Bucket::Scriptlet => format!("##+js({key}, …)"),
        _ => key.to_string(),
    }
}

/// What kind of rule a line is, and the sub-detail the caller records.
struct Classified {
    bucket: Bucket,
    detail: Detail,
}

enum Detail {
    Plain,
    ElemHide { specific: bool, exception: bool },
    Scriptlet { shipped: bool, operator: String },
    Operator(String),
    Modifier(String),
}

/// The catalogue of scriptlet names and aliases this core can inject, read from the generated table.
///
/// Both matters: filter lists overwhelmingly write uBO's *short* spellings (`##+js(aopr, x)`), while
/// the generated table's canonical names carry the `.js` suffix and the short forms live in `aliases`.
/// Asking `scriptlets::names()` alone would report every real scriptlet as missing.
struct ShippedScriptlets {
    names: std::collections::HashSet<String>,
}

impl ShippedScriptlets {
    fn load() -> Self {
        let mut names = std::collections::HashSet::new();
        for resource in zshield::cosmetic::scriptlets::resources() {
            names.insert(resource.name.clone());
            for alias in &resource.aliases {
                names.insert(alias.clone());
            }
        }
        Self { names }
    }

    /// Whether the body for `name` ships. Lists write both the short spelling (`set-constant`) and
    /// the canonical file name (`set-constant.js`), and the two name the same resource.
    fn has(&self, name: &str) -> bool {
        let name = name.trim();
        if name.is_empty() {
            return false;
        }
        if self.names.contains(name) {
            return true;
        }
        let with_suffix = format!("{name}.js");
        self.names.contains(&with_suffix)
    }
}

/// Classify one line, or `None` when it is not a rule at all.
fn classify(
    line: &str,
    scriptlets: &ShippedScriptlets,
    modifier_evidence: &mut HashMap<String, ModifierVerdict>,
) -> Option<Classified> {
    if line.is_empty() {
        return None;
    }
    // Metadata. `!` is the ABP/AdGuard comment, `[Adblock Plus 2.0]` the header, `# ` a hosts-style
    // comment. A line starting with `#` and *not* followed by whitespace is a cosmetic rule
    // (`#@#.ad-box` is a generic unhide), so it must not be swallowed here.
    if line.starts_with('!')
        || (line.starts_with('[') && line.ends_with(']'))
        || (line.starts_with('#') && line[1..].starts_with(char::is_whitespace))
    {
        return None;
    }

    // The DNS layer: this crate's own parser, exactly the one `FilterBuilder::add_text` uses.
    let dns_class = zshield::dns::filter::classify_line(line);
    if dns_class.is_dns() {
        return Some(Classified {
            bucket: Bucket::Dns,
            detail: Detail::Plain,
        });
    }

    match parse_filter(line, false, ParseOptions::default()) {
        Ok(ParsedLine::Network(_)) => Some(Classified {
            bucket: Bucket::Network,
            detail: Detail::Plain,
        }),
        Ok(ParsedLine::Cosmetic(filter)) => Some(classify_cosmetic(&filter, scriptlets)),
        Err(err) => Some(classify_rejected(line, &err, modifier_evidence)),
    }
}

fn classify_cosmetic(
    filter: &adblock::filters::cosmetic::CosmeticFilter,
    scriptlets: &ShippedScriptlets,
) -> Classified {
    use adblock::filters::cosmetic::{CosmeticFilterMask, CosmeticFilterOperator};

    let exception = filter.mask.contains(CosmeticFilterMask::UNHIDE);
    if filter.mask.contains(CosmeticFilterMask::SCRIPT_INJECT) {
        // The engine stores the raw `+js(...)` argument list in the first operator.
        let args = filter
            .selector
            .iter()
            .find_map(|op| match op {
                CosmeticFilterOperator::CssSelector(text) => Some(text.as_str()),
                _ => None,
            })
            .unwrap_or_default();
        let name = args.split(',').next().unwrap_or_default().trim();
        return Classified {
            bucket: Bucket::Scriptlet,
            detail: Detail::Scriptlet {
                shipped: scriptlets.has(name),
                operator: if name.is_empty() {
                    "(empty)".to_string()
                } else {
                    name.to_string()
                },
            },
        };
    }

    // A procedural operator is anything the engine had to keep outside plain CSS.
    let operator = filter.selector.iter().find_map(|op| match op {
        CosmeticFilterOperator::CssSelector(_) => None,
        CosmeticFilterOperator::HasText(_) => Some(":has-text"),
        CosmeticFilterOperator::MatchesAttr(_) => Some(":matches-attr"),
        CosmeticFilterOperator::MatchesCss(_) => Some(":matches-css"),
        CosmeticFilterOperator::MatchesCssBefore(_) => Some(":matches-css-before"),
        CosmeticFilterOperator::MatchesCssAfter(_) => Some(":matches-css-after"),
        CosmeticFilterOperator::MatchesPath(_) => Some(":matches-path"),
        CosmeticFilterOperator::MinTextLength(_) => Some(":min-text-length"),
        CosmeticFilterOperator::Upward(_) => Some(":upward"),
        CosmeticFilterOperator::Xpath(_) => Some(":xpath"),
    });
    if let Some(operator) = operator {
        return Classified {
            bucket: Bucket::ProceduralApplied,
            detail: Detail::Operator(operator.to_string()),
        };
    }
    // An action (`:remove()`, `:style()`, `:remove-attr()`, `:remove-class()`) also travels in the
    // procedural channel, which this core never reads. Report it as procedural under its own name so
    // the ranking shows the action separately from the operators.
    if let Some(action) = filter.action.as_ref() {
        let name = match action {
            adblock::filters::cosmetic::CosmeticFilterAction::Remove => ":remove()",
            adblock::filters::cosmetic::CosmeticFilterAction::Style(_) => ":style()",
            adblock::filters::cosmetic::CosmeticFilterAction::RemoveAttr(_) => ":remove-attr()",
            adblock::filters::cosmetic::CosmeticFilterAction::RemoveClass(_) => ":remove-class()",
        };
        return Classified {
            bucket: Bucket::ProceduralApplied,
            detail: Detail::Operator(name.to_string()),
        };
    }

    // A plain CSS selector: effective, and *how* effective depends on whether the rule is bound to a
    // hostname at all. A generic selector is only injected when the document happens to contain one
    // of its classes/ids (`cosmetic::inject`), which is why the two are counted apart.
    let specific = filter.hostnames.is_some()
        || filter.entities.is_some()
        || filter.not_hostnames.is_some()
        || filter.not_entities.is_some();
    Classified {
        bucket: Bucket::ElemHide,
        detail: Detail::ElemHide {
            specific,
            exception,
        },
    }
}

/// The `$option` name of a line this core evaluates itself, or `None`.
///
/// Delegates to [`zshield::https::extras`], the code that actually runs at request time. Doing the
/// classification here instead would be a second implementation of the same parse, and the two would
/// drift the first time a rule form was added to one of them.
fn self_evaluated_modifier(line: &str) -> Option<String> {
    if !line.contains("popup") && !line.contains("denyallow") && !line.contains("removeparam") {
        return None;
    }
    let modifiers = zshield::https::extras::collect([line]);
    // One line can carry several of these options in principle; report the first that took effect so
    // the ranking still attributes it to one shape.
    if !modifiers.popup.is_empty() {
        return Some("$popup".to_string());
    }
    if !modifiers.denyallow.is_empty() {
        return Some("$denyallow".to_string());
    }
    if !modifiers.removeparam.is_empty() {
        return Some("$removeparam".to_string());
    }
    None
}

/// Classify a line the engine's parser rejected.
fn classify_rejected(
    line: &str,
    err: &adblock::lists::FilterParseError,
    modifier_evidence: &mut HashMap<String, ModifierVerdict>,
) -> Classified {
    // `$removeheader` is implemented by this core outside the engine, so a rule the engine refuses
    // for that reason is effective. `https::modifiers` strips the option and hands the rest to the
    // engine; do exactly the same and accept the line when the remainder parses.
    if line.contains("removeheader") {
        let mut rules = zshield::https::modifiers::collect_removeheader([line]);
        rules.build();
        if !rules.rules().is_empty() {
            return Classified {
                bucket: Bucket::Network,
                detail: Detail::Plain,
            };
        }
    }

    // The modifiers this core evaluates itself (M5b §3/§5/§6). Each is asked through the *shipping*
    // collector rather than re-parsed here, so the report and the runtime cannot disagree: a line the
    // collector accepts is a line that will filter, and one it refuses stays in the ineffective bucket
    // with the reason attached.
    if let Some(detail) = self_evaluated_modifier(line) {
        return Classified {
            bucket: Bucket::Extras,
            detail: Detail::Modifier(detail),
        };
    }

    // Cosmetic syntaxes the engine refuses outright: AdGuard's own scriptlet/CSS markers and HTML
    // filtering. These are their own families; report them under the AdGuard bucket so the ranking
    // separates "a whole syntax we do not speak" from "one modifier we do not know".
    if line.contains("#%#") || line.contains("#$#") || line.contains("#$?#") {
        return Classified {
            bucket: Bucket::AdguardModifier,
            detail: Detail::Modifier("#%#/#$# AdGuard CSS/scriptlet".to_string()),
        };
    }
    if line.contains("##^") || line.contains("#@#^") {
        return Classified {
            bucket: Bucket::AdguardModifier,
            detail: Detail::Modifier("##^ HTML filtering".to_string()),
        };
    }
    // An AdGuard regex domain: `/mmsbee\d+\.com/##…`. The engine has no regex hostname matcher.
    if let Some(sharp) = line.find("##") {
        if line[..sharp].contains('/') && line[..sharp].trim_start().starts_with('/') {
            return Classified {
                bucket: Bucket::AdguardModifier,
                detail: Detail::Modifier("/regex/ 域匹配".to_string()),
            };
        }
    }
    // A generic unhide with no domain at all (`#@#.ad-box`): the engine refuses it because a rule that
    // unhides everywhere would cancel every generic hide rule in the list.
    if line.starts_with("#@#") || line.starts_with("#?#") {
        return Classified {
            bucket: Bucket::AdguardModifier,
            detail: Detail::Modifier("#@# 无域名".to_string()),
        };
    }
    // A whole-pattern regex rule (`/^88\.208\.22\.[1234]$/`): the engine needs the pattern to have a
    // token it can index on, and a pure-regex target has none.
    if line.starts_with('/') && line.len() > 2 {
        return Classified {
            bucket: Bucket::AdguardModifier,
            detail: Detail::Modifier("/regex/ 整条规则".to_string()),
        };
    }

    // An option the engine recognises but only in a narrower form than the rule uses
    // (`$removeparam=/regex/`, `$removeparam` on an exception) is still a modifier gap: the list
    // author asked for something this build does not do.
    if let Some(variant) = narrowed_modifier(&format!("{err}")) {
        return Classified {
            bucket: Bucket::AdguardModifier,
            detail: Detail::Modifier(variant),
        };
    }

    // Otherwise: find *which* option is the fault by removing options one at a time and re-parsing.
    // This is the only attributable answer: the engine reports "unrecognised option" without saying
    // which one, and a synthetic probe can disagree with reality (`$popup` is unknown to the parser,
    // yet the same name inside a real URL is not an option at all). Removing a name and seeing the
    // line start to parse proves that name was the blocker.
    if let Some(option) = rejects_for_option(line) {
        modifier_evidence
            .entry(option.clone())
            .or_insert_with(|| ModifierVerdict {
                option: option.clone(),
                probe: line.chars().take(200).collect(),
                accepted: false,
                error: format!("{err}"),
            });
        return Classified {
            bucket: Bucket::AdguardModifier,
            detail: Detail::Modifier(format!("${option}")),
        };
    }

    Classified {
        bucket: Bucket::ParseFailure,
        detail: Detail::Operator(format!("{err}")),
    }
}
/// Map the engine's "the option exists but not in this form" errors back to the modifier's name.
///
/// These are worth separating from parse failures: the list asked for a real feature that this
/// build's engine only implements in a narrower shape, which is a different kind of gap than a
/// broken line. They are also the reason the "unknown modifier" list cannot be built by removing
/// one option and re-parsing: for `$csp,subdocument` the removal *does* fix the line, yet `$csp` is a
/// name the parser knows — the fault is the combination, and the engine said so.
fn narrowed_modifier(error: &str) -> Option<String> {
    let name = if error.contains("removeparam regex unsupported") {
        "$removeparam=/regex/"
    } else if error.contains("empty removeparam") {
        "$removeparam"
    } else if error.contains("removeparam with exception") {
        "$removeparam (exception)"
    } else if error.contains("csp with content type") {
        "$csp 与资源类型组合"
    } else if error.contains("empty redirection") {
        "$redirect/$redirect-rule 缺参数"
    } else if error.contains("no supported domains") {
        "$domain 仅含排除项"
    } else if error.contains("full regex unsupported") {
        "$<regex>"
    } else if error.contains("match-case without full regex") {
        "$match-case"
    } else {
        return None;
    };
    Some(name.to_string())
}

/// A network rule's option list, and the ability to re-emit the line without one option.
struct Options<'a> {
    /// The rule text before the `$`.
    pattern: &'a str,
    /// The option names, in order, with any `=value` stripped.
    names: Vec<String>,
    /// The raw option segments, for re-emission.
    segments: Vec<&'a str>,
}

impl Options<'_> {
    /// The line with one option removed, `$`-joined exactly as the lists write it.
    fn without(&self, name: &str) -> String {
        let kept: Vec<&str> = self
            .segments
            .iter()
            .copied()
            .filter(|segment| segment.split('=').next() != Some(name))
            .collect();
        if kept.is_empty() {
            self.pattern.to_string()
        } else {
            format!("{}${}", self.pattern, kept.join(","))
        }
    }
}

/// The `$option,...` list a network rule carries, or `None` when it has none.
///
/// An option list only exists on a network rule, and only `$` outside the URL can start one: the last
/// `$` is used because a URL may contain `$` in its path or query while the option list never does.
/// (`||a.example/p$var^` uses `$` inside a regex-shaped pattern; the last `$` is still the right
/// split for every real list line, and a wrong split only means the line stays a parse failure.)
fn option_names(line: &str) -> Option<Options<'_>> {
    let pattern = line.strip_prefix("@@").unwrap_or(line);
    // Cosmetic rules carry `#` markers before any `$`.
    if pattern.contains("##") || pattern.contains("#@#") || pattern.contains("#?#") {
        return None;
    }
    let (base, options) = pattern.rsplit_once('$')?;
    if options.is_empty() {
        return None;
    }
    let segments: Vec<&str> = options
        .split(',')
        .map(|option| option.trim())
        .filter(|option| !option.is_empty())
        .collect();
    if segments.is_empty() {
        return None;
    }
    let names: Vec<String> = segments
        .iter()
        .map(|segment| {
            segment
                .trim_start_matches('~')
                .split('=')
                .next()
                .unwrap_or(segment)
                .to_string()
        })
        .collect();
    // Every segment must look like an option name. A `$` that is a regex end-anchor
    // (`/^88\.208\.22\.[1234]$/`) or part of a URL leaves garbage here, and treating that as an
    // option list would invent modifiers that no list ever wrote.
    if !names
        .iter()
        .all(|name| !name.is_empty() && name.len() <= 32 && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
    {
        return None;
    }
    Some(Options {
        // `base` is the rule without its `$`; `@@` stripped from `pattern` has to go back on, or a
        // re-emitted exception becomes a block rule.
        pattern: if pattern.len() == line.len() {
            base
        } else {
            &line[..line.len() - pattern.len() + base.len()]
        },
        names,
        segments,
    })
}

/// Whether the engine's parser rejects `line` because of a `$option` name it does not know, and which.
///
/// Attribute by construction rather than by a synthetic probe: remove one option at a time and
/// re-parse. A rule that parses once option *X* is gone proves *X* is a name this build's parser does
/// not know. When no single removal fixes the line (two unknown options, or a bad value on a known
/// option) the line stays a parse failure — that is honest, and it is why the ranking separates the
/// two counts.
fn rejects_for_option(line: &str) -> Option<String> {
    // Only a line that the engine actually rejects can have a rejecting option. Without this guard
    // the function reports an option for any parseable rule: removing a *known* option from
    // `||ads.example^$third-party` leaves `||ads.example`, which parses, so the removal would look
    // like proof that `$third-party` was the problem.
    if parse_filter(line, false, ParseOptions::default()).is_ok() {
        return None;
    }
    let options = option_names(line)?;
    for name in &options.names {
        let candidate = options.without(name);
        if candidate != line && parse_filter(&candidate, false, ParseOptions::default()).is_ok() {
            return Some(name.clone());
        }
    }
    None
}

/// The UTC timestamp recorded by `scripts/effectiveness/fetch-lists.sh`.
fn read_manifest_timestamp(list_dir: &Path) -> String {
    let path = list_dir.join("manifest.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return String::new();
    };
    // The manifest is a flat array of small objects; the first `fetchedAt` is the run's stamp and
    // parsing the whole thing would need a second serde type for no benefit.
    text.split("\"fetchedAt\": \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_default()
        .to_string()
}

fn print_summary(report: &Report) {
    println!("lists: {} (missing: {})", report.listCount, report.missingLists.len());
    println!("lists fetched at: {}", report.listsFetchedAt);
    println!();
    println!("{:<16} {:>10}", "bucket", "rules");
    for bucket in Bucket::ALL {
        println!(
            "{:<16} {:>10}",
            bucket.as_str(),
            report.totals.get(bucket.as_str()).copied().unwrap_or(0)
        );
    }
    let total: u64 = report.totals.values().sum();
    println!("{:<16} {:>10}", "sum", total);
    println!();
    println!(
        "effective {} / ineffective {}",
        report.effectiveRules, report.ineffectiveRules
    );
    println!(
        "elemhide: specific {} generic {} exception {}",
        report.elemhideSpecific, report.elemhideGeneric, report.elemhideException
    );
    println!(
        "scriptlet: shipped {} missing {}",
        report.scriptletShipped, report.scriptletMissing
    );
    println!("wildcard host rules (*.domain): {}", report.wildcardHostRules);
    println!();
    println!("unimplemented $modifiers (engine parser rejects the probe):");
    for verdict in &report.unimplementedModifiers {
        println!("  {:<24} {}", verdict.option, verdict.error);
    }
    println!();
    println!("top ineffective shapes:");
    for shape in report.topIneffectiveShapes.iter().take(30) {
        println!("  {:>8}  {:<12} {}", shape.count, shape.bucket, shape.shape);
    }
    println!();
    // Per-list reconciliation: the categories must partition the valid rules of every list.
    let mut bad = Vec::new();
    for list in &report.lists {
        let sum: u64 = list.counts.values().sum();
        if sum != list.validRules {
            bad.push(format!("{}: {} != {}", list.id, sum, list.validRules));
        }
    }
    if bad.is_empty() {
        println!("reconciliation: OK for all {} lists", report.lists.len());
    } else {
        println!("reconciliation MISMATCH: {bad:?}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    //! The classifier's own edge cases. They are unit tests rather than assertions in `main` because
    //! the report's credibility rests on this code classifying real list lines correctly, and the
    //! forms that broke it are not obvious from the outside (a `$` inside a regex, an empty option
    //! list, an AdGuard marker that looks like a comment).
    use super::*;

    fn classify_line(line: &str) -> Option<Classified> {
        static SCRIPTLETS: std::sync::OnceLock<ShippedScriptlets> = std::sync::OnceLock::new();
        let scriptlets = SCRIPTLETS.get_or_init(ShippedScriptlets::load);
        let mut evidence = HashMap::new();
        classify(line, scriptlets, &mut evidence)
    }

    #[test]
    fn comments_and_headers_are_not_rules_but_cosmetic_rules_are() {
        assert!(classify_line("! Title: something").is_none());
        assert!(classify_line("[Adblock Plus 2.0]").is_none());
        assert!(classify_line("# Version: 202611091205").is_none());
        // `#@#.ad-box` starts with `#` but is a cosmetic rule, not a comment: swallowing it as a
        // comment is what an earlier version of this probe did, and it hid 5 547 exception rules.
        assert!(classify_line("#@#.ad-box").is_some());
        assert!(classify_line("###case-1 > .test-banner").is_some());
    }

    #[test]
    fn the_dns_layer_claims_only_whole_domain_rules() {
        assert_eq!(classify_line("||ads.example^").map(|c| c.bucket), Some(Bucket::Dns));
        assert_eq!(classify_line("0.0.0.0 ads.example").map(|c| c.bucket), Some(Bucket::Dns));
        // A rule with any modifier is not a DNS-layer rule: it only forbids part of the domain's
        // traffic (`docs/DESIGN.md`, `compile.rs`).
        assert_eq!(
            classify_line("||ads.example^$third-party").map(|c| c.bucket),
            Some(Bucket::Network)
        );
    }

    #[test]
    fn a_scriptlet_is_effective_only_when_its_body_ships() {
        // `set-constant` ships; the short spelling is what the lists actually write.
        assert_eq!(
            classify_line("example.com##+js(set-constant, ads, false)").map(|c| c.bucket),
            Some(Bucket::Scriptlet)
        );
        match classify_line("example.com##+js(noeval, x)") {
            Some(Classified {
                bucket: Bucket::Scriptlet,
                detail: Detail::Scriptlet { shipped, .. },
            }) => assert!(!shipped, "noeval has no body in this build"),
            other => panic!("unexpected classification: {:?}", other.map(|c| c.bucket)),
        }
    }

    #[test]
    fn action_rules_are_reported_as_ineffective() {
        // `:style()`, `:remove()` and `:remove-attr()` are parsed into `CosmeticFilterAction` even
        // without the `css-validation` feature, and this core never reads that field — so they are
        // real gaps and must be counted as such.
        for line in [
            "example.com##.ad:style(display: none !important;)",
            "example.com##.ad:remove()",
            "example.com##.ad:remove-attr(onclick)",
        ] {
            assert_eq!(
                classify_line(line).map(|c| c.bucket),
                Some(Bucket::Procedural),
                "{line} must be procedural"
            );
        }
    }

    #[test]
    fn a_procedural_operator_survives_as_a_plain_selector_without_css_validation() {
        // **A finding, encoded so it cannot silently change.** `adblock` is built without its
        // `css-validation` feature (see `core/Cargo.toml`), and that feature is what turns
        // `:has-text()`, `:upward()`, `:xpath()`, `:matches-css()` into `CosmeticFilterOperator`
        // variants. Without it the engine keeps the whole thing as one opaque `CssSelector` string.
        //
        // Two consequences, both of which the report must not get wrong:
        //
        // 1. the engine cannot classify these rules as procedural, so this probe cannot count them
        //    from the parsed form — the count in `docs/coverage.json` for `procedural` therefore
        //    covers *actions* only, and the operator forms are counted by syntax (see
        //    `scripts/effectiveness/`), not here;
        // 2. more importantly, the engine will hand such a rule to the injector as a CSS selector,
        //    and a browser silently ignores a selector it cannot parse. That is a no-op today, which
        //    is why the classification as "ineffective" is still correct — but it is ineffective for
        //    a *different reason* than "this core does not read it".
        match classify_line("example.com##.ad:has-text(Sponsored)") {
            Some(Classified {
                bucket: Bucket::ElemHide,
                ..
            }) => {}
            other => panic!(
                "without css-validation the operator is an opaque selector: {:?}",
                other.map(|c| c.bucket)
            ),
        }
    }

    #[test]
    fn plain_element_hiding_is_effective_and_split_by_hostname_scope() {
        match classify_line("example.com##.ad-banner") {
            Some(Classified {
                bucket: Bucket::ElemHide,
                detail: Detail::ElemHide { specific, exception },
            }) => {
                assert!(specific, "a hostname-bound rule is specific");
                assert!(!exception);
            }
            other => panic!("unexpected: {:?}", other.map(|c| c.bucket)),
        }
        match classify_line("###generic-banner") {
            Some(Classified {
                detail: Detail::ElemHide { specific, .. },
                ..
            }) => assert!(!specific, "a rule with no hostname is generic"),
            other => panic!("unexpected: {:?}", other.map(|c| c.bucket)),
        }
    }

    #[test]
    fn an_option_is_attributed_only_when_removing_it_makes_the_line_parse() {
        // `$popup` is a name the pinned engine's parser does not know, so removing it fixes the line.
        assert_eq!(
            rejects_for_option("||ads.example^$popup").as_deref(),
            Some("popup")
        );
        // `$third-party` is known, so removing it is not what fixes anything and nothing is
        // attributed — the line parses as it stands.
        assert!(parse_filter("||ads.example^$third-party", false, ParseOptions::default()).is_ok());
        assert_eq!(rejects_for_option("||ads.example^$third-party"), None);
    }

    #[test]
    fn an_option_list_is_not_invented_from_a_regex_anchor() {
        // `/^88\.208\.22\.[1234]$/` ends with `$` followed by `/`, which is not an option list.
        assert!(option_names("/^88\\.208\\.22\\.[1234]$/").is_none());
        // A cosmetic rule has no option list even when a selector contains `$`.
        assert!(option_names("example.com##a[href$=\"/ad\"]").is_none());
        // A real option list is found, and a removal re-emits the `@@` prefix.
        let options = option_names("@@||ads.example^$script,third-party").expect("options");
        assert_eq!(options.names, vec!["script", "third-party"]);
        assert_eq!(options.without("script"), "@@||ads.example^$third-party");
    }

    #[test]
    fn the_shipped_scriptlet_table_exposes_aliases_not_just_canonical_names() {
        let scriptlets = ShippedScriptlets::load();
        // Short spellings live in `aliases`; reading only canonical names reported every real
        // scriptlet rule as missing.
        assert!(scriptlets.has("set-constant"), "short spelling");
        assert!(scriptlets.has("set-constant.js"), "canonical spelling");
        assert!(scriptlets.has("nostif"), "alias of no-setTimeout-if");
        assert!(!scriptlets.has("definitely-not-a-scriptlet"));
    }
}
