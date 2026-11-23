//! Report the evaluation path a request actually takes, per build (MYS-2826, review round 2).
//!
//! # Why this exists
//!
//! The first delivery claimed "the same 40 `by-value` rules cost 1.01×, therefore evaluation has not
//! regressed". The stage-5 review showed that claim was vacuous: those 40 rules are all anchored at
//! real hosts, the request was `www.example.com`, so **the gate never opened** and
//! `RemoveParamRules::rewrite` returned at `extras.rs:1132` without executing `in_force` at all. The
//! row measured "a gate that misses", not "rule evaluation".
//!
//! A cost comparison is only about evaluation when evaluation ran. This example prints, for one
//! request and one rule set:
//!
//!   * whether each rule's stripped form matches the request (`gate` semantics: the union of blocking
//!     forms the build collected);
//!   * how many rules each build collected, and how many of them can be reached for this request;
//!   * the resulting rewrite.
//!
//! so the report can state the path instead of assuming it. It is used as a gate on the comparison:
//! a case is only reported as an evaluation cost when `gate_would_open` is true for **both** builds.
//!
//! # What "gate" means here
//!
//! `RemoveParamRules::gate` is one `adblock::Engine` built from every blocking stripped form the build
//! collected, and `gate_open` asks it `should_block()`. This example rebuilds exactly that — from the
//! same `removeparam.rules()`, skipping exceptions, as `build()` does — so the answer matches the
//! shipping code path rather than approximating it. It does **not** re-implement matching; it uses the
//! engine, which is what `gate_open` uses.
//!
//! # Usage
//!
//! ```text
//! cargo run --release --manifest-path core/Cargo.toml --example removeparam_path -- \
//!     <rules-file> <matrix-case-id> [--matrix <path>] [--build-id <name>]
//! ```

use zshield::https::extras;

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.len() < 2 {
        eprintln!(
            "usage: removeparam_path <rules-file> <matrix-case-id> \
             [--matrix <path>] [--build-id <name>]"
        );
        std::process::exit(2);
    }
    let rules_path = &arguments[0];
    // The caller names the build, because this example does not know which revision it was compiled
    // into — and "which build took this path" is the whole point of the record.
    let build_id = arguments
        .iter()
        .position(|argument| argument == "--build-id")
        .and_then(|position| arguments.get(position + 1))
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    let case_id = &arguments[1];
    let matrix_path = arguments
        .iter()
        .position(|argument| argument == "--matrix")
        .and_then(|position| arguments.get(position + 1))
        .cloned()
        .unwrap_or_else(|| "scripts/perf/matrix.json".to_string());

    let rules = std::fs::read_to_string(rules_path)
        .unwrap_or_else(|error| panic!("cannot read {rules_path}: {error}"));
    let matrix: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&matrix_path)
            .unwrap_or_else(|error| panic!("cannot read {matrix_path}: {error}")),
    )
    .expect("matrix is JSON");
    let case = matrix["cases"]
        .as_array()
        .expect("matrix.cases")
        .iter()
        .find(|case| case["id"].as_str() == Some(case_id.as_str()))
        .unwrap_or_else(|| panic!("no matrix case {case_id}"));
    let url = case["url"].as_str().expect("case.url");
    let kind_text = case["kind"].as_str().unwrap_or("document");
    let method = case["method"].as_str().unwrap_or("GET");
    let referer = case["referer"].as_str();

    let collected = extras::collect([rules.as_str()]);

    // Rebuild the gate the way `RemoveParamRules::build` does: one engine over every **blocking**
    // stripped form. Exceptions are excluded there for a reason the struct documents (an `@@` inside
    // one engine cancels a block, which would answer "nothing matched" for a request an exception only
    // narrows), so they are excluded here too.
    let blocking_forms: Vec<String> = collected
        .removeparam
        .rules()
        .iter()
        .filter(|rule| !rule.exception)
        .map(|rule| rule.stripped.clone())
        .collect();
    let gate = {
        let mut set = adblock::lists::FilterSet::new(false);
        for form in &blocking_forms {
            set.add_filter_list(form.clone(), adblock::lists::ParseOptions::default());
        }
        adblock::Engine::new_with_filter_set(set)
    };

    // The same request the harness builds: `Request::new(url, source, type, method)`, with the matrix
    // URL standing in as the source when no referer is given — which is what the harness's
    // `build_request` does (it leaves `referer: None`, and `to_adblock_request` then reports
    // first-party with an empty source). `Request::new` needs *some* source, so the URL is the one that
    // makes the party first-party, matching the production decision.
    let request = adblock::request::Request::new(
        url,
        referer.unwrap_or(url),
        kind_text,
        method,
    )
    .expect("benchmark URL parses");
    let gate_should_block = gate.check_network_request(&request).should_block();

    // How many rules can be reached at all. `Scope::Engine` rules need a query, so this is the count
    // that decides whether the per-candidate path is exercised — the number the report has to quote.
    let total = collected.removeparam.len();
    let exceptions = collected
        .removeparam
        .rules()
        .iter()
        .filter(|rule| rule.exception)
        .count();

    println!(
        "{}",
        serde_json::json!({
            "record": "path",
            "build": build_id,
            "rules_file": rules_path,
            "case": case_id,
            "url": url,
            "kind": kind_text,
            "referer": referer,
            "removeparam_rules": total,
            "exceptions": exceptions,
            "blocking_forms": blocking_forms.len(),
            // The decisive field: false means `rewrite` returns at the gate and `in_force` never runs,
            // so any timing for this pair is the cost of a *missed* gate, not of evaluation.
            "gate_should_block": gate_should_block,
            "enters_in_force": gate_should_block && url.split_once('?')
                .is_some_and(|(_, query)| !query.split('#').next().unwrap_or("").is_empty()),
            "rewrite": collected.removeparam.rewrite(
                &zshield::http::head::HttpRequest {
                    method: method.to_string(),
                    target: url
                        .find("://")
                        .and_then(|index| {
                            let after = &url[index + 3..];
                            after.find('/').map(|slash| after[slash..].to_string())
                        })
                        .unwrap_or_else(|| "/".to_string()),
                    version: zshield::http::head::Version::Http11,
                    url: url.to_string(),
                    host: String::new(),
                    hostname: adblock::url_parser::parse_url(url)
                        .map(|parsed| parsed.hostname().to_ascii_lowercase())
                        .unwrap_or_default(),
                    referer: referer.map(str::to_string),
                    fetch_dest: Some(kind_text.to_string()),
                    fetch_site: None,
                    fetch_user: None,
                    accept: None,
                    content_length: None,
                    chunked: false,
                    upgrade: false,
                    expect_continue: false,
                    head_len: 0,
                },
                kind_of(kind_text),
            ),
        })
    );
}

fn kind_of(text: &str) -> zshield::http::resource::RequestKind {
    use zshield::http::resource::RequestKind;
    match text {
        "document" => RequestKind::Document,
        "subdocument" => RequestKind::Subdocument,
        "script" => RequestKind::Script,
        "stylesheet" => RequestKind::Stylesheet,
        "image" => RequestKind::Image,
        "media" => RequestKind::Media,
        "font" => RequestKind::Font,
        "xmlhttprequest" => RequestKind::Xhr,
        "websocket" => RequestKind::Websocket,
        "ping" => RequestKind::Ping,
        "object" => RequestKind::Object,
        _ => RequestKind::Other,
    }
}
