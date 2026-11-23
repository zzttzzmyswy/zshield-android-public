//! Host controls for MYS-2859: does a reload notice an `extras.txt`-only change?
//!
//! # Why this exists
//!
//! The lead's reproduction (`lead-extras-repro.rs`) walks the production path once:
//! `compile_request` → `start_engine` → `compile_request` again → `reload_engine`, and reported
//! `extras_changed=true, fingerprint_equal=true, reload_returned=true` with the log line
//! `rules reload: artifacts unchanged, keeping the loaded rule sets`. That is the bug. This example
//! turns the same walk into a **checked** control with two properties the reproduction did not have:
//!
//! 1. It asserts what the reload is *for*, not only what it returned: the parameter that the new rule
//!    names must be gone from the URL after the reload, evaluated through the same
//!    `HttpsModifiers::edits` the relays call. A return value alone cannot tell "the new rule is in
//!    force" from "the function returned true while keeping the old rule set" — which is exactly the
//!    wrong answer this task exists to remove.
//! 2. It covers the three transition shapes (appear / change / disappear) plus the failure and retry,
//!    and it runs the unchanged case repeatedly, so the fast path cannot be "fixed" by making the
//!    reload always rebuild.
//!
//! # What it is not
//!
//! This is a **host** control: a `UnixDatagram` pair stands in for the TUN descriptor (the tokio
//! reactor registers it exactly like a TUN fd, so the tunnel loop really runs), no packet is
//! forwarded, and no Android API is involved. It proves the reload bookkeeping; it says nothing about
//! Pixel concurrency, HTTPS interception or PSS, which stay with the device stages.
//!
//! # Usage
//!
//! ```text
//! cargo run --release --manifest-path core/Cargo.toml --example extras_reload_identity -- <workdir>
//! ```
//!
//! Exits 0 when every control passes, 1 otherwise, printing one `PASS`/`FAIL` line per control so the
//! delivery log can be read without the source.

use std::os::fd::IntoRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use zshield::http::decision::HttpFilter;
use zshield::http::head::{HttpRequest, Version};
use zshield::http::resource::RequestKind;
use zshield::http::rewrite::ModifierSource;
use zshield::https::modifiers::{collect_removeheader, HttpsModifiers};

/// One control's verdict, accumulated so a run reports every failure rather than the first.
struct Report {
    passed: u32,
    failed: u32,
}

impl Report {
    fn check(&mut self, name: &str, condition: bool, detail: &str) {
        if condition {
            self.passed += 1;
            println!("PASS {name}{}", suffix(detail));
        } else {
            self.failed += 1;
            println!("FAIL {name}{}", suffix(detail));
        }
    }
}

fn suffix(detail: &str) -> String {
    if detail.is_empty() {
        String::new()
    } else {
        format!("  [{detail}]")
    }
}

/// Compile `rules` (no lists, only user rules) into `<work>/compiled`. Returns the stats JSON.
fn compile(work: &Path, rules: &str) -> serde_json::Value {
    let request = serde_json::json!({
        "lists": [],
        "userRules": rules,
        "outputDir": work.join("compiled").to_string_lossy(),
    })
    .to_string();
    let stats = zshield::compile::compile_request(&request).expect("compile");
    serde_json::to_value(stats).expect("stats json")
}

/// Start an engine over a real, registerable descriptor — not `/dev/null`.
///
/// A `UnixDatagram` pair is a socket the tokio reactor can register with `AsyncFd`, so the tunnel loop
/// reaches its first `select!` and the handle is a real running tunnel rather than a failed
/// registration pretending to be one.
fn start(work: &Path) -> (u64, std::os::unix::net::UnixDatagram) {
    let (tun, peer) = std::os::unix::net::UnixDatagram::pair().expect("socketpair");
    // Keep the peer owned until stop, then close it with this control's other resources.
    let config = serde_json::json!({
        "compiledDir": work.join("compiled").to_string_lossy(),
        "upstreams": [{"type": "udp", "address": "127.0.0.1:53"}],
    })
    .to_string();
    let handle = zshield::jni_api::start_engine(tun.into_raw_fd(), &config).expect("engine starts");
    (handle, peer)
}

fn stop(handle: u64, peer: std::os::unix::net::UnixDatagram) {
    zshield::jni_api::stop_engine(handle);
    drop(peer);
    assert!(zshield::jni_api::handle_rules_state(handle).is_none());
    assert!(zshield::jni_api::handle_http_filter(handle).is_none());
    assert!(zshield::jni_api::handle_dns_filter(handle).is_none());
}

/// The filter in force on `handle`.
fn filter_of(handle: u64) -> Arc<HttpFilter> {
    zshield::jni_api::handle_http_filter(handle).expect("engine.bin loaded")
}

/// What `$removeparam` leaves of `url`, through the production evaluation path.
fn removeparam(filter: &Arc<HttpFilter>, url: &str, kind: RequestKind) -> String {
    let modifiers = HttpsModifiers::new(
        filter.clone(),
        Arc::new(collect_removeheader(std::iter::empty())),
        filter.extras_arc(),
    );
    let authority = url
        .split("//")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .expect("absolute url");
    let request = HttpRequest {
        method: "GET".into(),
        target: format!("/{}", url.splitn(4, '/').nth(3).unwrap_or("")),
        version: Version::Http11,
        url: url.into(),
        host: authority.into(),
        hostname: authority.split(':').next().unwrap_or(authority).into(),
        referer: Some(format!("https://{authority}/")),
        fetch_dest: Some("empty".into()),
        fetch_site: None,
        fetch_user: None,
        accept: None,
        content_length: None,
        chunked: false,
        upgrade: false,
        expect_continue: false,
        head_len: 0,
    };
    modifiers
        .edits(&request, kind)
        .and_then(|edits| edits.url)
        .unwrap_or_else(|| url.to_string())
}

/// The three artifacts' identities as the handle reports them, and its generation.
fn state(handle: u64) -> zshield::rules_identity::RulesState {
    zshield::jni_api::handle_rules_state(handle).expect("handle is live")
}

fn extras_bytes(work: &Path) -> Option<Vec<u8>> {
    zshield::compiled::Envelope::read(
        &work.join("compiled").join(zshield::compiled::EXTRAS_FILE),
        zshield::compiled::Artifact::Extras,
    )
    .ok()
    .map(|envelope| envelope.payload)
}

/// The regression itself: only `extras.txt` changes, and the reload must pick it up.
///
/// Two rules that both live exclusively in `extras.txt` (a regex `$removeparam` the adblock engine
/// refuses) so that `dns.bin` and `engine.bin` are byte-identical between the two compiles. The
/// controls assert that identity rather than assuming it: if the compile ever started putting these
/// rules into the engine too, this control would stop describing the bug.
fn extras_only_change(report: &mut Report, work: &Path) {
    let old_rule = "||example.test^$xmlhttprequest,removeparam=/^old=/";
    let new_rule = "||example.test^$xmlhttprequest,removeparam=/^new=/";
    let url = "https://example.test/p?old=1&new=2&keep=3";

    compile(work, old_rule);
    let dns_before = std::fs::read(work.join("compiled").join(zshield::compiled::DNS_FILE)).ok();
    let engine_before =
        std::fs::read(work.join("compiled").join(zshield::compiled::ENGINE_FILE)).ok();
    let extras_before = extras_bytes(work);

    let (handle, peer) = start(work);
    let before_url = removeparam(&filter_of(handle), url, RequestKind::Xhr);
    report.check(
        "extras_only/baseline_rule_in_force",
        before_url == "https://example.test/p?new=2&keep=3",
        &format!("got {before_url}"),
    );
    let identity_before = state(handle).identities.extras;
    let generation_before = state(handle).generation;

    compile(work, new_rule);
    let dns_after = std::fs::read(work.join("compiled").join(zshield::compiled::DNS_FILE)).ok();
    let engine_after =
        std::fs::read(work.join("compiled").join(zshield::compiled::ENGINE_FILE)).ok();
    let extras_after = extras_bytes(work);
    report.check(
        "extras_only/dns_bin_identical",
        dns_before == dns_after,
        "this case is only about extras",
    );
    report.check(
        "extras_only/engine_bin_identical",
        engine_before == engine_after,
        "this case is only about extras",
    );
    report.check(
        "extras_only/extras_changed",
        extras_before != extras_after,
        "the premise of the case",
    );
    // The lead's reproduction read this exact equality as "nothing to do"; here it is the input to
    // the question, and the answer is what the next controls decide.
    report.check(
        "extras_only/fingerprint_dns_engine_equal",
        dns_before == dns_after && engine_before == engine_after,
        "dns.bin and engine.bin are unchanged, extras.txt is not",
    );

    let reloaded = zshield::jni_api::reload_engine(handle, &work.join("compiled").to_string_lossy());
    report.check("extras_only/reload_returned_true", reloaded, "");

    let after_url = removeparam(&filter_of(handle), url, RequestKind::Xhr);
    report.check(
        "extras_only/new_rule_in_force",
        after_url == "https://example.test/p?old=1&keep=3",
        &format!("want old kept/new removed, got {after_url}"),
    );
    let after = state(handle);
    report.check(
        "extras_only/identity_updated",
        after.identities.extras != identity_before && after.identities.extras.is_some(),
        "the extras identity must describe the rules now in force",
    );
    report.check(
        "extras_only/identity_matches_payload",
        extras_after.is_some()
            && after.identities.extras
                == extras_after
                    .as_ref()
                    .map(|payload| zshield::compiled::PayloadIdentity::of_payload(payload)),
        "the identity must hash the bytes that were installed",
    );
    report.check(
        "extras_only/generation_advanced",
        after.generation > generation_before,
        &format!("{} -> {}", generation_before, after.generation),
    );

    stop(handle, peer);
}

/// The four states an `extras.txt` moves between, each reloaded on its own.
fn transitions(report: &mut Report, work: &Path) {
    let url = "https://shop.test/p?one=1&two=2&three=3";
    compile(work, "||plain.test^");
    // Start from "no file at all" — an artifact set written before `extras.txt` existed, and the
    // state a user reaches by removing the file.
    let _ = std::fs::remove_file(work.join("compiled").join(zshield::compiled::EXTRAS_FILE));
    let (handle, peer) = start(work);
    report.check(
        "transitions/absent_at_start",
        state(handle).identities.extras.is_none(),
        "no extras.txt, so the component is absent",
    );

    // 1. appears
    compile(work, "||shop.test^$xmlhttprequest,removeparam=/^one=/");
    let reloaded = zshield::jni_api::reload_engine(handle, &work.join("compiled").to_string_lossy());
    let applied = removeparam(&filter_of(handle), url, RequestKind::Xhr);
    report.check(
        "transitions/added_applies",
        reloaded && applied == "https://shop.test/p?two=2&three=3",
        &format!("reloaded={reloaded} got {applied}"),
    );
    let first = state(handle).identities.extras;

    // 2. changes
    compile(work, "||shop.test^$xmlhttprequest,removeparam=/^two=/");
    let reloaded = zshield::jni_api::reload_engine(handle, &work.join("compiled").to_string_lossy());
    let applied = removeparam(&filter_of(handle), url, RequestKind::Xhr);
    report.check(
        "transitions/changed_applies",
        reloaded && applied == "https://shop.test/p?one=1&three=3",
        &format!("reloaded={reloaded} got {applied}"),
    );
    report.check(
        "transitions/changed_identity",
        state(handle).identities.extras != first,
        "different rules, different identity",
    );

    // 3. emptied: a compile with no modifier rules writes an empty file, and "the user deleted their
    //    rules" has to be installable.
    compile(work, "||shop.test^");
    let emptied = extras_bytes(work);
    let reloaded = zshield::jni_api::reload_engine(handle, &work.join("compiled").to_string_lossy());
    let applied = removeparam(&filter_of(handle), url, RequestKind::Xhr);
    report.check(
        "transitions/emptied_applies",
        reloaded && applied == url && emptied.as_deref() == Some(&[][..]),
        &format!("reloaded={reloaded} got {applied}"),
    );

    // 4. removed
    compile(work, "||shop.test^$xmlhttprequest,removeparam=/^three=/");
    let reloaded = zshield::jni_api::reload_engine(handle, &work.join("compiled").to_string_lossy());
    let applied = removeparam(&filter_of(handle), url, RequestKind::Xhr);
    report.check(
        "transitions/readded_applies",
        reloaded && applied == "https://shop.test/p?one=1&two=2",
        &format!("reloaded={reloaded} got {applied}"),
    );
    let _ = std::fs::remove_file(work.join("compiled").join(zshield::compiled::EXTRAS_FILE));
    let reloaded = zshield::jni_api::reload_engine(handle, &work.join("compiled").to_string_lossy());
    let applied = removeparam(&filter_of(handle), url, RequestKind::Xhr);
    report.check(
        "transitions/deleted_applies",
        reloaded && state(handle).identities.extras.is_none() && applied == url,
        &format!("reloaded={reloaded} got {applied}"),
    );

    stop(handle, peer);
}

/// A corrupt artifact must not be recorded as installed, and the next good write must be picked up.
fn corruption_and_retry(report: &mut Report, work: &Path) {
    let url = "https://shop.test/p?keep=1&stay=2";
    compile(work, "||shop.test^$xmlhttprequest,removeparam=/^keep=/");
    let good = extras_bytes(work).expect("extras.txt exists");
    let (handle, peer) = start(work);
    let working = removeparam(&filter_of(handle), url, RequestKind::Xhr);
    report.check(
        "corrupt/baseline_rule_in_force",
        working == "https://shop.test/p?stay=2",
        &format!("got {working}"),
    );
    let identity_before = state(handle).identities.extras;
    let generation_before = state(handle).generation;

    std::fs::write(
        work.join("compiled").join(zshield::compiled::EXTRAS_FILE),
        b"ZSEXT\0\0\x01 not a real envelope",
    )
    .expect("corrupt extras.txt");
    let reloaded = zshield::jni_api::reload_engine(handle, &work.join("compiled").to_string_lossy());
    report.check(
        "corrupt/reload_reports_failure",
        !reloaded,
        "a component that could not be installed is not a successful reload",
    );
    let still = removeparam(&filter_of(handle), url, RequestKind::Xhr);
    report.check(
        "corrupt/rules_in_force_kept",
        still == "https://shop.test/p?stay=2",
        &format!("a checksum failure must not delete the rules, got {still}"),
    );
    let after = state(handle);
    report.check(
        "corrupt/identity_unchanged",
        after.identities.extras == identity_before,
        "the identity still describes the rules in force",
    );
    report.check(
        "corrupt/generation_unchanged",
        after.generation == generation_before,
        "a failed swap advances no generation",
    );

    // The retry: the *same* call, with the bytes the tunnel was asked for. The old code recorded the
    // corrupt set as loaded and would have skipped here forever.
    let repaired =
        zshield::compiled::Envelope::new(zshield::compiled::Artifact::Extras, good).encode();
    std::fs::write(
        work.join("compiled").join(zshield::compiled::EXTRAS_FILE),
        repaired,
    )
    .expect("restore extras.txt");
    let reloaded = zshield::jni_api::reload_engine(handle, &work.join("compiled").to_string_lossy());
    report.check(
        "corrupt/retry_succeeds",
        reloaded && state(handle).generation > generation_before,
        "rewriting the artifact must be picked up",
    );

    stop(handle, peer);
}

/// The fast path: twenty unchanged reloads keep the same rule objects, then a real change gets through.
fn unchanged_fast_path(report: &mut Report, work: &Path) {
    compile(work, "||example.test^$xmlhttprequest,removeparam=/^old=/");
    let (handle, peer) = start(work);
    let (dns, http, extras) = {
        let filter = filter_of(handle);
        (
            zshield::jni_api::handle_dns_filter(handle).expect("dns filter"),
            filter.engine(),
            filter.extras(),
        )
    };
    let generation_before = state(handle).generation;

    let mut stable = true;
    for _ in 0..20 {
        if !zshield::jni_api::reload_engine(handle, &work.join("compiled").to_string_lossy()) {
            stable = false;
            break;
        }
        let filter = filter_of(handle);
        stable &= Arc::ptr_eq(&dns, &zshield::jni_api::handle_dns_filter(handle).expect("dns"))
            && Arc::ptr_eq(&http, &filter.engine())
            && Arc::ptr_eq(&extras, &filter.extras());
    }
    report.check(
        "unchanged/objects_reused_20x",
        stable,
        "an unchanged artifact set must not rebuild any of the three rule sets",
    );
    report.check(
        "unchanged/generation_unchanged",
        state(handle).generation == generation_before,
        "a skipped reload installs nothing",
    );

    compile(work, "||example.test^$xmlhttprequest,removeparam=/^new=/");
    let reloaded = zshield::jni_api::reload_engine(handle, &work.join("compiled").to_string_lossy());
    let applied = removeparam(
        &filter_of(handle),
        "https://example.test/p?old=1&new=2&keep=3",
        RequestKind::Xhr,
    );
    report.check(
        "unchanged/change_still_lands",
        reloaded && applied == "https://example.test/p?old=1&keep=3",
        &format!("got {applied}"),
    );

    stop(handle, peer);
}

/// A/B alternation: the same two rule sets, swapped back and forth, must decide identically every time.
///
/// This is the stability property the task card asks for as "at least 20 unchanged reloads and some
/// extras A/B alternation": a reload path that is right once and drifts on repetition would pass the
/// single-shot controls above.
fn ab_alternation(report: &mut Report, work: &Path) {
    let a = "||ab.test^$xmlhttprequest,removeparam=/^alpha=/";
    let b = "||ab.test^$xmlhttprequest,removeparam=/^beta=/";
    let url = "https://ab.test/p?alpha=1&beta=2&keep=3";
    compile(work, a);
    let (handle, peer) = start(work);
    let expect_a = "https://ab.test/p?beta=2&keep=3";
    let expect_b = "https://ab.test/p?alpha=1&keep=3";
    report.check(
        "ab/baseline",
        removeparam(&filter_of(handle), url, RequestKind::Xhr) == expect_a,
        "",
    );

    let mut mismatches = 0;
    let mut returned_false = 0;
    for round in 0..12 {
        let (rule, expected) = if round % 2 == 0 { (b, expect_b) } else { (a, expect_a) };
        compile(work, rule);
        if !zshield::jni_api::reload_engine(handle, &work.join("compiled").to_string_lossy()) {
            returned_false += 1;
        }
        if removeparam(&filter_of(handle), url, RequestKind::Xhr) != expected {
            mismatches += 1;
        }
    }
    report.check(
        "ab/every_round_consistent",
        mismatches == 0 && returned_false == 0,
        &format!("{mismatches} mismatched rounds, {returned_false} failed reloads of 12"),
    );

    stop(handle, peer);
}

fn main() {
    let work: PathBuf = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("zshield-extras-reload-identity"));
    std::fs::create_dir_all(&work).expect("workdir");
    println!("workdir: {}", work.display());

    let mut report = Report {
        passed: 0,
        failed: 0,
    };
    // One directory per control: they each start from a different artifact set, and sharing one would
    // make every control depend on its predecessor's leftovers.
    for (name, run) in [
        ("extras_only", extras_only_change as fn(&mut Report, &Path)),
        ("transitions", transitions),
        ("corrupt", corruption_and_retry),
        ("unchanged", unchanged_fast_path),
        ("ab", ab_alternation),
    ] {
        let dir = work.join(name);
        std::fs::create_dir_all(&dir).expect("control dir");
        let resources = || {
            ["/proc/self/fd", "/proc/self/task"].map(|path| {
                std::fs::read_dir(path).expect("Linux proc resource census").count()
            })
        };
        let before = resources();
        run(&mut report, &dir);
        let after = resources();
        report.check(
            &format!("{name}/resources_released"),
            before == after,
            &format!("[fds, threads] {before:?} -> {after:?}"),
        );
    }

    println!(
        "\ncontrols: {} passed, {} failed",
        report.passed, report.failed
    );
    if report.failed > 0 {
        std::process::exit(1);
    }
}
