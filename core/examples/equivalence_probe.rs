//! Decide a large sample of real names with the shipped matcher and with the pre-M4b `HashSet`
//! reference, and report any disagreement (M4b acceptance criterion).
//!
//! Usage: `cargo run --release --example equivalence_probe -- <compiled-dir> [count]`
//!
//! The sample is not synthetic: it is every blocked domain in `dns.bin` (plus each one's parents, a
//! child of each, a look-alike sibling, and the upper-cased and dot-terminated spellings), which is
//! broader than the "10 000 URLs" the task card asks for and costs nothing to generate. The verdicts
//! come from the artifact actually loaded by the app, so the number proves the *shipped* structure,
//! not a test-only reimplementation.

use std::collections::HashSet;

use zshield::dns::filter::Verdict;

fn hash_set_suffix_match(domains: &HashSet<String>, name: &str) -> bool {
    if domains.is_empty() || name.is_empty() {
        return false;
    }
    if domains.contains(name) {
        return true;
    }
    let mut rest = name;
    while let Some(index) = rest.find('.') {
        rest = &rest[index + 1..];
        if rest.is_empty() {
            break;
        }
        if domains.contains(rest) {
            return true;
        }
    }
    false
}

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = std::path::PathBuf::from(args.next().unwrap_or_else(|| {
        eprintln!("usage: equivalence_probe <compiled-dir> [count]");
        std::process::exit(2);
    }));
    let limit: usize = args
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(10_000);

    let filter = zshield::compile::load_dns_filter(&dir)
        .expect("load dns.bin")
        .expect("dns.bin present");
    let stats = filter.stats();
    println!(
        "loaded dns.bin: {} block / {} exception rules",
        stats.block_rules, stats.exception_rules
    );

    // The reference sets, built from the same artifact through the public encoder. Re-encoding is
    // how the probe reaches the raw domain lists without a second accessor that only a test uses.
    let payload = filter.encode_payload();
    let mut block_suffix: HashSet<String> = HashSet::new();
    let mut block_exact: HashSet<String> = HashSet::new();
    let mut block_ips: HashSet<String> = HashSet::new();
    let mut allow_suffix: HashSet<String> = HashSet::new();
    let mut allow_exact: HashSet<String> = HashSet::new();
    let mut important_suffix: HashSet<String> = HashSet::new();
    let mut important_exact: HashSet<String> = HashSet::new();
    let mut priority_allow: HashSet<String> = HashSet::new();
    for line in payload.split(|byte| *byte == b'\n') {
        let Some(tab) = line.iter().position(|byte| *byte == b'\t') else {
            continue;
        };
        let (tag, domain) = (&line[..tab], &line[tab + 1..]);
        let Ok(domain) = std::str::from_utf8(domain) else {
            continue;
        };
        match tag {
            b"b" => block_suffix.insert(domain.to_string()),
            b"B" => block_exact.insert(domain.to_string()),
            b"i" => block_ips.insert(domain.to_string()),
            b"a" => allow_suffix.insert(domain.to_string()),
            b"A" => allow_exact.insert(domain.to_string()),
            b"m" => important_suffix.insert(domain.to_string()),
            b"M" => important_exact.insert(domain.to_string()),
            b"p" => priority_allow.insert(domain.to_string()),
            _ => continue,
        };
    }
    println!(
        "reference sets: {} block suffixes, {} exact, {} ips, {} exceptions",
        block_suffix.len(),
        block_exact.len(),
        block_ips.len(),
        allow_suffix.len() + allow_exact.len() + important_suffix.len() + important_exact.len(),
    );

    // `Filter::match_domain` normalises the name itself (trailing dot stripped, lowercased), and the
    // oracle below takes a normalised name — so the probe normalises once, exactly as the library
    // does internally, before asking either implementation. Comparing a raw name against the oracle
    // would only measure the two spellings of normalisation, not the two data structures.
    let normalize = |name: &str| -> String {
        name.trim().trim_end_matches('.').to_ascii_lowercase()
    };
    let oracle = |name: &str| -> Verdict {
        if name.is_empty() {
            return Verdict::Allow;
        }
        let looks_like_ip = name.contains(':')
            || (name.bytes().next().is_some_and(|b| b.is_ascii_digit())
                && name.bytes().all(|b| b.is_ascii_digit() || b == b'.'));
        if hash_set_suffix_match(&priority_allow, name) {
            return Verdict::Allow;
        }
        if looks_like_ip {
            return if block_ips.contains(name) {
                Verdict::Block
            } else {
                Verdict::Allow
            };
        }
        if hash_set_suffix_match(&important_suffix, name) || important_exact.contains(name) {
            return Verdict::Block;
        }
        if hash_set_suffix_match(&allow_suffix, name) || allow_exact.contains(name) {
            return Verdict::Allow;
        }
        if hash_set_suffix_match(&block_suffix, name) || block_exact.contains(name) {
            return Verdict::Block;
        }
        Verdict::Allow
    };

    let mut checked = 0usize;
    let mut disagreements: Vec<(String, Verdict, Verdict)> = Vec::new();
    let mut blocked = 0usize;
    for domain in block_suffix.iter().take(limit) {
        let labels: Vec<&str> = domain.split('.').collect();
        let mut probes: Vec<String> = Vec::with_capacity(8);
        for start in 0..labels.len() {
            let suffix = labels[start..].join(".");
            probes.push(suffix.clone());
            probes.push(format!("x.{suffix}"));
        }
        probes.push(format!("not{domain}"));
        probes.push(format!("{domain}.evil.example"));
        probes.push(format!("{domain}."));
        probes.push(domain.to_ascii_uppercase());
        for probe in probes {
            let shipped = filter.match_domain(&probe);
            let reference = oracle(&normalize(&probe));
            checked += 1;
            if shipped == Verdict::Block {
                blocked += 1;
            }
            if shipped != reference && disagreements.len() < 20 {
                disagreements.push((probe, shipped, reference));
            }
        }
    }
    for domain in block_ips.iter().chain(block_exact.iter()) {
        let shipped = filter.match_domain(domain);
        let reference = oracle(&normalize(domain));
        checked += 1;
        if shipped != reference && disagreements.len() < 20 {
            disagreements.push((domain.clone(), shipped, reference));
        }
    }

    println!("checked {checked} names ({blocked} blocked) against {limit} source domains");
    if disagreements.is_empty() {
        println!("RESULT: identical on every name");
    } else {
        println!("RESULT: {} DISAGREEMENTS", disagreements.len());
        for (name, shipped, reference) in disagreements {
            println!("  {name}: shipped {shipped:?} vs reference {reference:?}");
        }
        std::process::exit(1);
    }
}
