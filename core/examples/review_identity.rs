use std::sync::Arc;
use zshield::http::{
    decision::HttpFilter,
    head::{HttpRequest, Version},
    resource::RequestKind,
    rewrite::ModifierSource,
};
use zshield::https::{
    extras,
    modifiers::{collect_removeheader, HttpsModifiers},
};
fn main() {
    let cases = [
        ("parameter_case", "||shop.example^$removeparam=TRACK\n||shop.example^$removeparam=track,badfilter\n||shop.example^$removeparam=other", "https://shop.example/p?TRACK=1&other=2&keep=3", "https://shop.example/p?keep=3", RequestKind::Document),
        ("regex_case", "||shop.example^$removeparam=/^TAG=/\n||shop.example^$removeparam=/^tag=/,badfilter\n||shop.example^$removeparam=other", "https://shop.example/p?TAG=1&other=2&keep=3", "https://shop.example/p?keep=3", RequestKind::Document),
        ("type_alias", "||shop.example^$xmlhttprequest,removeparam=track\n||shop.example^$xhr,removeparam=track,badfilter\n||shop.example^$xmlhttprequest,removeparam=other", "https://shop.example/p?track=1&other=2&keep=3", "https://shop.example/p?track=1&keep=3", RequestKind::Xhr),
    ];
    let mut failed = 0;
    for (name, list, url, expected, kind) in cases {
        let mut set = adblock::lists::FilterSet::new(false);
        set.add_filter_list(list.to_string(), adblock::lists::ParseOptions::default());
        let filter = Arc::new(
            HttpFilter::new(adblock::Engine::new_with_filter_set(set))
                .with_extras(Arc::new(extras::collect([list]))),
        );
        let modifiers = HttpsModifiers::new(
            filter.clone(),
            Arc::new(collect_removeheader(std::iter::empty())),
            filter.extras_arc(),
        );
        let request = HttpRequest {
            method: "GET".into(),
            target: "/p".into(),
            version: Version::Http11,
            url: url.into(),
            host: "shop.example".into(),
            hostname: "shop.example".into(),
            referer: Some("https://shop.example/".into()),
            fetch_dest: None,
            fetch_site: None,
            fetch_user: None,
            accept: None,
            content_length: None,
            chunked: false,
            upgrade: false,
            expect_continue: false,
            head_len: 0,
        };
        let (_, engine_url, _) = filter.decide_full(&request, kind);
        let actual = modifiers
            .edits(&request, kind)
            .and_then(|e| e.url)
            .unwrap_or_else(|| url.into());
        println!(
            "{name}: {}\n expected={expected}\n actual={actual}\n engine={engine_url:?}",
            if actual == expected {
                "PASS"
            } else {
                failed += 1;
                "FAIL"
            }
        );
    }
    assert_eq!(failed, 0, "{failed} regressions");
}
