use std::sync::Arc;
use zshield::http::{decision::HttpFilter,head::{HttpRequest,Version},resource::RequestKind,rewrite::ModifierSource};
use zshield::https::{extras,modifiers::{HttpsModifiers,collect_removeheader}};
fn main() {
 let cases = [
 ("untyped_only", "||shop.example^$removeparam=track", "https://shop.example/p?track=1&keep=2", "https://shop.example/p?track=1&keep=2"),
 ("mixed_plus_other", "||shop.example^$xmlhttprequest,removeparam=track\n||shop.example^$removeparam=track\n||shop.example^$xmlhttprequest,removeparam=other", "https://shop.example/p?track=1&other=2&keep=3", "https://shop.example/p?keep=3"),
 ("scoped_untyped", "||shop.example^$domain=shop.example,removeparam=track\n||shop.example^$xmlhttprequest,removeparam=other", "https://shop.example/p?track=1&other=2&keep=3", "https://shop.example/p?track=1&keep=3"),
 ("value_sensitive", "||shop.example^$xmlhttprequest,removeparam=/^tag=drop$/\n||shop.example^$removeparam=unused\n||shop.example^$xmlhttprequest,removeparam=other", "https://shop.example/p?tag=drop&tag=keep&other=2&keep=1", "https://shop.example/p?tag=keep&keep=1"),
 ("typed_regex_and_untyped", "||shop.example^$xmlhttprequest,removeparam=/^track=1$/\n||shop.example^$removeparam=track\n||shop.example^$xmlhttprequest,removeparam=other", "https://shop.example/p?track=1&other=2&keep=3", "https://shop.example/p?keep=3"),
 ];
 let mut failed=0;
 for (name,list,url,expected) in cases {
  let mut set=adblock::lists::FilterSet::new(false);
  set.add_filter_list(list.to_string(),adblock::lists::ParseOptions::default());
  let filter=Arc::new(HttpFilter::new(adblock::Engine::new_with_filter_set(set)).with_extras(Arc::new(extras::collect([list]))));
  let m=HttpsModifiers::new(filter.clone(),Arc::new(collect_removeheader(std::iter::empty())),filter.extras_arc());
  let request=HttpRequest { method:"GET".into(),target:"/p".into(),version:Version::Http11,url:url.into(),host:"shop.example".into(),hostname:"shop.example".into(),referer:Some("https://shop.example/".into()),fetch_dest:Some("empty".into()),fetch_site:None,fetch_user:None,accept:None,content_length:None,chunked:false,upgrade:false,expect_continue:false,head_len:0 };
  let actual=m.edits(&request,RequestKind::Xhr).and_then(|e|e.url).unwrap_or_else(||url.into());
  println!("{name}: {}\n expected={expected}\n actual={actual}",if actual==expected {"PASS"}else{failed+=1;"FAIL"});
 }
 assert_eq!(failed,0,"{failed} semantic regressions");
}
