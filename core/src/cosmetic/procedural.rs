//! Procedural and action cosmetic rules: the ones that cannot be expressed in CSS at all.
//!
//! # What lands here
//!
//! `adblock` splits every cosmetic rule into two channels. A rule whose selector is plain CSS goes
//! into `hide_selectors` and becomes a `<style>` rule ([`crate::cosmetic::inject`]). Everything else
//! goes into `procedural_actions`, one **JSON string per rule**, in the shape
//! `{"selector":[<operator>...],"action":{"type":…,"arg":…}}`:
//!
//! | filter syntax | why it needs a script |
//! |---|---|
//! | `##.x:style(color:red)` (17,303 rules) | CSS can express it, but only after the selector matched — and the rule is stored in the procedural channel by the engine |
//! | `##div:has-text(Sponsored)` | CSS has no text matcher |
//! | `##.x:upward(2)` | CSS cannot walk *up* |
//! | `##.x:matches-css(display:block)` | computed style is not a CSS selector input |
//! | `##.x:xpath(//div)` | CSS has no XPath |
//! | `##.x:remove()` / `:remove-attr()` / `:remove-class()` (462 rules) | DOM mutation, not styling |
//!
//! # The one thing that must not go wrong
//!
//! These rules come from a subscription the user downloaded, so they are **untrusted input**, and the
//! script that acts on them is pasted into every page the user visits. Two rules follow from that and
//! are enforced structurally rather than by review:
//!
//! 1. **Rule content is data, never code.** The engine's JSON goes into one JavaScript array literal
//!    and is only ever read (`rule.selector`, `rule.action`). No part of a rule is interpolated into
//!    the runtime source — the runtime is a compile-time constant ([`RUNTIME`]) with exactly one hole
//!    for the array.
//! 2. **The literal cannot end the element.** `</` becomes `<\/` and `<!--` becomes `<\!--`
//!    ([`crate::cosmetic::inject::escape_script_body_into`]), which is the same defence the scriptlet
//!    bundle uses. Both are no-ops to a JavaScript parser inside a string, so the data arrives intact.
//!
//! A third check sits in front: a rule whose style or selector would escape its own syntax is dropped
//! at build time ([`Screen`]), because the JSON is data *and* the values in it reach `setProperty` and
//! `querySelectorAll`, where a `}` or a `<` has no business being.
//!
//! # Why a budget
//!
//! `:has-text()` and `:matches-css()` are O(elements × rules) on a real page, and a page that mutates
//! continuously (a feed, a chat) re-runs them on every mutation. uBlock Origin settles this with a
//! per-rule time budget and this runtime copies that design: a rule that overruns is disabled for the
//! rest of the document's life and *earns its budget back* only after two seconds of not being asked,
//! so a temporarily heavy page recovers instead of staying un-filtered.

use std::collections::BTreeSet;

use adblock::filters::cosmetic::CosmeticFilterOperator;

use crate::cosmetic::inject::escape_script_body_into;
use crate::cosmetic::validate::Verdict;

/// Upper bound on how many rules one document is given.
///
/// A subscription can carry thousands of procedural rules for one hostname in principle. The cap is
/// not a correctness requirement — it is there so the injected script (and the JSON in it) cannot grow
/// without bound on a document, which would cost more than the rules are worth. Real lists stay two
/// orders of magnitude below it: the busiest hostname measured across the built-in catalog carries
/// fewer than 40.
pub const MAX_RULES_PER_DOCUMENT: usize = 512;

/// One rule that survived screening, ready to be serialized into the script.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rule {
    /// `false` when the action mutates the DOM (`remove*`), `true` when it styles the element.
    ///
    /// Only used for the counters: a document that had a rule apply is reported once either way.
    pub styling: bool,
    /// The JSON the engine produced, already screened.
    pub json: String,
}

/// What screening one document's procedural rules produced.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ScreenResult {
    /// Rules to inject, deduplicated and ordered.
    pub rules: Vec<Rule>,
    /// Rules the engine produced.
    pub offered: usize,
    /// Rules dropped because they could not be injected safely.
    pub dropped: usize,
}

impl ScreenResult {
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// The tasks one screening pass needs, so it can be driven from a unit test without an engine.
pub struct Screen<'a> {
    /// Whether a selector is one a browser parses. See [`crate::cosmetic::validate`].
    pub validate: &'a dyn Fn(&str) -> Verdict,
}

impl Screen<'_> {
    /// Turn the engine's `procedural_actions` into the rules the script will be given.
    ///
    /// Every rule is parsed back out of its JSON rather than threaded through as text, because the
    /// screening has to look at the selector and the style separately: JSON quoting would hide a `}`
    /// inside an escape and let it through.
    pub fn apply(&self, actions: &std::collections::HashSet<String>) -> ScreenResult {
        let mut rules: Vec<Rule> = Vec::new();
        let mut dropped = 0usize;
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for action in actions {
            let Some(rule) = self.screen_one(action) else {
                dropped += 1;
                continue;
            };
            if rules.len() >= MAX_RULES_PER_DOCUMENT {
                dropped += 1;
                continue;
            }
            if seen.insert(rule.json.clone()) {
                rules.push(rule);
            }
        }
        rules.sort();
        ScreenResult {
            rules,
            offered: actions.len(),
            dropped,
        }
    }

    /// Screen one engine rule, or say why it is unusable.
    fn screen_one(&self, action: &str) -> Option<Rule> {
        let parsed: ProceduralOrAction = serde_json::from_str(action).ok()?;
        if parsed.selector.is_empty() {
            return None;
        }
        // Every plain-CSS part must be a selector a browser parses. A procedural rule whose CSS half
        // is broken would throw inside `querySelectorAll`, which the runtime catches — but catching it
        // per rule per mutation is a cost with no benefit, so the rule is dropped once here.
        for operator in &parsed.selector {
            if let CosmeticFilterOperator::CssSelector(selector) = operator {
                let selector = selector.trim();
                if selector.is_empty() {
                    continue;
                }
                if (self.validate)(selector) != Verdict::Usable {
                    return None;
                }
            }
        }
        if let Some(action) = parsed.action.as_ref() {
            if !action.is_safe() {
                return None;
            }
        }
        // A NUL byte would truncate the string at the JSON boundary in some parsers and cannot occur in
        // a selector a list author wrote; anything else in the arguments is handled by the escaping in
        // `script_element`, which is where the guarantee actually lives. Refusing `</` here instead
        // would silently lose real rules (`##div:has-text(</script>)` is in the wild) for a risk the
        // escaper already removes.
        if action.contains('\u{0}') {
            return None;
        }
        Some(Rule {
            styling: !matches!(
                parsed.action,
                Some(EngineAction::Remove)
                    | Some(EngineAction::RemoveAttr(_))
                    | Some(EngineAction::RemoveClass(_))
            ),
            json: action.to_string(),
        })
    }
}

/// The engine's JSON contract, mirrored so the fields can be inspected.
///
/// Only the two fields screening needs are mirrored: threading the whole `CosmeticFilterOperator`
/// enum through would mean re-serializing it, and the exact JSON the engine produced is what the
/// runtime is given.
#[derive(Debug, serde::Deserialize)]
struct ProceduralOrAction {
    selector: Vec<CosmeticFilterOperator>,
    #[serde(default)]
    action: Option<EngineAction>,
}

/// The engine's action, mirrored for the same reason.
///
/// `RemoveAttr` and `RemoveClass` carry the attribute/class name; it is not read here because the JSON
/// the runtime receives is the engine's own line, but it is kept so the mirror stays faithful to the
/// contract it mirrors.
#[allow(dead_code)]
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "type", content = "arg")]
#[serde(rename_all = "kebab-case")]
enum EngineAction {
    Remove,
    Style(String),
    RemoveAttr(String),
    RemoveClass(String),
}

impl EngineAction {
    /// Whether this action can be handed to the runtime.
    ///
    /// `:style()` is the only one whose argument is pasted into a property assignment, so it is the
    /// only one that has to be checked for the characters that would escape a declaration block. The
    /// engine already refuses `url(`, `image-set(`, `\` and `/*` (its `is_valid_css_style`), and the
    /// four below are this module's own: a `}` would end the declaration, a `<` would end the
    /// `<script>` element, and a `;` is legal but a `!important` injection through it is not something
    /// a hide rule needs.
    fn is_safe(&self) -> bool {
        match self {
            EngineAction::Style(style) => {
                !style.contains(['}', '{', '<'])
                    && !style.contains('\n')
                    && !style.contains('\r')
            }
            EngineAction::Remove | EngineAction::RemoveAttr(_) | EngineAction::RemoveClass(_) => true,
        }
    }
}

/// Build the `<script>` element that applies `rules`, or `None` when there are none.
///
/// The element is emitted exactly like the scriptlet bundle: same escaping, same optional nonce, same
/// `data-zshield` marker so a reader (and `docs/TESTING.md`) can tell injected markup from the page's.
pub fn script_element(rules: &[Rule], nonce: Option<&str>) -> Option<String> {
    if rules.is_empty() {
        return None;
    }
    // The array literal is the *only* place rule text enters the script, and it enters as data: the
    // runtime concatenated after it never splices any part of it into code, only reads fields off it.
    let body = script_body(rules);

    let mut out = String::with_capacity(body.len() + 96);
    out.push_str("<script");
    if let Some(nonce) = nonce {
        out.push_str(" nonce=\"");
        out.push_str(nonce);
        out.push('"');
    }
    out.push_str(" data-zshield=\"procedural\">\n");
    escape_script_body_into(&body, &mut out);
    out.push_str("\n</script>\n");
    Some(out)
}

/// A one-line description of the runtime for the delivery note and `statsJson`.
pub fn runtime_bytes() -> usize {
    RUNTIME.len()
}

/// The script body (the array literal plus the runtime) without the `<script>` wrapper.
///
/// Split out because the escaping tests care about the body and the element tests care about the tag;
/// keeping one builder for both is what guarantees they describe the same bytes.
fn script_body(rules: &[Rule]) -> String {
    let mut json = String::with_capacity(rules.iter().map(|rule| rule.json.len() + 1).sum::<usize>() + 2);
    json.push('[');
    for (index, rule) in rules.iter().enumerate() {
        if index > 0 {
            json.push(',');
        }
        json.push_str(&rule.json);
    }
    json.push(']');
    // Wrapped in a function so `R` stays local: a top-level `const R` would be a global lexical
    // binding, and any page script that later declares its own top-level `R` (`var R`, `let R`,
    // `class R`) would fail with a redeclaration `SyntaxError` — breaking the page we are filtering.
    format!("(function(){{const R={json};\n{RUNTIME}\n}})();")
}

/// The runtime. A compile-time constant, so no rule text can ever reach it.
///
/// # Shape
///
/// `R` is the array built by [`script_element`]. Each entry is
/// `{"selector":[{type,arg}…], "action"?:{type,arg}}`, exactly as `adblock` serializes it.
///
/// The selector list is a **flattened, ordered** sequence: runs of `css-selector` separated by
/// operators. That is not uBlock Origin's model (one CSS selector plus a task list), so the walk
/// below is written for this one:
///
/// - a run is a `querySelectorAll` from the document the first time, and after that a *refinement*
///   of the nodes reached so far — `:has(…)`-style continuations filter the node itself, a leading
///   combinator walks to its descendants;
/// - an operator transposes the node set exactly where it appears.
///
/// # What it deliberately does not do
///
/// `:watch-attr`, `:others`, `:shadow`, `:matches-media` and `:matches-prop` are not reachable from
/// `adblock`'s parser, so they are absent rather than stubbed. `:if` / `:if-not` / `:has` are plain
/// CSS `:has()` now that `css-validation` is on, so they arrive as selectors and need no operator.
const RUNTIME: &str = r#"(function(){
'use strict';
var D=document,W=window;
if(!D.documentElement||!R||!R.length)return;

// One style element, filled through CSSOM. CSSOM `insertRule` is not subject to `style-src`, so this
// keeps working on pages whose CSP would refuse an inline <style> that carried no nonce.
var sheetEl=null,styleTokens=Object.create(null),tokenSeq=0,allTokens=[];
function styleSheet(){
  if(sheetEl!==null)return sheetEl.sheet;
  var el=D.createElement('style');
  el.setAttribute('data-zshield','procedural');
  var cs=D.currentScript;
  if(cs&&cs.nonce)el.setAttribute('nonce',cs.nonce);
  (D.head||D.documentElement).appendChild(el);
  sheetEl=el;
  return el.sheet;
}
// The token for one style string, or null when the browser refuses the declaration. `!important`
// survives `insertRule`, so a rule that says `display:block !important` keeps its priority.
function styleToken(css){
  var known=styleTokens[css];
  if(known!==undefined)return known;
  var sh;
  try{sh=styleSheet();}catch(e){return null;}
  if(!sh)return null;
  var token='zs'+(++tokenSeq);
  try{sh.insertRule('['+token+']{'+css+'}',sh.cssRules.length);}catch(e){return null;}
  styleTokens[css]=token;
  allTokens.push(token);
  return token;
}

// uBO's rule: `a/b/c` is a regex, anything else a literal, matched exactly or as a substring.
function rx(s,exact){
  if(s===''||s===undefined||s===null)return /^/;
  var m=/^\/(.+)\/([imsu]*)$/.exec(s);
  if(m!==null){try{return new RegExp(m[1],m[2]||undefined);}catch(e){return /^/;}}
  var lit=s.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
  return new RegExp(exact?'^'+lit+'$':lit);
}
function textOf(node){return node.textContent||'';}

// One operator: takes the current node set, returns the next. Unknown operators yield nothing, which
// stops the rule rather than letting it apply to the wrong elements.
var OPS=Object.create(null);
OPS['has-text']=function(arg,nodes){
  var re=rx(arg),out=[];
  for(var i=0;i<nodes.length;i++)if(re.test(textOf(nodes[i])))out.push(nodes[i]);
  return out;
};
OPS['min-text-length']=function(arg,nodes){
  var min=parseInt(arg,10)||0,out=[];
  for(var i=0;i<nodes.length;i++)if(textOf(nodes[i]).length>=min)out.push(nodes[i]);
  return out;
};
OPS['matches-attr']=function(arg,nodes){
  var eq=arg.indexOf('='),reAttr,reVal=null;
  if(eq===-1){reAttr=rx(arg,true);}else{reAttr=rx(arg.slice(0,eq),true);reVal=rx(arg.slice(eq+1),true);}
  var out=[];
  for(var i=0;i<nodes.length;i++){
    var n=nodes[i];
    if(typeof n.getAttributeNames!=='function')continue;
    var names=n.getAttributeNames();
    for(var j=0;j<names.length;j++){
      if(!reAttr.test(names[j]))continue;
      if(reVal===null||reVal.test(n.getAttribute(names[j])||'')){out.push(n);break;}
    }
  }
  return out;
};
function matchesCss(arg,nodes,pseudo){
  var colon=arg.indexOf(':');
  if(colon===-1)return [];
  var name=arg.slice(0,colon).trim(),re=rx(arg.slice(colon+1).trim()),out=[];
  for(var i=0;i<nodes.length;i++){
    var st=null;
    try{st=W.getComputedStyle(nodes[i],pseudo);}catch(e){continue;}
    if(st===null)continue;
    var value=st.getPropertyValue(name);
    if(value!==''&&re.test(value))out.push(nodes[i]);
  }
  return out;
}
OPS['matches-css']=function(arg,nodes){return matchesCss(arg,nodes,null);};
OPS['matches-css-before']=function(arg,nodes){return matchesCss(arg,nodes,'::before');};
OPS['matches-css-after']=function(arg,nodes){return matchesCss(arg,nodes,'::after');};
OPS['matches-path']=function(arg,nodes){
  var re=rx(arg.replace(/[^\x00-\x7F]/g,function(c){return encodeURIComponent(c);}));
  return re.test(W.location.pathname+W.location.search)?nodes:[];
};
OPS['upward']=function(arg,nodes){
  var n=parseInt(arg,10),sel=isNaN(n)?String(arg):'',out=[];
  for(var i=0;i<nodes.length;i++){
    var node=nodes[i];
    if(sel!==''){var parent=node.parentElement;if(!parent)continue;var hit=parent.closest(sel);if(hit)out.push(hit);}
    else{var left=n;while(left>0){node=node.parentElement;if(!node)break;left--;}if(node&&left===0)out.push(node);}
  }
  return out;
};
OPS['xpath']=function(arg,nodes){
  var out=[];
  for(var i=0;i<nodes.length;i++){
    var r=null;
    try{r=D.evaluate(arg,nodes[i],null,XPathResult.UNORDERED_NODE_SNAPSHOT_TYPE,null);}catch(e){continue;}
    if(!r)continue;
    for(var j=0;j<r.snapshotLength;j++){var it=r.snapshotItem(j);if(it&&it.nodeType===1)out.push(it);}
  }
  return out;
};

// One CSS run, applied to the nodes reached so far. The first run queries the document; every later
// run is a *refinement*: a continuation that starts with a combinator is a descendant/child step, and
// anything else filters the node itself (`:has(…)`, `:not(…)`, `:empty`, an attribute test, …).
function cssRun(sel,nodes,first){
  var out=[],i;
  if(first){
    try{return Array.prototype.slice.call(D.querySelectorAll(sel));}catch(e){return [];}
  }
  var lead=sel.replace(/^[ \t\r\n]+/,'');
  if(lead==='')return [];
  var c0=lead.charCodeAt(0);
  var isStep=(c0===0x3E||c0===0x2B||c0===0x7E||lead.length!==sel.length);
  for(i=0;i<nodes.length;i++){
    var base=nodes[i];
    if(base.nodeType!==1)continue;
    try{
      if(isStep){var more=base.querySelectorAll(':scope '+lead);for(var j=0;j<more.length;j++)out.push(more[j]);}
      else if(base.matches(sel))out.push(base);
    }catch(e){return [];}
  }
  return out;
}

function selectorNodes(rule){
  var parts=rule.selector;
  // Every rule starts from the document: a rule may begin with an operator
  // (`##:matches-path(/x/) .ad`), and that operator has to see the root, not be skipped.
  var nodes=[D],firstCss=true;
  for(var i=0;i<parts.length;i++){
    var p=parts[i];
    if(p&&p.type==='css-selector'){
      nodes=cssRun(p.arg,nodes,firstCss);
      firstCss=false;
    }else{
      var op=OPS[p&&p.type];
      if(op===undefined)return [];
      try{nodes=op(p.arg,nodes,p.type);}catch(e){return [];}
    }
    if(nodes.length===0)return [];
  }
  // A rule made of operators only (`:matches-path(…)` with no CSS selector) matches the root itself,
  // which is not a hideable element.
  if(firstCss)return [];
  return nodes;
}

// A node the previous pass styled and this one did not stops matching: release it. uBO does the same
// (`unprocessNodes`), and it is what keeps a single-page app from leaving holes behind.
function unstyle(node){
  for(var i=0;i<allTokens.length;i++)node.removeAttribute(allTokens[i]);
}

function commit(){
  var now=Date.now(),t0=now;
  var styled=new Set();
  for(var i=0;i<R.length;i++){
    var s=state[i];
    if(s.dead)continue;
    var allowance=Math.floor((t0-s.last)/2000);
    if(allowance>=1){s.budget+=allowance*50;if(s.budget>200)s.budget=200;s.last=t0;}
    if(s.budget<=0)continue;
    var nodes=selectorNodes(s.rule);
    var t1=Date.now();
    s.budget-=t1-t0;
    if(s.budget<-500){s.dead=true;continue;}
    t0=t1;
    if(nodes.length===0)continue;
    s.hit=true;
    var action=s.rule.action,type=action&&action.type||'',arg=action&&action.arg;
    if(type==='remove'){
      for(var r=0;r<nodes.length;r++){var parent=nodes[r].parentNode;if(parent)parent.removeChild(nodes[r]);nodes[r].textContent='';}
      continue;
    }
    if(type==='remove-attr'){
      var reAttr=rx(arg,true);
      for(var a=0;a<nodes.length;a++){
        var n=nodes[a];
        if(typeof n.getAttributeNames!=='function')continue;
        var names=n.getAttributeNames();
        for(var k=0;k<names.length;k++)if(reAttr.test(names[k]))n.removeAttribute(names[k]);
      }
      continue;
    }
    if(type==='remove-class'){
      var reClass=rx(arg,true);
      for(var c=0;c<nodes.length;c++){
        var cl=nodes[c].classList;
        if(!cl)continue;
        for(var m=cl.length-1;m>=0;m--)if(reClass.test(cl[m]))cl.remove(cl[m]);
      }
      continue;
    }
    // `style`, or no action at all: hide it. Any other action type is one this runtime does not know.
    if(type!==''&&type!=='style')continue;
    var css=(type==='style'&&typeof arg==='string'&&arg!=='')?arg:'display:none !important';
    var token=styleToken(css);
    for(var n2=0;n2<nodes.length;n2++){
      var node=nodes[n2];
      if(token===null){try{node.style.setProperty('display','none','important');}catch(e){}}
      else node.setAttribute(token,'');
      styled.add(node);
    }
  }
  styledPrev.forEach(function(node){if(!styled.has(node))unstyle(node);});
  styledPrev=styled;
}
var styledPrev=new Set();
var state=R.map(function(rule){return{rule:rule,budget:200,last:0,dead:false,hit:false};});

var timer=0;
function schedule(){
  if(timer!==0)return;
  // Coalesce mutation bursts: at most one pass per 50 ms. Each pass re-runs every rule against the
  // document, and a page that mutates continuously would otherwise keep the CPU busy.
  timer=W.setTimeout(function(){timer=0;try{commit();}catch(e){}},50);
}
function start(){
  try{commit();}catch(e){}
  if(typeof MutationObserver==='function'){
    try{
      new MutationObserver(schedule).observe(D.documentElement,{
        childList:true,subtree:true,attributes:true,
        attributeFilter:['class','id','style','hidden','aria-hidden','data-ad','data-ad-slot']
      });
    }catch(e){}
  }
}
start();
if(D.readyState==='loading')D.addEventListener('DOMContentLoaded',function(){try{commit();}catch(e){}},{once:true});
})();"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cosmetic::validate::{SelectorValidator, Verdict};

    fn screen(actions: &[&str]) -> ScreenResult {
        let validator = SelectorValidator::new();
        let check = |selector: &str| validator.check(selector);
        let screen = Screen { validate: &check };
        let set: std::collections::HashSet<String> =
            actions.iter().map(|a| a.to_string()).collect();
        screen.apply(&set)
    }

    fn rule(selector: &str, action: &str) -> String {
        format!(r#"{{"selector":{selector},"action":{action}}}"#)
    }

    #[test]
    fn a_style_action_becomes_one_rule() {
        let result = screen(&[&rule(
            r#"[{"type":"css-selector","arg":".ad"}]"#,
            r#"{"type":"style","arg":"margin:0 !important"}"#,
        )]);
        assert_eq!(result.dropped, 0);
        assert_eq!(result.offered, 1);
        assert_eq!(result.rules.len(), 1);
        assert!(result.rules[0].styling);
    }

    #[test]
    fn a_remove_action_is_not_styling() {
        let result = screen(&[&rule(
            r#"[{"type":"css-selector","arg":".ad"}]"#,
            r#"{"type":"remove"}"#,
        )]);
        assert_eq!(result.rules.len(), 1);
        assert!(!result.rules[0].styling);
    }

    #[test]
    fn a_rule_whose_css_half_does_not_parse_is_dropped() {
        // The selector the engine produced still has to be one a browser parses. A subscription can
        // produce a half-broken rule (`:contains()` is not CSS) and it must not reach
        // `querySelectorAll` on every mutation.
        let result = screen(&[&rule(
            r#"[{"type":"css-selector","arg":"div:contains(Refresh)"}]"#,
            r#"{"type":"style","arg":"color:red"}"#,
        )]);
        assert_eq!(result.offered, 1);
        assert_eq!(result.rules.len(), 0);
        assert_eq!(result.dropped, 1);
    }

    #[test]
    fn a_style_that_would_escape_its_rule_is_dropped() {
        for style in [
            "color:red}body{display:none",
            "color:red</style><script>x</script>",
        ] {
            let result = screen(&[&rule(
                r#"[{"type":"css-selector","arg":".ad"}]"#,
                &format!(r#"{{"type":"style","arg":"{style}"}}"#),
            )]);
            assert!(result.rules.is_empty(), "{style} must be dropped");
            assert_eq!(result.dropped, 1);
        }
    }

    #[test]
    fn a_rule_carrying_a_script_end_tag_is_kept_and_escaped() {
        // Dropping it would be safe but wrong: `##div:has-text(</script>)` is a real rule form, and
        // the escaper already makes it inert. The rule must survive screening and reach the script in
        // a form an HTML parser does not read as an end tag.
        let result = screen(&[&rule(
            r#"[{"type":"css-selector","arg":".ad"},{"type":"has-text","arg":"a</script><img src=x onerror=alert(1)>"}]"#,
            r#"{"type":"remove"}"#,
        )]);
        assert_eq!(result.dropped, 0);
        assert_eq!(result.rules.len(), 1);
        let element = script_element(&result.rules, None).expect("a script");
        assert!(
            !element.to_ascii_lowercase().contains("</script><img"),
            "the escaped element must not carry the raw sequence: {element}"
        );
        assert!(element.contains("<\\/script><img"));
    }

    #[test]
    fn the_injected_script_does_not_depend_on_iteration_order() {
        // The same rule set must produce the same bytes on every page, or the injected script (and the
        // `rejectedSelectors` counter that measures it) would vary run to run for no reason.
        let one = rule(
            r#"[{"type":"css-selector","arg":".ad"}]"#,
            r#"{"type":"style","arg":"color:red"}"#,
        );
        let two = rule(
            r#"[{"type":"css-selector","arg":".banner"}]"#,
            r#"{"type":"remove"}"#,
        );
        let first = screen(&[&one, &two]);
        let second = screen(&[&two, &one]);
        assert_eq!(first, second);
        assert_eq!(first.rules.len(), 2);
        let script_a = script_element(&first.rules, None);
        let script_b = script_element(&second.rules, None);
        assert_eq!(script_a, script_b);
    }

    #[test]
    fn the_document_cap_is_a_cap_not_a_crash() {
        let actions: Vec<String> = (0..(MAX_RULES_PER_DOCUMENT + 20))
            .map(|index| {
                rule(
                    &format!(r#"[{{"type":"css-selector","arg":".ad-{index}"}}]"#),
                    r#"{"type":"remove"}"#,
                )
            })
            .collect();
        let refs: Vec<&str> = actions.iter().map(String::as_str).collect();
        let result = screen(&refs);
        assert_eq!(result.rules.len(), MAX_RULES_PER_DOCUMENT);
        assert_eq!(result.dropped, 20);
    }

    // ---------------------------------------------------------------------------------------
    // The injected script's shape. These are the acceptance criteria that are about the *wire*,
    // not about the runtime's behaviour (which needs a DOM — `docs/TESTING.md` covers the device
    // run for that).
    // ---------------------------------------------------------------------------------------

    #[test]
    fn the_script_carries_the_rules_as_data_and_nothing_else() {
        let result = screen(&[&rule(
            r#"[{"type":"css-selector","arg":".ad"}]"#,
            r#"{"type":"style","arg":"color:red"}"#,
        )]);
        let script = script_element(&result.rules, Some("n0nce")).expect("a script");
        assert!(script.starts_with("<script nonce=\"n0nce\" data-zshield=\"procedural\">"));
        assert!(script.ends_with("</script>\n"));
        // The rules appear exactly once, inside the array literal.
        assert!(script.contains(r#"const R=[{"selector":[{"type":"css-selector","arg":".ad"}],"action":{"type":"style","arg":"color:red"}}];"#));
        assert_eq!(script.matches("color:red").count(), 1);
    }

    #[test]
    fn a_rule_containing_a_script_end_tag_cannot_close_the_element() {
        // The engine's JSON would contain `</script>`; the emitted element must contain it only in a
        // form a JavaScript parser reads back as the same string, and an HTML parser does not read as
        // an end tag.
        let body = script_body(&[Rule {
            styling: true,
            json: r#"{"selector":[{"type":"css-selector","arg":".ad"},{"type":"has-text","arg":"</script><b>x</b>"}]}"#
                .to_string(),
        }]);
        let mut escaped = String::new();
        escape_script_body_into(&body, &mut escaped);
        assert!(!escaped.to_ascii_lowercase().contains("</script"));
        assert!(escaped.contains("<\\/script"));
        // And the escaping is transparent to JavaScript: `<\/` is `</`.
        assert!(escaped.contains("<\\/script><b>x<\\/b>"));
    }

    #[test]
    fn quoted_and_multi_line_arguments_survive_escaping() {
        let rule = Rule {
            styling: false,
            json: r#"{"selector":[{"type":"css-selector","arg":"[title=\"a b\"]"}]}"#.to_string(),
        };
        let element = script_element(std::slice::from_ref(&rule), None).expect("a script");
        assert!(element.contains(r#"[title=\"a b\"]"#));
        // No nonce: the element must not carry an empty `nonce=""`, which a CSP would reject.
        assert!(element.starts_with("<script data-zshield=\"procedural\">"));
    }

    #[test]
    fn the_rules_are_local_to_the_injected_script() {
        // A top-level `const R` would be a global lexical binding that a page's own `let R` collides
        // with. The body must be one expression statement that keeps `R` inside a function.
        let rules = vec![Rule {
            json: r#"{"selector":[{"type":"css-selector","arg":".ad"}]}"#.to_string(),
            styling: true,
        }];
        let body = script_body(&rules);
        assert!(body.starts_with("(function(){const R=["), "{body}");
        assert!(body.trim_end().ends_with("})();"), "the wrapper must close");
    }

    #[test]
    fn no_rules_means_no_element() {
        assert!(script_element(&[], Some("nonce")).is_none());
    }

    #[test]
    fn the_runtime_is_self_contained_and_syntactically_a_program() {
        // The runtime is a compile-time constant, so a typo in it would ship to every page and fail
        // silently in the browser. These are the structural properties a static check can assert
        // without a JavaScript engine; the behavioural run is in `docs/TESTING.md` (§"过程式运行时")
        // and `scripts/check-procedural-runtime.mjs`, which executes it against a DOM.
        assert!(RUNTIME.starts_with("(function(){"), "the runtime is one IIFE");
        assert!(RUNTIME.trim_end().ends_with("})();"), "the IIFE must close");
        // Balanced braces outside strings and regexes would be a parse error, so the counts are a
        // cheap proxy: every `{` the runtime opens is one it closes.
        let opens = RUNTIME.matches('{').count();
        let closes = RUNTIME.matches('}').count();
        assert_eq!(opens, closes, "unbalanced braces in the runtime");
        let parens_open = RUNTIME.matches('(').count();
        let parens_close = RUNTIME.matches(')').count();
        assert_eq!(parens_open, parens_close, "unbalanced parentheses");
        // No rule text can be spliced in: the only hole is the array literal `script_element` writes
        // *before* this constant, and the runtime has no template literal at all. (`${` on its own
        // would be a false positive: `String.replace` uses it inside a regex character class.)
        // Backticks would make a template literal, which is the one construct that could splice a
        // value into code. They appear in the runtime's comments, so the check is on the code lines.
        let code: String = RUNTIME
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !code.contains('`'),
            "the runtime must contain no template literal"
        );
        assert!(!RUNTIME.contains("function eval"), "the runtime must not evaluate strings");
        assert!(!RUNTIME.contains("eval("), "the runtime must not evaluate strings");
        assert!(!RUNTIME.contains("innerHTML"), "the runtime must not parse markup");
        assert!(!RUNTIME.contains("document.write"), "the runtime must not parse markup");
    }

    #[test]
    fn screening_uses_the_same_verdict_the_style_path_uses() {
        // A selector that is fine as CSS must pass, so a `:style()` rule on an ordinary selector is
        // not lost to an over-eager screen.
        let validator = SelectorValidator::new();
        let check = |selector: &str| validator.check(selector);
        let screen = Screen { validate: &check };
        let set: std::collections::HashSet<String> = [
            rule(
                r#"[{"type":"css-selector","arg":"div#case-1-elemhide > .test-banner"}]"#,
                r#"{"type":"style","arg":"display:block !important;"}"#,
            ),
        ]
        .into_iter()
        .collect();
        let result = screen.apply(&set);
        assert_eq!(result.rules.len(), 1);
        assert_eq!(check(".ad"), Verdict::Usable);
    }
}
