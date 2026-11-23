#!/usr/bin/env node
/**
 * Execute the injected procedural runtime against a real DOM.
 *
 *   node scripts/check-procedural-runtime.mjs
 *
 * The runtime lives in `core/src/cosmetic/procedural.rs` as the constant `RUNTIME`, and it is the one
 * piece of this app that runs inside the user's pages: a syntax error there is invisible in Rust (it
 * is a string) and would simply make every procedural rule silently do nothing. This script extracts
 * the constant, checks it parses, and drives it with jsdom against a table of cases covering every
 * operator the engine can produce.
 *
 * The case table is deliberately written against the *filter-list* meaning of each operator
 * (`:has-text`, `:upward`, `:remove()`, …), not against the implementation: a case failing means the
 * page the user sees is wrong, which is the only thing worth testing here.
 *
 * `jsdom` is a dev dependency, not part of the app: `npm install jsdom` in the repository root (or
 * wherever this script is run from) is enough. The script exits 2 when it is missing rather than
 * pretending to pass, so a CI-less project cannot "pass" by not running.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(here, '..', 'core', 'src', 'cosmetic', 'procedural.rs'), 'utf8');

/** Pull `RUNTIME` out of the Rust source: the raw string between `r#"` and `"#`. */
function extractRuntime(text) {
    const start = text.indexOf('const RUNTIME: &str = r#"(function(){');
    if (start === -1) throw new Error('RUNTIME constant not found in procedural.rs');
    const bodyStart = text.indexOf('r#"', start) + 3;
    const bodyEnd = text.indexOf('"#;', bodyStart);
    if (bodyEnd === -1) throw new Error('unterminated RUNTIME raw string');
    return text.slice(bodyStart, bodyEnd);
}

let JSDOM;
try {
    ({ JSDOM } = await import('jsdom'));
} catch {
    console.error('jsdom is not installed: run `npm install jsdom` first');
    process.exit(2);
}

const runtime = extractRuntime(source);

/** Build a page, run the runtime with `rules`, and return the window. */
function apply(rules, html, options = {}) {
    const dom = new JSDOM(
        `<!doctype html><html><head><title>t</title></head><body>${html}</body></html>`,
        {
            runScripts: 'outside-only',
            pretendToBeVisual: true,
            url: 'https://site.example' + (options.path ?? '/page'),
        },
    );
    const window = dom.window;
    // Same composition as `script_body` in procedural.rs: the rules are local to a wrapper function.
    window.eval(`(function(){const R=${JSON.stringify(rules)};\n${runtime}\n})();`);
    return window;
}

const cases = [];
const test = (name, fn) => cases.push({ name, fn });

/// The attribute the runtime stamps on a styled element, read off the element itself.
const marks = (node) => node.getAttributeNames().filter((name) => name.startsWith('zs'));

/** The rules the runtime inserted, as CSS text (jsdom exposes CSSOM, not `textContent`). */
const sheetRules = (window) =>
    [...window.document.querySelector('style[data-zshield="procedural"]').sheet.cssRules]
        .map((rule) => rule.cssText)
        .join('\n');

test(':style() applies the declaration to the matched element only', () => {
    const window = apply(
        [{ selector: [{ type: 'css-selector', arg: '.promo' }], action: { type: 'style', arg: 'margin:0 !important' } }],
        '<div class="promo">p</div><div class="other">o</div>',
    );
    const promo = window.document.querySelector('.promo');
    if (marks(promo).length !== 1) return `marks=${JSON.stringify(promo.getAttributeNames())}`;
    if (marks(window.document.querySelector('.other')).length !== 0) return 'the other element was styled';
    if (!sheetRules(window).includes('margin')) return `css=${sheetRules(window)}`;
    return true;
});

test('no action means display:none', () => {
    const window = apply([{ selector: [{ type: 'css-selector', arg: '.ad' }] }], '<div class="ad">a</div>');
    return sheetRules(window).includes('display: none') || `css=${sheetRules(window)}`;
});

test(':remove() deletes the element', () => {
    const window = apply(
        [{ selector: [{ type: 'css-selector', arg: '.ad' }], action: { type: 'remove' } }],
        '<div class="ad">a</div><div class="keep">k</div>',
    );
    if (window.document.querySelector('.ad')) return 'still present';
    return window.document.querySelector('.keep') ? true : 'the neighbour went too';
});

test(':remove-attr() strips only the named attribute', () => {
    const window = apply(
        [{ selector: [{ type: 'css-selector', arg: '.x' }], action: { type: 'remove-attr', arg: 'onclick' } }],
        '<div class="x" onclick="a()" title="t">x</div>',
    );
    const node = window.document.querySelector('.x');
    if (node.hasAttribute('onclick')) return 'onclick kept';
    return node.hasAttribute('title') ? true : 'title stripped as well';
});

test(':remove-class() strips only the named class', () => {
    const window = apply(
        [{ selector: [{ type: 'css-selector', arg: '.x' }], action: { type: 'remove-class', arg: 'ad' } }],
        '<div class="x ad keep">x</div>',
    );
    const node = window.document.querySelector('.x');
    if (node.classList.contains('ad')) return 'ad kept';
    return node.classList.contains('keep') ? true : 'keep stripped as well';
});

test(':has-text() matches on text content', () => {
    const window = apply(
        [{ selector: [{ type: 'css-selector', arg: 'div' }, { type: 'has-text', arg: 'Sponsored' }], action: { type: 'remove' } }],
        '<div>Sponsored</div><div>Editorial</div>',
    );
    const left = [...window.document.querySelectorAll('div')].map((node) => node.textContent);
    return JSON.stringify(left) === '["Editorial"]' ? true : JSON.stringify(left);
});

test(':has-text() accepts a regular expression', () => {
    const window = apply(
        [{ selector: [{ type: 'css-selector', arg: 'div' }, { type: 'has-text', arg: '/^Ad\\d+$/i' }], action: { type: 'remove' } }],
        '<div>ad42</div><div>Ad</div>',
    );
    const left = [...window.document.querySelectorAll('div')].map((node) => node.textContent);
    return JSON.stringify(left) === '["Ad"]' ? true : JSON.stringify(left);
});

test(':min-text-length() keeps the short ones out', () => {
    const window = apply(
        [{ selector: [{ type: 'css-selector', arg: 'p' }, { type: 'min-text-length', arg: '5' }], action: { type: 'remove' } }],
        '<p>abc</p><p>abcdefgh</p>',
    );
    const left = [...window.document.querySelectorAll('p')].map((node) => node.textContent);
    return JSON.stringify(left) === '["abc"]' ? true : JSON.stringify(left);
});

test(':upward(1) removes the parent', () => {
    const window = apply(
        [{ selector: [{ type: 'css-selector', arg: '.inner' }, { type: 'upward', arg: '1' }], action: { type: 'remove' } }],
        '<div class="outer"><div class="mid"><span class="inner">x</span></div></div>',
    );
    if (!window.document.querySelector('.outer')) return 'the grandparent went too';
    return window.document.querySelector('.mid') ? 'the parent survived' : true;
});

test(':upward(2) removes the grandparent', () => {
    const window = apply(
        [{ selector: [{ type: 'css-selector', arg: '.inner' }, { type: 'upward', arg: '2' }], action: { type: 'remove' } }],
        '<div class="outer"><div class="mid"><span class="inner">x</span></div></div>',
    );
    return window.document.querySelector('.outer') ? 'the grandparent survived' : true;
});

test(':upward(selector) removes the ancestor that matches', () => {
    const window = apply(
        [{ selector: [{ type: 'css-selector', arg: '.inner' }, { type: 'upward', arg: '.outer' }], action: { type: 'remove' } }],
        '<div class="outer"><div class="mid"><span class="inner">x</span></div></div>',
    );
    return window.document.querySelector('.outer') ? 'the ancestor survived' : true;
});

test(':upward() past the root is a no-op', () => {
    const window = apply(
        [{ selector: [{ type: 'css-selector', arg: '.inner' }, { type: 'upward', arg: '99' }], action: { type: 'remove' } }],
        '<div class="inner">x</div>',
    );
    return window.document.querySelector('.inner') ? true : 'removed past the root';
});

test(':matches-attr(name) matches on the attribute name', () => {
    const window = apply(
        [{ selector: [{ type: 'css-selector', arg: 'div' }, { type: 'matches-attr', arg: 'data-ad' }], action: { type: 'remove' } }],
        '<div data-ad="1">a</div><div data-x="1">b</div>',
    );
    const left = [...window.document.querySelectorAll('div')].map((node) => node.textContent);
    return JSON.stringify(left) === '["b"]' ? true : JSON.stringify(left);
});

test(':matches-attr(name=value) matches on the value', () => {
    const window = apply(
        [{ selector: [{ type: 'css-selector', arg: 'div' }, { type: 'matches-attr', arg: 'data-ad=sponsored' }], action: { type: 'remove' } }],
        '<div data-ad="sponsored">a</div><div data-ad="other">b</div>',
    );
    const left = [...window.document.querySelectorAll('div')].map((node) => node.textContent);
    return JSON.stringify(left) === '["b"]' ? true : JSON.stringify(left);
});

test(':matches-path() limits the rule to a path', () => {
    const $$rule = [{ selector: [{ type: 'matches-path', arg: '/gaming' }, { type: 'css-selector', arg: ' .ad' }], action: { type: 'remove' } }];
    const on = apply($$rule, '<div class="ad">a</div>', { path: '/gaming/x' });
    if (on.document.querySelector('.ad')) return 'not applied on the matching path';
    const off = apply($$rule, '<div class="ad">a</div>', { path: '/other' });
    return off.document.querySelector('.ad') ? true : 'applied on a non-matching path';
});

test('a CSS continuation filters the node itself', () => {
    const window = apply(
        [{ selector: [{ type: 'css-selector', arg: 'div.wrap' }, { type: 'css-selector', arg: ':has(> img)' }], action: { type: 'remove' } }],
        '<div class="wrap"><img></div><div class="wrap"><span></span></div>',
    );
    const left = window.document.querySelectorAll('div.wrap').length;
    return left === 1 ? true : `left=${left}`;
});

test('a CSS continuation with a leading combinator walks down', () => {
    const window = apply(
        [{ selector: [{ type: 'css-selector', arg: 'div.wrap' }, { type: 'css-selector', arg: ' > .ad' }], action: { type: 'remove' } }],
        '<div class="wrap"><div class="ad">a</div></div>',
    );
    return window.document.querySelector('.ad') ? 'not removed' : true;
});

test('an unknown operator stops the rule instead of misapplying it', () => {
    const window = apply(
        [{ selector: [{ type: 'css-selector', arg: '.ad' }, { type: 'no-such-op', arg: 'x' }], action: { type: 'remove' } }],
        '<div class="ad">a</div>',
    );
    return window.document.querySelector('.ad') ? true : 'removed despite an unknown operator';
});

test('a selector the browser rejects does not stop the next rule', () => {
    const window = apply(
        [
            { selector: [{ type: 'css-selector', arg: 'div:contains(x)' }], action: { type: 'remove' } },
            { selector: [{ type: 'css-selector', arg: '.ok' }], action: { type: 'remove' } },
        ],
        '<div class="ok">a</div>',
    );
    return window.document.querySelector('.ok') ? 'the second rule did not run' : true;
});

test('a rule argument cannot inject markup', () => {
    // The value reaches `textContent`/`setAttribute` and a regex, never `innerHTML`; a payload that
    // looks like a tag must stay an inert string.
    const payload = '</script><img src=x onerror="window.__owned=1">';
    // The page holds the payload as *text*, which is the only form a page can hold it in: the point is
    // that the rule argument does the same rather than being parsed.
    const escaped = payload.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const window = apply(
        [{ selector: [{ type: 'css-selector', arg: 'div' }, { type: 'has-text', arg: payload }], action: { type: 'remove' } }],
        `<div>${escaped}</div><div class="safe">s</div>`,
    );
    if (window.__owned) return 'the payload executed';
    if (window.document.querySelector('img')) return 'the payload became markup';
    return true;
});

test('the rules do not leak a global that a page script could collide with', () => {
    const window = apply(
        [{ selector: [{ type: 'css-selector', arg: '.ad' }] }],
        '<div class="ad">a</div>',
    );
    // A page script declaring its own top-level `R` must still run after injection.
    try {
        window.eval('let R = 42; window.__pageR = R;');
    } catch (error) {
        return `page script failed: ${error.message}`;
    }
    return window.__pageR === 42 ? true : 'page script did not run';
});

let failed = 0;
for (const { name, fn } of cases) {
    let result;
    try {
        result = await fn();
    } catch (error) {
        result = `threw: ${error.message}`;
    }
    if (result === true) {
        console.log(`ok   ${name}`);
    } else {
        failed += 1;
        console.log(`FAIL ${name}  -> ${result}`);
    }
}
console.log(`\n${cases.length - failed}/${cases.length} passed`);
process.exit(failed === 0 ? 0 : 1);
