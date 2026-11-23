#!/usr/bin/env node
/*
 * Regenerate `core/src/cosmetic/scriptlet-resources.rs` from a uBlock Origin checkout.
 *
 * The core does not ship a hand-written copy of uBO's scriptlets: the file is generated from one
 * pinned uBO revision, so the provenance (`docs/THIRD_PARTY.md`) is a fact rather than a claim and a
 * reviewer can regenerate it and diff the result.
 *
 * Usage:
 *   git clone --depth 1 --branch 1.76.0 https://github.com/gorhill/uBlock /tmp/uBlock
 *   node scripts/gen-scriptlet-resources.mjs /tmp/uBlock > core/src/cosmetic/scriptlet-resources.rs
 *
 * What it emits: every **non-trusted** uBO scriptlet (the only ones a third-party list may reference
 * once lists are compiled with default permissions) plus the transitive closure of the helper
 * functions/classes they depend on. `core/src/cosmetic/scriptlets.rs` turns each entry into an
 * `adblock::resources::Resource`.
 *
 * # Attribution
 *
 * Every emitted entry carries the `Copyright (C) …` line and the source file it came from, both read
 * out of the checkout rather than restated here: uBO's scriptlet bodies live in several files whose
 * headers differ (`prevent-navigation.js` starts at 2026, `jsonpath.js` at 2025, most at 2019), and a
 * hand-maintained list would silently drift from the code it is supposed to describe.
 *
 * The body is located by searching the checkout for the exact source text of the function, so an
 * ambiguous or missing match fails generation instead of attributing code to the wrong file.
 */

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const root = process.argv[2];
if (!root) {
    console.error('usage: gen-scriptlet-resources.mjs <path-to-uBlock-checkout>');
    process.exit(2);
}

const src = path.join(root, 'src', 'js', 'resources') + path.sep;
const { registeredScriptlets } = await import(src + 'base.js');
await import(src + 'scriptlets.js');

const byName = new Map(registeredScriptlets.map((s) => [s.name, s]));
const codeOf = (d) => d.fn.toString().replace(/^export\s+/, '');

// Non-trusted scriptlets only: `requiresTrust` ones need a permission mask the app never grants, so
// shipping them would only add bytes nothing can reference.
const wanted = registeredScriptlets.filter(
    (s) => s.name.endsWith('.js') && s.requiresTrust !== true,
);

// Transitive closure over helpers (`*.fn` entries are functions/classes, not invokable scriptlets).
const helpers = new Map();
const queue = [];
for (const s of wanted) queue.push(...(s.dependencies || []));
while (queue.length > 0) {
    const token = queue.shift();
    if (helpers.has(token)) continue;
    const d = byName.get(token);
    if (!d) {
        console.error(`missing dependency ${token}`);
        continue;
    }
    helpers.set(token, d);
    if (Array.isArray(d.dependencies)) queue.push(...d.dependencies);
}

// ---------------------------------------------------------------------------------------------
// Attribution: which file each body came from, and that file's copyright line.
// ---------------------------------------------------------------------------------------------
const jsRoot = path.join(root, 'src', 'js');

/** Every `.js` file under `src/js` — the scriptlet bodies are not all in `src/js/resources`. */
function jsFiles(dir) {
    const out = [];
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) out.push(...jsFiles(full));
        else if (entry.name.endsWith('.js')) out.push(full);
    }
    return out;
}

const files = jsFiles(jsRoot);
const texts = new Map(files.map((file) => [file, fs.readFileSync(file, 'utf8')]));

/**
 * The `Copyright (C) …` line of a source file's leading block comment.
 *
 * uBO puts one per file. A file without one cannot be attributed, which is a hard error: emitting an
 * entry whose upstream notice was dropped is exactly the defect this generator exists to prevent.
 */
function copyrightOf(file) {
    const text = texts.get(file);
    const header = text.trimStart().startsWith('/*') ? text.split('*/')[0] : '';
    const found = header.match(/Copyright \(C\)[^\n]*/);
    if (!found) {
        console.error(`no copyright header in ${path.relative(root, file)}`);
        process.exit(1);
    }
    return found[0].trim();
}

/** The `file` field a reader can paste into the uBO repository, plus its copyright line. */
function attribute(entry) {
    const code = codeOf(entry);
    const hits = files.filter((file) => texts.get(file).includes(code));
    if (hits.length !== 1) {
        // 0 means the body was rewritten at load time, >1 means the search cannot tell two files
        // apart; either way the attribution would be a guess.
        console.error(
            `cannot attribute ${entry.name}: ${hits.length} matches` +
                (hits.length ? ` (${hits.map((f) => path.relative(root, f)).join(', ')})` : ''),
        );
        process.exit(1);
    }
    return {
        origin: path.relative(root, hits[0]).split(path.sep).join('/'),
        copyright: copyrightOf(hits[0]),
    };
}

const entries = [];
for (const [token, d] of helpers) {
    if (d.name.endsWith('.js')) continue; // pulled in as another scriptlet's dependency
    entries.push({
        name: d.name,
        aliases: [],
        dependencies: (d.dependencies || []).filter((x) => byName.has(x)),
        code: codeOf(d),
        ...attribute(d),
    });
}
for (const d of wanted) {
    entries.push({
        name: d.name,
        aliases: (d.aliases || []).filter((a) => !byName.has(a) || byName.get(a) === d),
        dependencies: (d.dependencies || []).filter((x) => byName.has(x)),
        code: codeOf(d),
        ...attribute(d),
    });
}

// `ResourceStorage::add_resource` rejects a name (or alias) registered twice, and the engine then
// silently drops the resource — a rule would quietly do nothing. Fail the generation instead.
const seen = new Set();
for (const entry of entries) {
    for (const name of [entry.name, ...entry.aliases]) {
        if (seen.has(name)) {
            console.error(`duplicate resource name ${name}`);
            process.exit(1);
        }
        seen.add(name);
    }
}

// One row per upstream file, for the file header and for [`scriptlets::attribution`] — which is what
// lets the app's notice screen name the sources without a second, hand-copied list.
const attribution = new Map();
for (const entry of entries) {
    const previous = attribution.get(entry.origin);
    if (previous !== undefined && previous !== entry.copyright) {
        // Two entries from one file disagreeing means the file has more than one notice block and
        // picking either would misreport one of them.
        console.error(
            `conflicting copyright lines for ${entry.origin}: ${previous} / ${entry.copyright}`,
        );
        process.exit(1);
    }
    attribution.set(entry.origin, entry.copyright);
}

// A Rust raw string delimiter that does not occur in the code (`r#"…"#` unless the code contains
// `"#`, which shader-ish scriptlet code could conceivably do).
const raw = (text) => {
    let hashes = 1;
    while (text.includes('"' + '#'.repeat(hashes))) hashes += 1;
    return `r${'#'.repeat(hashes)}"${text}"${'#'.repeat(hashes)}`;
};
const list = (items) => `&[${items.map((item) => JSON.stringify(item)).join(', ')}]`;

// The tag and commit are read from the checkout (a checked-out uBO has no version string inside the
// source tree — the extension version lives only in the build scripts and the git tag). `--tags
// --exact-match` fails on a commit that is not a release, so a plain clone of `main` cannot silently
// stamp the header with a version the bodies are not from: pass UBLOCK_VERSION / UBLOCK_COMMIT then,
// and record why in docs/THIRD_PARTY.md.
const git = (args) => {
    const result = spawnSync('git', ['-C', root, ...args], { encoding: 'utf8' });
    return result.status === 0 ? result.stdout.trim() : null;
};
const upstreamVersion = process.env.UBLOCK_VERSION || git(['describe', '--tags', '--exact-match']) || null;
const upstreamCommit = process.env.UBLOCK_COMMIT || git(['rev-parse', 'HEAD']) || null;
if (upstreamVersion === null) {
    console.error(
        'cannot determine the uBlock Origin version: HEAD is not a tagged commit.\n' +
            'Check out the release tag (git checkout 1.76.0) or set UBLOCK_VERSION.',
    );
    process.exit(1);
}
if (upstreamCommit === null) {
    console.error('cannot determine the uBlock Origin commit (git rev-parse HEAD failed)');
    process.exit(1);
}

const out = [];
out.push('// Generated by scripts/gen-scriptlet-resources.mjs from uBlock Origin — do not edit.');
out.push('//');
out.push('// Source: uBlock Origin ' + upstreamVersion + ' <https://github.com/gorhill/uBlock>,');
out.push('// commit ' + upstreamCommit + '.');
out.push('//');
out.push('// uBlock Origin is free software under the GNU General Public License, version 3 or (at your');
out.push('// option) any later version: every source file this generation read carries the notice');
out.push('// "either version 3 of the License, or (at your option) any later version". See');
out.push('// docs/THIRD_PARTY.md for the license text location, the pinned revision and how to');
out.push('// regenerate this file.');
out.push('//');
out.push('// Bodies in this file were copied verbatim from the upstream files listed below. Each one');
out.push('// keeps that file\'s own copyright line, which is why the years differ:');
out.push('//');
for (const [origin, copyright] of [...attribution].sort((a, b) => a[0].localeCompare(b[0]))) {
    out.push(`//   ${origin} — ${copyright}`);
}
out.push('//');
out.push('// This file is part of ZShield (GPL-3.0-or-later, see LICENSE). Because it contains uBlock');
out.push('// Origin code, it may only be conveyed under GPL-3.0-or-later.');
out.push('//');
out.push('// The attribution above is a source-comment record, not a runtime table: a distributed APK');
out.push('// carries no comments, and per-entry `origin`/`copyright` fields would be dead weight in');
out.push('// `.so` (or eliminated by the compiler, which is worse — unverifiable). The copy that');
out.push('// actually ships is app/src/main/assets/licenses/THIRD-PARTY-NOTICES.txt, generated by');
out.push('// scripts/gen-license-assets.py; a test asserts the two lists agree.');
out.push('//');
out.push('// One entry per scriptlet and per helper the scriptlets depend on. `code` is the JavaScript');
out.push('// body exactly as uBO evaluates it, minus the module `export` keyword.');
out.push('struct Generated {');
out.push("    name: &'static str,");
out.push("    aliases: &'static [&'static str],");
out.push("    dependencies: &'static [&'static str],");
out.push("    code: &'static str,");
out.push('}');
out.push('');
out.push('const GENERATED: &[Generated] = &[');
for (const entry of entries) {
    out.push('    Generated {');
    out.push(`        name: ${JSON.stringify(entry.name)},`);
    out.push(`        aliases: ${list(entry.aliases)},`);
    out.push(`        dependencies: ${list(entry.dependencies)},`);
    out.push(`        code: ${raw(entry.code)},`);
    out.push('    },');
}
out.push('];');
out.push('');

process.stdout.write(out.join('\n'));
const bytes = entries.reduce((n, e) => n + e.code.length, 0);
const origins = new Set(entries.map((e) => e.origin));
console.error(
    `generated ${entries.length - helpers.size} scriptlets + ${helpers.size} helpers, ${bytes} bytes of JavaScript, ` +
        `${origins.size} upstream files`,
);
