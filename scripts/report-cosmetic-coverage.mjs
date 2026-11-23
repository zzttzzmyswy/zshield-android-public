#!/usr/bin/env node
/*
 * Report how much of the shipped filter lists' cosmetic filtering this core can actually apply.
 *
 * Usage:
 *   node scripts/report-cosmetic-coverage.mjs <list.txt> [<list.txt> ...]
 *   node scripts/report-cosmetic-coverage.mjs --builtin
 *
 * What it answers, for the delivery note and `docs/EFFECTIVENESS.md`:
 *
 * - `##+js(...)` rules whose scriptlet this core ships, by canonical name — the share of scriptlet
 *   rules that will actually run, and which names to add next when it is too low;
 * - procedural / action rules (`:has-text()`, `:upward()`, `:remove()`, `:style()`, `:matches-css()`,
 *   `:xpath()`, `:min-text-length()`, `:matches-attr()`, `:remove-attr()`, `:remove-class()`,
 *   `#%#` AdGuard scriptlets): counted and reported separately, because they are deliberately not
 *   implemented in this milestone.
 *
 * The scriptlet names come from `core/src/cosmetic/scriptlet-resources.rs`, so this report can never
 * claim support for a scriptlet the binary does not contain.
 */

import fs from 'node:fs';
import path from 'node:path';

const RESOURCE_FILE = path.join(
    path.dirname(new URL(import.meta.url).pathname),
    '..',
    'core',
    'src',
    'cosmetic',
    'scriptlet-resources.rs',
);

/** Every resource name and alias in the generated table. */
function shippedNames() {
    const source = fs.readFileSync(RESOURCE_FILE, 'utf8');
    const names = new Set();
    const aliases = new Map();
    // The generated table is one `Generated { … }` literal per resource; parsing it with a regex is
    // enough because the generator controls its exact shape.
    for (const block of source.split('Generated {').slice(1)) {
        const name = /name: "([^"]+)"/.exec(block);
        if (!name) continue;
        names.add(name[1]);
        const aliasList = /aliases: &\[([^\]]*)\]/.exec(block);
        if (!aliasList) continue;
        for (const alias of aliasList[1].split(',')) {
            const value = alias.trim().replace(/^"|"$/g, '');
            if (value) aliases.set(value, name[1]);
        }
    }
    return { names, aliases };
}

/** The canonical name a rule's scriptlet argument refers to, or `null`. */
function canonical(name, shipped) {
    const withJs = name.endsWith('.js') ? name : `${name}.js`;
    if (shipped.names.has(withJs)) return withJs;
    if (shipped.aliases.has(withJs)) return shipped.aliases.get(withJs);
    if (shipped.aliases.has(name)) return shipped.aliases.get(name);
    return null;
}

const PROCEDURAL = [
    ':has-text(',
    ':upward(',
    ':remove()',
    ':style(',
    ':matches-css(',
    ':xpath(',
    ':min-text-length(',
    ':matches-attr(',
    ':matches-path(',
    ':matches-prop(',
    ':others(',
    ':watch-attr(',
    ':remove-attr(',
    ':remove-class(',
];

function analyse(file, shipped) {
    const scriptlets = new Map();
    let scriptletRules = 0;
    let unsupportedScriptletRules = 0;
    let proceduralRules = 0;
    let hideRules = 0;
    let total = 0;

    for (const raw of fs.readFileSync(file, 'utf8').split('\n')) {
        const line = raw.trim();
        if (!line || line.startsWith('!') || line.startsWith('[')) continue;
        total += 1;

        const scriptlet = /##\+?js\(([^,)]*)/.exec(line);
        if (scriptlet) {
            scriptletRules += 1;
            const name = scriptlet[1].trim();
            const canonicalName = canonical(name, shipped);
            if (canonicalName) {
                scriptlets.set(canonicalName, (scriptlets.get(canonicalName) || 0) + 1);
            } else {
                unsupportedScriptletRules += 1;
                scriptlets.set(`(unsupported) ${name}`, (scriptlets.get(`(unsupported) ${name}`) || 0) + 1);
            }
            continue;
        }
        if (line.includes('#%#')) {
            // AdGuard's own scriptlet syntax (`#%#//scriptlet(...)`): a different resource system.
            proceduralRules += 1;
            continue;
        }
        if (PROCEDURAL.some((token) => line.includes(token))) {
            proceduralRules += 1;
            continue;
        }
        if (/#@?#/.test(line) || /##/.test(line)) {
            hideRules += 1;
        }
    }

    return {
        file: path.basename(file),
        total,
        hideRules,
        scriptletRules,
        unsupportedScriptletRules,
        proceduralRules,
        scriptlets,
    };
}

const shipped = shippedNames();
const args = process.argv.slice(2);
if (args.length === 0 || args[0] === '--builtin') {
    console.log(`shipped scriptlets: ${[...shipped.names].filter((n) => n.endsWith('.js')).length}`);
    console.log(`shipped helpers:    ${[...shipped.names].filter((n) => !n.endsWith('.js')).length}`);
    console.log(`shipped aliases:    ${shipped.aliases.size}`);
    process.exit(0);
}

const results = args.map((file) => analyse(file, shipped));
for (const result of results) {
    const covered = result.scriptletRules - result.unsupportedScriptletRules;
    const share = result.scriptletRules === 0 ? 100 : (covered * 100) / result.scriptletRules;
    console.log(`\n=== ${result.file}`);
    console.log(`  lines                     ${result.total}`);
    console.log(`  hide/exception rules      ${result.hideRules}  (implemented: specific + generic)`);
    console.log(
        `  ##+js rules              ${result.scriptletRules}  (scriptlet shipped: ${covered}, ${share.toFixed(1)}%)`,
    );
    console.log(`  procedural / AdGuard js   ${result.proceduralRules}  (not implemented, by design)`);
    const unsupported = [...result.scriptlets]
        .filter(([name]) => name.startsWith('(unsupported) '))
        .sort((a, b) => b[1] - a[1]);
    if (unsupported.length > 0) {
        console.log('  unsupported scriptlets:');
        for (const [name, count] of unsupported) {
            console.log(`    ${String(count).padStart(6)}  ${name.replace('(unsupported) ', '')}`);
        }
    }
}
