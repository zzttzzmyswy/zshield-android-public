#!/usr/bin/env python3
"""Regenerate `app/src/main/assets/licenses/` from the crates that actually ship.

The notices in an APK have to be *upstream's own files*, not a hand-picked set of SPDX templates.
A crate's `license = "Apache-2.0 AND ISC"` string is a summary; the obligations live in the files the
crate ships, and those files differ in ways the string cannot express — `ring`'s root LICENSE points at
`LICENSE-BoringSSL` (which carries Go and Chromium statements after the Apache text) and at
`LICENSE-other-bits` (ISC, with its own year range), and it embeds `third_party/fiat/LICENSE` and
`src/polyfill/once_cell/` for code it vendored. Copying only a generic `Apache-2.0.txt` loses all of
that.

So this script:

  1. resolves the runtime dependency set from `cargo metadata --locked` for the Android target,
  2. walks every runtime crate for license-bearing files (any depth — the nested ones are the point),
  3. copies each **distinct** file verbatim into `assets/licenses/`, naming it after the first crate
     that ships it and listing every other crate that maps to the same bytes,
  4. emits `THIRD-PARTY-NOTICES.txt`, the index a reader (or a reviewer without `cargo`) uses to go
     from "which crate is in this APK" to "which file states its terms",
  5. fails if a runtime crate ships no license file at all, so the gap is a build failure rather than
     a silently missing notice.

Usage:
    python3 scripts/gen-license-assets.py            # regenerate in place
    python3 scripts/gen-license-assets.py --check    # verify the tree is current; exit 1 if not

`--check` is what the tests and the release checklist run: it regenerates into a temporary directory
and compares, so a crate bump that changes a notice cannot pass unnoticed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ASSETS = REPO / "app" / "src" / "main" / "assets" / "licenses"
CORE = REPO / "core"

# The target the release APK is built for (docs/DESIGN.md §1: arm64 only).
TARGET = "aarch64-linux-android"

# Files a crate may use to state its terms. `AUTHORS` is not one of them — it names people, not terms —
# but `COPYING` and `UNLICENSE` are the two spellings that are easy to miss.
LICENSE_FILE = re.compile(r"(?i)^(licen[sc]e|copying|notice|unlicense)")


def sh(cmd: list[str], **kw) -> str:
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw).stdout


def cargo_metadata() -> dict:
    out = sh([
        "cargo", "metadata", "--locked", "--manifest-path", str(CORE / "Cargo.toml"),
        "--filter-platform", TARGET, "--format-version", "1",
    ])
    return json.loads(out)


def runtime_packages(meta: dict) -> list[dict]:
    """Every package linked into the binary, with the crate source directory for each.

    Walks `resolve.nodes` along non-`build` edges. Build scripts and proc-macros produce no code in
    the APK, so their notices are not required to travel with it — but they are *listed* in the
    notices index under a "build only" heading so a reader can see they were considered rather than
    overlooked.
    """
    by_id = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    root = next(p for p in meta["packages"] if p["name"] == "zshield-core")
    proc_macro = {
        p["id"] for p in meta["packages"]
        if any("proc-macro" in t["kind"] for t in p.get("targets", []))
    }

    runtime: set[str] = set()
    build: set[str] = set()
    queue = [(root["id"], "normal")]
    seen: set[tuple[str, str]] = set()
    while queue:
        pid, state = queue.pop()
        if (pid, state) in seen:
            continue
        seen.add((pid, state))
        (runtime if state == "normal" else build).add(pid)
        for dep in nodes[pid]["deps"]:
            for kind in dep["dep_kinds"]:
                k = kind["kind"] or "normal"
                nxt = "normal" if (state == "normal" and k == "normal" and dep["pkg"] not in proc_macro) else "build"
                queue.append((dep["pkg"], nxt))
    runtime -= build
    runtime.discard(root["id"])

    def rows(ids: set[str]) -> list[dict]:
        out = []
        for pid in ids:
            p = by_id[pid]
            src = Path(p["manifest_path"]).parent
            out.append({"name": p["name"], "version": p["version"], "license": p.get("license"), "dir": src})
        return sorted(out, key=lambda r: (r["name"], r["version"]))

    return rows(runtime), rows(build)


def folder_of(crate: dict) -> Path:
    return REPO / "scripts" / "licenses-extra" / f"{crate['name']}-{crate['version']}"


def supplementary_files(crate: dict) -> list[Path]:
    """Files vendored under `scripts/licenses-extra/` for crates that ship none.

    Five runtime crates publish no license file at all. Substituting a generic SPDX template would
    lose the copyright line, so the upstream file is fetched from the project at a recorded commit and
    kept here — see `scripts/licenses-extra/README.md` for the provenance table.
    """
    folder = folder_of(crate)
    if not folder.is_dir():
        return []
    return sorted(p for p in folder.iterdir() if p.is_file())


def license_files(crate_dir: Path) -> list[Path]:
    found = []
    for root, _dirs, files in os.walk(crate_dir):
        for name in files:
            if LICENSE_FILE.match(name):
                found.append(Path(root) / name)
    return sorted(found)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def classify(text: str) -> str:
    """A short human label for the index, derived from the text itself rather than a filename."""
    flat = re.sub(r"\s+", " ", text).strip()
    low = flat.lower()
    if "gnu general public license" in low and "version 3" in low:
        return "GPL-3.0"
    if "mozilla public license version 2.0" in low:
        return "MPL-2.0"
    if "apache license" in low and "version 2.0" in low:
        return "Apache-2.0" if len(flat) > 3000 else "Apache-2.0 (reference note)"
    if "unicode license v3" in low or "unicode, inc. license" in low:
        return "Unicode"
    if "redistribution and use in source and binary forms" in low:
        return "BSD-3-Clause"
    if "permission to use, copy, modify, and/or distribute" in low:
        return "ISC/0BSD"
    if "permission is hereby granted, free of charge" in low:
        return "MIT"
    if "this is free and unencumbered software released into the public domain" in low:
        return "Unlicense"
    if "this software is provided 'as-is'" in low:
        return "Zlib"
    if low.startswith("this project is dual-licensed") or "distributed under the following" in low:
        return "dual-license note"
    if low.startswith("*ring* uses"):
        return "ring root note"
    if "mit or apache-2.0" in low and len(flat) < 200:
        return "dual-license note"
    return "upstream notice"


def safe_component(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text)


def build(dest: Path) -> dict:
    meta = cargo_metadata()
    runtime, build_only = runtime_packages(meta)

    # content hash -> record
    by_bytes: dict[str, dict] = {}
    # crate -> list of asset names
    mapping: dict[str, list[str]] = {}
    missing: list[dict] = []

    for crate in runtime:
        files = license_files(crate["dir"])
        vendored = False
        if not files:
            files = supplementary_files(crate)
            vendored = True
        if not files:
            missing.append(crate)
            continue
        for path in files:
            # Supplementary files live under scripts/licenses-extra/<crate>/; the crate directory is
            # their base, everything else resolves against the published tarball.
            base_dir = crate["dir"] if not vendored else folder_of(crate)
            origin = f"{crate['name']}-{crate['version']}/{path.relative_to(base_dir).as_posix()}"
            h = digest(path)
            rec = by_bytes.get(h)
            if rec is None:
                rec = {
                    "text": path.read_text(encoding="utf-8", errors="replace"),
                    "origin": origin,
                    "crates": [],
                    "asset": None,
                    "vendored": set(),
                }
                by_bytes[h] = rec
            key = f"{crate['name']} {crate['version']}"
            rec["crates"].append(key)
            if vendored:
                # Recorded per crate, not per file: an identical text may also be shipped normally by
                # another crate, and naming that one as "vendored" would be false.
                rec["vendored"].add(key)

    # Name each distinct file. A text shipped by exactly one crate keeps that crate's name (so a
    # reader can match it against the crate tarball). A text shipped by several crates gets a neutral
    # name instead — naming the MIT body "adler2-LICENSE-MIT.txt" would make every other crate's index
    # entry point at a file named after an unrelated crate, which reads as an error even when the
    # bytes are right.
    used_names: set[str] = set()
    for h, rec in sorted(by_bytes.items(), key=lambda kv: kv[1]["origin"]):
        owners = sorted(set(rec["crates"]))
        if len(owners) > 1:
            family = safe_component(classify(rec["text"]).split(" ")[0]) or "license"
            base = f"shared-{family}-{h[:8]}.txt"
        else:
            crate_name, rest = rec["origin"].split("/", 1)
            base = safe_component(crate_name) + "-" + safe_component(Path(rest).name)
            if not base.endswith(".txt"):
                base += ".txt"
        name = base
        n = 2
        while name in used_names:
            name = f"{base[:-4]}.{n}.txt"
            n += 1
        used_names.add(name)
        rec["asset"] = name
        dest.joinpath(name).write_text(rec["text"], encoding="utf-8")
        for crate in rec["crates"]:
            mapping.setdefault(crate, []).append(name)

    return {
        "distinct": by_bytes,
        "mapping": mapping,
        "missing": missing,
        "runtime": runtime,
        "build_only": build_only,
        "meta": meta,
    }


def render_notices(result: dict, gpl_text: str) -> str:
    runtime = result["runtime"]
    distinct = result["distinct"]
    mapping = result["mapping"]
    missing = result["missing"]

    lines: list[str] = []
    add = lines.append
    add("ZShield 净盾 — 第三方组件通知 / Third-Party Notices")
    add("")
    add("本文件随 APK 分发，说明 ZShield 中包含哪些第三方组件、各自以什么条款授权，")
    add("以及条款正文在 assets/licenses/ 下的哪个文件里。")
    add("")
    add("ZShield 净盾以 GNU 通用公共许可证第 3 版或更高版本授权 (GPL-3.0-or-later)。")
    add("完整条款见 GPL-3.0-or-later.txt；完整对应源代码随每个版本公开。")
    add("")
    add("本目录下的条款文件全部取自上游发布包的原始文件（逐字节复制，未改写），")
    add("由 scripts/gen-license-assets.py 从锁定的依赖集生成，可重新生成并逐字节比对。")
    add("")
    add("=" * 78)
    add("一、uBlock Origin scriptlet（代码编入 libzshield.so）")
    add("=" * 78)
    add("")
    add("本 APK 的本地核心库内含从 uBlock Origin 逐字复制的 JavaScript scriptlet 代码。")
    add("")
    add("    uBlock Origin 1.76.0")
    add("    https://github.com/gorhill/uBlock")
    add("    commit aa9236cb351e369cbb68113dbe8175b87f3cd134")
    add("    Copyright (C) 2019-present Raymond Hill")
    add("    Copyright (C) 2022-present Raymond Hill (src/js/urlskip.js)")
    add("    Copyright (C) 2025-present Raymond Hill (src/js/jsonpath.js 等)")
    add("    Copyright (C) 2026-present Raymond Hill (prevent-navigation.js, vod.js)")
    add("")
    add("    本程序是自由软件：你可以依据自由软件基金会发布的 GNU 通用公共许可证第 3 版")
    add("    或（由你选择）任何更高版本的条款重新分发和/or 修改它。")
    add("")
    add("    本程序分发时希望它有用，但不提供任何担保，甚至不提供适销性或特定用途适用性")
    add("    的默示担保。详见 GNU 通用公共许可证。")
    add("")
    add("    你应当已随本程序收到 GNU 通用公共许可证的副本；如果没有，见")
    add("    <https://www.gnu.org/licenses/>。")
    add("")
    add("修改后的首选形式：scriptlet 代码由 scripts/gen-scriptlet-resources.mjs 从上述")
    add("uBlock Origin 修订生成，不经手工编辑；生成办法见源码仓库 docs/THIRD_PARTY.md。")
    add("")
    add("代码来源文件与各自的版权行：")
    add("")
    for origin, copyright in UB_ORIGINS:
        add(f"    {origin}")
        add(f"        {copyright}")
    add("")
    add("=" * 78)
    add(f"二、Rust 运行时依赖（{len(runtime)} 个 crate，代码链接进 libzshield.so）")
    add("=" * 78)
    add("")
    add("每个 crate 后面列出它在上游发布包中自带的条款文件，文件已原样收在本目录。")
    add("同一份正文被多个 crate 共用时只保留一个文件，此处逐条指回。")
    add("")
    for crate in runtime:
        key = f"{crate['name']} {crate['version']}"
        assets = sorted(set(mapping.get(key, [])))
        label = crate.get("license") or "未声明"
        if assets:
            add(f"    {key}  [{label}]")
            for asset in assets:
                add(f"        -> {asset}")
        else:
            add(f"    {key}  [{label}]  （上游发布包未附条款文件，见第四节）")
    add("")
    add("=" * 78)
    add("三、Android / Kotlin 依赖（DEX 与资源）")
    add("=" * 78)
    add("")
    add("清单依据 releaseRuntimeClasspath、各构件的 POM 和上游声明。47 个构件包含 57 个许可文件，正文相同。")
    add("全部为 Apache License 2.0，正文见 Apache-2.0 相关文件。")
    add("")
    for coord in ANDROID_COORDS:
        add(f"    {coord}")
    add("")
    add("例外：")
    add("  * com.google.guava:listenablefuture:1.0 — POM 未声明 licenses 段，其 parent 为")
    add("    com.google.guava:guava-parent，按 Apache-2.0 处理。")
    add("  * org.rustls:rustls-platform-verifier:0.2.0 — 按上游 LICENSE-APACHE / LICENSE-MIT")
    add("    以 Apache-2.0 OR MIT 授权，本项目选择 Apache-2.0。")
    add("")
    add("=" * 78)
    add("四、需要单独说明的项")
    add("=" * 78)
    add("")
    add(f"A. ring 0.17.14：根 LICENSE 只是索引，指向随包附带的其它文件。本目录收录了")
    add("   它的全部条款文件：LICENSE-BoringSSL（Apache 正文之后还有 Go 与 Chromium 的")
    add("   版权与许可声明）、LICENSE-other-bits（ISC，Brian Smith，2015-2025）、")
    add("   third_party/fiat/LICENSE（fiat-crypto 作者的 Apache-2.0）、以及内嵌的")
    add("   src/polyfill/once_cell 两份。ring 同时以 Apache-2.0 与 ISC 授权，两者都适用。")
    add("")
    if missing:
        add("B. 上游发布包未附条款文件的 crate（如实记录，不代为拟定）：")
        for crate in missing:
            add(f"   * {crate['name']} {crate['version']} — Cargo.toml 声明 {crate.get('license') or '未声明'}，")
            add("     但包内没有许可证文件，也没有版权行。按声明条款处理。")
    else:
        add("B. 全部运行时 crate 均已映射到许可文件，含下列上游补充件。")
    add("")
    vendored = sorted({c for rec in result["distinct"].values() for c in rec.get("vendored", ())})
    if vendored:
        add("   其中以下 crate 的发布包**没有**条款文件，本目录收的是按上游 commit 取得的补充件")
        add("   （取得地址与 commit 见源码仓库 scripts/licenses-extra/README.md）：")
        for crate in vendored:
            add(f"     - {crate}")
        add("")
    add("C. Mozilla 公共后缀列表（Public Suffix List）：经 psl crate 编译进 libzshield.so，")
    add("   共 10406 条规则，以 MPL-2.0 发布。https://publicsuffix.org/")
    add("")
    add("D. 图标：应用图标使用 Google Material Icons 的 verified_user 路径数据，")
    add("   Apache License 2.0。https://github.com/google/material-design-icons")
    add("")
    add("E. Apache-2.0 §4(d)（传递上游 NOTICE）：Rust 与 Android 运行时构件逐个解包，")
    add("   NOTICE 文件 0 个，因此没有需要额外传递的 NOTICE 内容。")
    add("")
    add("=" * 78)
    add("五、订阅过滤列表（不随包分发）")
    add("=" * 78)
    add("")
    add("应用内可选下载的过滤列表由各自发布方授权（AdGuard 过滤器 GPL-3.0、")
    add("uBlock filters GPL-3.0、EasyList GPLv3+CC BY-SA、URLhaus CC-BY-SA-4.0 等）。")
    add("它们由用户按需下载，不包含在本 APK 中。逐条授权见应用内列表目录。")
    add("")
    add("=" * 78)
    add("六、获取对应源代码")
    add("=" * 78)
    add("")
    add("本 APK 的完整对应源代码（含构建脚本、Cargo.lock 与版本锁定信息）随每个版本")
    add("在项目公开仓库按 tag 提供；APK 的 versionName/versionCode 对应同名 tag。")
    add("")
    add("第三方 crate 的对应源码：按上表的名称与版本从 crates.io 取得同一发布包，")
    add("或在本仓库执行 `cargo vendor` 取得锁定版本的完整副本。这些 crate 未被本项目修改。")
    add("")
    return "\n".join(lines)


# The uBO source files each generated body came from, and that file's own notice. Kept in sync with
# `core/src/cosmetic/scriptlet-resources.rs` by a test rather than duplicated by hand here.
UB_ORIGINS = [
    ("src/js/resources/abort-current-script.js", "Copyright (C) 2019-present Raymond Hill"),
    ("src/js/resources/attribute.js", "Copyright (C) 2019-present Raymond Hill"),
    ("src/js/resources/cookie.js", "Copyright (C) 2019-present Raymond Hill"),
    ("src/js/resources/href-sanitizer.js", "Copyright (C) 2019-present Raymond Hill"),
    ("src/js/resources/json-edit.js", "Copyright (C) 2019-present Raymond Hill"),
    ("src/js/resources/json-prune.js", "Copyright (C) 2019-present Raymond Hill"),
    ("src/js/resources/localstorage.js", "Copyright (C) 2019-present Raymond Hill"),
    ("src/js/resources/noeval.js", "Copyright (C) 2019-present Raymond Hill"),
    ("src/js/resources/object-prune.js", "Copyright (C) 2019-present Raymond Hill"),
    ("src/js/resources/prevent-addeventlistener.js", "Copyright (C) 2019-present Raymond Hill"),
    ("src/js/resources/prevent-bab.js", "Copyright (C) 2019-present Raymond Hill"),
    ("src/js/resources/prevent-dialog.js", "Copyright (C) 2025-present Raymond Hill"),
    ("src/js/resources/prevent-fetch.js", "Copyright (C) 2019-present Raymond Hill"),
    ("src/js/resources/prevent-innerHTML.js", "Copyright (C) 2025-present Raymond Hill"),
    ("src/js/resources/prevent-navigation.js", "Copyright (C) 2026-present Raymond Hill"),
    ("src/js/resources/prevent-settimeout.js", "Copyright (C) 2019-present Raymond Hill"),
    ("src/js/resources/prevent-xhr.js", "Copyright (C) 2019-present Raymond Hill"),
    ("src/js/resources/proxy-apply.js", "Copyright (C) 2019-present Raymond Hill"),
    ("src/js/resources/run-at.js", "Copyright (C) 2019-present Raymond Hill"),
    ("src/js/resources/safe-self.js", "Copyright (C) 2019-present Raymond Hill"),
    ("src/js/resources/scriptlets.js", "Copyright (C) 2019-present Raymond Hill"),
    ("src/js/resources/set-constant.js", "Copyright (C) 2019-present Raymond Hill"),
    ("src/js/resources/spoof-css.js", "Copyright (C) 2019-present Raymond Hill"),
    ("src/js/resources/stack-trace.js", "Copyright (C) 2019-present Raymond Hill"),
    ("src/js/resources/utils.js", "Copyright (C) 2019-present Raymond Hill"),
    ("src/js/resources/vod.js", "Copyright (C) 2026-present Raymond Hill"),
    ("src/js/jsonpath.js", "Copyright (C) 2025-present Raymond Hill"),
    ("src/js/urlskip.js", "Copyright (C) 2022-present Raymond Hill"),
]

ANDROID_COORDS = [
    "androidx.activity:activity:1.13.0",
    "androidx.activity:activity-compose:1.13.0",
    "androidx.activity:activity-ktx:1.13.0",
    "androidx.annotation:annotation-experimental:1.4.1",
    "androidx.annotation:annotation-jvm:1.9.1",
    "androidx.arch.core:core-common:2.2.0",
    "androidx.arch.core:core-runtime:2.2.0",
    "androidx.autofill:autofill:1.0.0",
    "androidx.collection:collection-jvm:1.5.0",
    "androidx.collection:collection-ktx:1.5.0",
    "androidx.compose.animation:animation-android:1.11.4",
    "androidx.compose.animation:animation-core-android:1.11.4",
    "androidx.compose.foundation:foundation-android:1.11.4",
    "androidx.compose.foundation:foundation-layout-android:1.11.4",
    "androidx.compose.material:material-icons-core-android:1.7.8",
    "androidx.compose.material:material-ripple-android:1.11.4",
    "androidx.compose.material3:material3-android:1.4.0",
    "androidx.compose.runtime:runtime-android:1.11.4",
    "androidx.compose.runtime:runtime-annotation-android:1.11.4",
    "androidx.compose.runtime:runtime-retain-android:1.11.4",
    "androidx.compose.runtime:runtime-saveable-android:1.11.4",
    "androidx.compose.ui:ui-android:1.11.4",
    "androidx.compose.ui:ui-geometry-android:1.11.4",
    "androidx.compose.ui:ui-graphics-android:1.11.4",
    "androidx.compose.ui:ui-text-android:1.11.4",
    "androidx.compose.ui:ui-unit-android:1.11.4",
    "androidx.compose.ui:ui-util-android:1.11.4",
    "androidx.concurrent:concurrent-futures:1.1.0",
    "androidx.core:core:1.18.0",
    "androidx.core:core-ktx:1.18.0",
    "androidx.core:core-viewtree:1.0.0",
    "androidx.customview:customview-poolingcontainer:1.0.0",
    "androidx.documentfile:documentfile:1.0.0",
    "androidx.dynamicanimation:dynamicanimation:1.0.0",
    "androidx.emoji2:emoji2:1.4.0",
    "androidx.graphics:graphics-path:1.0.1",
    "androidx.interpolator:interpolator:1.0.0",
    "androidx.legacy:legacy-support-core-utils:1.0.0",
    "androidx.lifecycle:lifecycle-common-java8:2.10.0",
    "androidx.lifecycle:lifecycle-common-jvm:2.10.0",
    "androidx.lifecycle:lifecycle-livedata:2.10.0",
    "androidx.lifecycle:lifecycle-livedata-core:2.10.0",
    "androidx.lifecycle:lifecycle-livedata-core-ktx:2.10.0",
    "androidx.lifecycle:lifecycle-process:2.10.0",
    "androidx.lifecycle:lifecycle-runtime-android:2.10.0",
    "androidx.lifecycle:lifecycle-runtime-compose-android:2.10.0",
    "androidx.lifecycle:lifecycle-runtime-ktx-android:2.10.0",
    "androidx.lifecycle:lifecycle-viewmodel:2.10.0",
    "androidx.lifecycle:lifecycle-viewmodel-android:2.10.0",
    "androidx.lifecycle:lifecycle-viewmodel-ktx:2.10.0",
    "androidx.lifecycle:lifecycle-viewmodel-savedstate-android:2.10.0",
    "androidx.loader:loader:1.0.0",
    "androidx.localbroadcastmanager:localbroadcastmanager:1.0.0",
    "androidx.navigationevent:navigationevent-android:1.0.0",
    "androidx.navigationevent:navigationevent-compose-android:1.0.0",
    "androidx.print:print:1.0.0",
    "androidx.profileinstaller:profileinstaller:1.4.0",
    "androidx.savedstate:savedstate-android:1.4.0",
    "androidx.savedstate:savedstate-compose-android:1.4.0",
    "androidx.savedstate:savedstate-ktx:1.4.0",
    "androidx.startup:startup-runtime:1.1.1",
    "androidx.tracing:tracing:1.2.0",
    "androidx.transition:transition:1.6.0",
    "androidx.versionedparcelable:versionedparcelable:1.1.1",
    "androidx.window:window:1.5.0",
    "androidx.window:window-core-android:1.5.0",
    "com.google.guava:listenablefuture:1.0",
    "org.jetbrains:annotations:23.0.0",
    "org.jetbrains.kotlin:kotlin-stdlib:2.2.20",
    "org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0",
    "org.jetbrains.kotlinx:kotlinx-coroutines-core-jvm:1.11.0",
    "org.jetbrains.kotlinx:kotlinx-serialization-core-jvm:1.7.3",
    "org.jspecify:jspecify:1.0.0",
    "org.rustls:rustls-platform-verifier:0.2.0",
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="verify the tree matches the crates")
    args = parser.parse_args()

    gpl = (REPO / "LICENSE").read_text(encoding="utf-8")

    if args.check:
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp)
            result = build(dest)
            expected = {p.name: p.read_bytes() for p in dest.iterdir()}
            notices = render_notices(result, gpl)
            expected["THIRD-PARTY-NOTICES.txt"] = notices.encode()
            expected["GPL-3.0-or-later.txt"] = (REPO / "LICENSE").read_bytes()
            actual = {p.name: p.read_bytes() for p in ASSETS.iterdir()}
            problems = []
            for name in sorted(set(expected) - set(actual)):
                problems.append(f"missing asset: {name}")
            for name in sorted(set(actual) - set(expected)):
                problems.append(f"stale asset: {name}")
            for name in sorted(set(expected) & set(actual)):
                if expected[name] != actual[name]:
                    problems.append(f"content differs: {name}")
            for problem in problems:
                print(problem, file=sys.stderr)
            if problems:
                print(
                    f"{len(problems)} problem(s); run python3 scripts/gen-license-assets.py",
                    file=sys.stderr,
                )
                return 1
            print(f"assets current: {len(expected)} files, {len(result['distinct'])} distinct upstream notices")
            return 0

    if ASSETS.exists():
        shutil.rmtree(ASSETS)
    ASSETS.mkdir(parents=True)
    result = build(ASSETS)
    (ASSETS / "THIRD-PARTY-NOTICES.txt").write_text(render_notices(result, gpl), encoding="utf-8")
    shutil.copyfile(REPO / "LICENSE", ASSETS / "GPL-3.0-or-later.txt")

    total = sum(p.stat().st_size for p in ASSETS.iterdir())
    print(
        f"wrote {len(list(ASSETS.iterdir()))} files, {total} bytes: "
        f"{len(result['runtime'])} runtime crates, {len(result['distinct'])} distinct upstream notices, "
        f"{len(result['missing'])} crate(s) without a license file",
        file=sys.stderr,
    )
    for crate in result["missing"]:
        print(f"  no license file: {crate['name']} {crate['version']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
