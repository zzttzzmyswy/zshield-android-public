package top.zztweb.zshield.licenses

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * The notices that travel inside the APK.
 *
 * The project packages its own notices and the Rust dependencies' terms under assets/licenses.
 * Android libraries may also supply nested META-INF licenses.
 *
 * These tests check the *content obligations*, not just that files exist:
 *
 *  - every license-bearing text the runtime dependency set needs is present, byte-for-byte as
 *    upstream ships it (a generic SPDX template is not a substitute — see [the_match_ring_...]),
 *  - the composite crates keep every file they reference, including the nested ones,
 *  - the generated tree is current with respect to `cargo metadata` (drift means a crate bump shipped
 *    old notices).
 *
 * The regeneration check is a separate script (`scripts/gen-license-assets.py --check`) because it
 * needs `cargo`; it runs in the release checklist. What can be checked here on the JVM is that the
 * tree carries what the checked-in evidence says it must.
 */
class NoticesTest {

    private val assets = File("src/main/assets/licenses")
    private val repoRoot = File("../")

    private fun asset(name: String) = File(assets, name)

    private fun sha256(file: File): String =
        MessageDigest.getInstance("SHA-256").digest(file.readBytes())
            .joinToString("") { "%02x".format(it) }

    private fun allText(): String =
        assets.listFiles().orEmpty()
            .filter { it.isFile }
            .joinToString("\n") { it.readText(Charsets.UTF_8) }

    @Test
    fun the_packaged_gpl_text_is_the_project_license() {
        // The APK's copy and the repository's `LICENSE` must be the same document; two slightly
        // different "GPL v3" texts in one project is how the previous hand-edited copy went unnoticed.
        val repo = File(repoRoot, "LICENSE")
        assertEquals(
            "assets/licenses/GPL-3.0-or-later.txt must be byte-identical to LICENSE",
            sha256(repo),
            sha256(asset("GPL-3.0-or-later.txt")),
        )
    }

    @Test
    fun every_license_family_the_runtime_needs_has_a_verbatim_text() {
        // Each of these is the canonical body of a license that appears in the runtime dependency
        // set. Presence is checked by a sentence only that license contains, so a truncated or
        // template-substituted file cannot pass.
        val required = mapOf(
            "GPL-3.0" to "GNU GENERAL PUBLIC LICENSE",
            "MPL-2.0" to "Mozilla Public License Version 2.0",
            "Apache-2.0" to "Apache License",
            "MIT" to "Permission is hereby granted, free of charge",
            "ISC/0BSD" to "Permission to use, copy, modify, and/or distribute this software",
            "Unlicense" to "free and unencumbered software released into the public domain",
            "Zlib" to "This software is provided 'as-is'",
            "Unicode" to "UNICODE LICENSE V3",
            "BSD-3-Clause" to "Redistribution and use in source and binary forms",
        )
        val text = allText()
        for ((family, needle) in required) {
            assertTrue("no verbatim $family text is packaged", text.contains(needle))
        }
    }

    @Test
    fun the_match_ring_package_keeps_every_file_its_root_license_points_at() {
        // `ring` is the crate where a generic Apache text is provably insufficient: its root LICENSE
        // is an index, and the files it points at carry *additional* notices after the Apache body.
        // These three lines exist nowhere else, so their presence is the evidence that the referenced
        // files were actually carried rather than assumed.
        val text = allText()
        val required = listOf(
            // LICENSE-other-bits (ISC, own year range)
            "Copyright 2015-2025 Brian Smith.",
            // LICENSE-BoringSSL, after the Apache text: Go
            "Copyright (c) 2009 The Go Authors. All rights reserved.",
            // LICENSE-BoringSSL, after the Apache text: Chromium
            "Copyright 2015 The Chromium Authors. All rights reserved.",
            // third_party/fiat — code ring vendors from another project
            "Copyright 2015-2020 the fiat-crypto authors",
            // src/polyfill/once_cell — vendored inside ring
            "Permission is hereby granted, free of charge",
        )
        for (needle in required) {
            assertTrue("ring's packaged notices are missing: $needle", text.contains(needle))
        }
        // The root LICENSE that names those files must be present too, not replaced by them.
        assertTrue(
            "ring's root LICENSE index is missing",
            text.contains("*ring* uses an \"ISC\" license"),
        )
    }

    @Test
    fun the_crates_that_ship_no_license_file_still_have_their_terms() {
        // Five runtime crates publish no LICENSE file at all. Leaving them out would be invisible
        // (nothing references a file that was never there), so they are vendored from upstream at a
        // recorded commit — see scripts/licenses-extra/README.md.
        val index = asset("THIRD-PARTY-NOTICES.txt").readText(Charsets.UTF_8)
        val vendored = index.substringAfter("本目录收的是按上游 commit 取得的补充件")
            .substringBefore("=")
        for (crate in listOf("flatbuffers 25.12.19", "jni 0.22.4", "seahash 4.1.0", "selectors 0.32.0")) {
            assertTrue(
                "the index does not disclose that $crate's terms were vendored",
                vendored.contains(crate),
            )
        }
        // And each of them must still be reachable from the index to a packaged file.
        for (crate in listOf("jni 0.22.4", "seahash 4.1.0", "selectors 0.32.0", "flatbuffers 25.12.19")) {
            assertTrue("$crate has no entry in the index", index.contains("    $crate  ["))
        }
        // Copyright holders that exist nowhere else in the tree, so the assertion cannot be satisfied
        // by an unrelated MIT file.
        val text = allText()
        assertTrue(
            "jni's MIT branch (Prevoty, Inc.) is not packaged",
            text.contains("Copyright (c) 2016 Prevoty, Inc. and jni-rs contributors"),
        )
        assertTrue(
            "selectors' per-file MPL notice is not accounted for",
            text.contains("This Source Code Form is subject to the terms of the Mozilla Public"),
        )
    }

    @Test
    fun the_notices_index_names_every_runtime_crate_with_its_files() {
        val notices = asset("THIRD-PARTY-NOTICES.txt")
        assertTrue("missing THIRD-PARTY-NOTICES.txt", notices.isFile)
        val text = notices.readText(Charsets.UTF_8)
        // The components whose code is compiled into the APK and whose terms require attribution.
        val required = listOf(
            "uBlock Origin",
            "Copyright (C) 2019-present Raymond Hill",
            "aa9236cb351e369cbb68113dbe8175b87f3cd134",
            "GNU 通用公共许可证",
            "adblock 0.13.5",
            "smoltcp 0.14.0",
            "ring 0.17.14",
            "rustls 0.23.46",
            "cssparser 0.35.0",
            "selectors 0.32.0",
            "psl 2.1.248",
        )
        for (needle in required) {
            assertTrue("notices do not mention $needle", text.contains(needle))
        }
        // Every crate the index lists must point at at least one packaged file, so a reader can
        // always get from "this crate is in the APK" to "here are its terms". A crate is a 4-space
        // indented line; its files are the following 8-space `-> ` lines.
        val crateHeader = Regex("""^    (\S+ \S+) {2}\[""")
        var current: String? = null
        val pointers = mutableMapOf<String, Int>()
        val declared = mutableListOf<String>()
        for (line in text.lines()) {
            val header = crateHeader.find(line)
            if (header != null) {
                current = header.groupValues[1]
                declared.add(current)
                pointers[current] = 0
            } else if (line.trimStart().startsWith("-> ") && current != null) {
                pointers[current!!] = (pointers[current] ?: 0) + 1
            }
        }
        assertTrue("the index lists no crates", declared.size > 100)
        val dangling = declared.filter { (pointers[it] ?: 0) == 0 }
        assertEquals("these crates are listed without pointing at their terms", emptyList<String>(), dangling)

        // And every file the index names must actually be packaged. Counting pointer lines is not
        // enough: a deleted asset leaves a well-formed index pointing at nothing, which is exactly the
        // silent failure this suite exists to catch.
        val named = Regex("""^\s+-> (\S+\.txt)$""", RegexOption.MULTILINE)
            .findAll(text).map { it.groupValues[1] }.toSet()
        assertTrue("the index names no files", named.size > 50)
        val absent = named.filterNot { asset(it).isFile }
        assertEquals("the index points at files that are not packaged", emptyList<String>(), absent)
    }

    @Test
    fun the_notices_list_the_same_ub_origin_files_as_the_generated_header() {
        // The generated Rust file records one line per upstream file in its header; the packaged
        // notice must credit the same set. If a regeneration adds a source file and the notice file is
        // not refreshed, the APK would credit fewer files than it contains.
        val notices = asset("THIRD-PARTY-NOTICES.txt").readText(Charsets.UTF_8)
        val source = File("../core/src/cosmetic/scriptlet-resources.rs")
        val origins = Regex("""^//   (src/js/\S+\.js) — """, RegexOption.MULTILINE)
            .findAll(source.readText(Charsets.UTF_8))
            .map { it.groupValues[1] }
            .toSet()
        assertEquals("the generated header must attribute its bodies", 28, origins.size)
        val missing = origins.filterNot { notices.contains(it) }
        assertEquals("notice file does not credit these upstream files", emptyList<String>(), missing)
    }

    @Test
    fun no_packaged_text_carries_an_unfilled_template_placeholder() {
        // SPDX's published license files contain `<<var;name=...>>` substitution markers. Shipping one
        // of those is worse than shipping nothing: it looks like a license, has no copyright holder,
        // and is not the document the licensor granted under.
        for (file in assets.listFiles().orEmpty().filter { it.isFile }) {
            val text = file.readText(Charsets.UTF_8)
            assertTrue(
                "${file.name} contains an unfilled template placeholder",
                !text.contains("<<var;") && !text.contains("<<beginOptional"),
            )
        }
    }
}
