package top.zztweb.zshield.filters

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Acceptance test 2: the plausibility check that stops an HTML page replacing a real list. */
class ListSanityTest {

    private val realList = """
        [Adblock Plus 2.0]
        ! Title: Sample
        ! Expires: 2 days
        ||ads.example^
        ||tracker.example^
        0.0.0.0 malware.example
        example.com##.ad-banner
    """.trimIndent()

    @Test
    fun a_real_list_passes() {
        assertEquals(ListSanity.Verdict.Ok, ListSanity.check(realList.toByteArray()))
    }

    @Test
    fun a_hosts_only_list_passes() {
        val hosts = (1..200).joinToString("\n") { "0.0.0.0 host$it.example.com" }
        assertEquals(ListSanity.Verdict.Ok, ListSanity.check(hosts.toByteArray()))
    }

    @Test
    fun an_html_page_is_rejected() {
        val html = """
            <!DOCTYPE html>
            <html><head><title>Captive portal</title></head>
            <body><h1>Please sign in to the WiFi</h1></body></html>
        """.trimIndent()
        val verdict = ListSanity.check(html.toByteArray())
        assertTrue(verdict is ListSanity.Verdict.Rejected)
        assertTrue((verdict as ListSanity.Verdict.Rejected).reason.contains("HTML"))
    }

    @Test
    fun an_html_page_with_a_leading_bom_or_whitespace_is_still_rejected() {
        val html = "﻿\n\n  <html><body>nope</body></html>"
        val verdict = ListSanity.check(html.toByteArray())
        assertTrue(verdict is ListSanity.Verdict.Rejected)
    }

    @Test
    fun an_html_content_type_is_rejected_even_without_html_markup() {
        val body = (1..50).joinToString("\n") { "||host$it.example^" }
        val verdict = ListSanity.check(body.toByteArray(), contentType = "text/html; charset=utf-8")
        assertTrue(verdict is ListSanity.Verdict.Rejected)
        assertTrue((verdict as ListSanity.Verdict.Rejected).reason.contains("Content-Type"))
    }

    @Test
    fun a_tiny_body_is_rejected() {
        val verdict = ListSanity.check("short".toByteArray())
        assertTrue(verdict is ListSanity.Verdict.Rejected)
        assertTrue((verdict as ListSanity.Verdict.Rejected).reason.contains("过短"))
    }

    @Test
    fun a_body_with_no_rules_is_rejected() {
        val prose = (1..100).joinToString("\n") { "This is just a sentence number $it in a text file." }
        val verdict = ListSanity.check(prose.toByteArray())
        assertTrue(verdict is ListSanity.Verdict.Rejected)
        assertTrue(
            (verdict as ListSanity.Verdict.Rejected).reason.contains("规则行") ||
                verdict.reason.contains("没有任何"),
        )
    }

    @Test
    fun a_body_with_too_few_rules_among_many_lines_is_rejected() {
        val lines = (1..1_000).map { index ->
            if (index == 500) "||only-rule.example^" else "arbitrary prose line $index"
        }
        val verdict = ListSanity.check(lines.joinToString("\n").toByteArray())
        assertTrue(verdict is ListSanity.Verdict.Rejected)
        assertTrue((verdict as ListSanity.Verdict.Rejected).reason.contains("占比"))
    }

    @Test
    fun binary_content_is_rejected() {
        val binary = ByteArray(256) { if (it % 7 == 0) 0.toByte() else (it and 0xff).toByte() }
        val verdict = ListSanity.check(binary)
        assertTrue(verdict is ListSanity.Verdict.Rejected)
        assertFalse((verdict as ListSanity.Verdict.Rejected).reason.isEmpty())
    }

    @Test
    fun rule_shapes_are_recognised() {
        for (line in listOf(
            "||a.example^",
            "|http://a.example",
            "@@||a.example^",
            "0.0.0.0 a.example",
            "127.0.0.1\tb.example",
            "a.example",
            "example.com##.ad",
            "example.com#@#.ad",
            "example.com#?#div",
            "/banner[0-9]+/",
        )) {
            assertTrue("must look like a rule: $line", ListSanity.looksLikeRule(line))
        }
        for (line in listOf(
            "",
            "! Title: x",
            "# comment",
            "[Adblock Plus 2.0]",
            "<html>",
            "he said hello",
            "localhost",
        )) {
            assertFalse("must not look like a rule: $line", ListSanity.looksLikeRule(line))
        }
    }

    @Test
    fun a_large_real_world_shaped_list_passes() {
        val body = buildString {
            append("! Title: Big\n! Expires: 1 day\n")
            for (index in 1..20_000) {
                if (index % 3 == 0) {
                    append("||host$index.example^\n")
                } else {
                    append("0.0.0.0 tracker$index.example.com\n")
                }
            }
        }
        assertEquals(ListSanity.Verdict.Ok, ListSanity.check(body.toByteArray()))
    }

    @Test
    fun the_ratio_is_computed_over_a_bounded_sample() {
        // A huge file whose first two thousand lines are rules: the sample is what decides, so a
        // later tail of junk cannot make a usable list fail.
        val body = buildString {
            for (index in 1..2_000) append("||host$index.example^\n")
            for (index in 1..50_000) append("junk line $index\n")
        }
        assertEquals(ListSanity.Verdict.Ok, ListSanity.check(body.toByteArray()))
    }

    @Test
    fun easy_list_shaped_network_rules_are_recognised() {
        // MYS-2742 device test: a real EasyList scored 0.4% and was rejected as "not a filter list",
        // so EasyList could never be enabled. Its body is mostly rules that neither start with `||`
        // nor name a domain. These are verbatim lines from `https://easylist.to/easylist/easylist.txt`
        // (2026-11-09), which is what makes this test worth having.
        for (line in listOf(
            "&rb=&uuid=\$third-party",
            "&subaffid=%\$subdocument,third-party",
            "-ad-manager/\$~stylesheet",
            "-ad-sidebar.\$image",
            "-ad.jpg.pagespeed.\$image",
            "-ads-manager/\$domain=~wordpress.org",
            "-ads/assets/\$script,domain=~web-ads.org",
            "-assets/ads.\$~script",
            "-banner-ads-\$~stylesheet",
            ".ads.controller.js\$script",
            ".ashx?AdID=",
            ".biz/?ce=\$third-party",
            "/adframe.",
            "^ad_provider=",
            "||a.example^",
        )) {
            assertTrue("must look like a rule: $line", ListSanity.looksLikeRule(line))
        }
    }

    @Test
    fun prose_is_still_not_a_rule() {
        // The other half: the bare-network-rule branch must not turn any single word into a rule, or
        // the HTML/prose rejection this class exists for would stop working.
        for (line in listOf(
            "he",
            "hello",
            "word",
            "The",
            "sentence",
            "<div>",
            "a</div>",
            "{}",
            "\\\\windows\\\\path",
        )) {
            assertFalse("must not look like a rule: $line", ListSanity.looksLikeRule(line))
        }
    }

    @Test
    fun a_real_easy_list_header_and_body_passes_the_sanity_check() {
        // A representative slice of EasyList: the 2 000-line header block plus the rule body, in the
        // proportions the real file has. Before the fix this shape was rejected.
        val body = buildString {
            append("[Adblock Plus 2.0]\n")
            for (index in 1..18) append("! header line $index\n")
            val rules = listOf(
                "&rb=&uuid=\$third-party",
                "-ad-manager/\$~stylesheet",
                "-ads/assets/\$script,domain=~web-ads.org",
                ".ads.controller.js\$script",
                "-banner-ads-\$~stylesheet",
                "||ads.example^",
                "example.com##.ad-banner",
            )
            while (length < 8_000) {
                for (rule in rules) append(rule).append('\n')
            }
        }
        assertEquals(ListSanity.Verdict.Ok, ListSanity.check(body.toByteArray()))
    }
}
