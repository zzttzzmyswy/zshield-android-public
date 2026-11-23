package top.zztweb.zshield.filters

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Acceptance test 2: same-origin enforcement for `!#include`. */
class ListPreprocessorTest {

    private val base = "https://lists.example/sub/a.txt"

    @Test
    fun same_origin_compares_scheme_host_and_port() {
        assertTrue(ListPreprocessor.sameOrigin(base, "https://lists.example/sub/b.txt"))
        assertTrue(ListPreprocessor.sameOrigin(base, "https://lists.example:443/b.txt"))
        assertTrue(ListPreprocessor.sameOrigin("http://lists.example/a", "http://lists.example:80/b"))
        assertFalse("different host", ListPreprocessor.sameOrigin(base, "https://cdn.example/b.txt"))
        assertFalse("different scheme", ListPreprocessor.sameOrigin(base, "http://lists.example/b.txt"))
        assertFalse("different port", ListPreprocessor.sameOrigin(base, "https://lists.example:8443/b.txt"))
        assertFalse("subdomain is a different origin", ListPreprocessor.sameOrigin(base, "https://api.lists.example/b.txt"))
        assertFalse("garbage", ListPreprocessor.sameOrigin(base, "not a url"))
    }

    @Test
    fun includes_are_expanded_in_place() {
        val body = """
            ! Title: parent
            ||parent.example^
            !#include child.txt
            ||after.example^
        """.trimIndent()
        val fetched = mutableListOf<String>()
        val expansion = ListPreprocessor.expand(body, base) { url ->
            fetched.add(url)
            if (url.endsWith("/child.txt")) "||child.example^\n" else null
        }

        assertEquals(listOf("https://lists.example/sub/child.txt"), fetched)
        assertTrue(expansion.text.contains("||parent.example^"))
        assertTrue(expansion.text.contains("||child.example^"))
        assertTrue(expansion.text.contains("||after.example^"))
        assertTrue(expansion.skipped.isEmpty())
        // The list itself is reported first, then what it pulled in.
        assertEquals(
            listOf(base, "https://lists.example/sub/child.txt"),
            expansion.fetchedUrls,
        )
    }

    @Test
    fun cross_origin_includes_are_refused_without_a_request() {
        val body = "||a.example^\n!#include https://evil.example/x.txt\n"
        val fetched = mutableListOf<String>()
        val expansion = ListPreprocessor.expand(body, base) { url ->
            fetched.add(url)
            "||evil.example^\n"
        }

        assertTrue("a cross-origin include must not be fetched", fetched.isEmpty())
        assertTrue(expansion.skipped.single().contains("跨源 include"))
        assertFalse(expansion.text.contains("||evil.example^"))
        // The rest of the list is still used.
        assertTrue(expansion.text.contains("||a.example^"))
    }

    @Test
    fun absolute_same_origin_includes_are_allowed() {
        val body = "!#include https://lists.example/other/b.txt\n"
        val expansion = ListPreprocessor.expand(body, base) { url ->
            if (url == "https://lists.example/other/b.txt") "||b.example^\n" else null
        }
        assertTrue(expansion.text.contains("||b.example^"))
    }

    /**
     * The interesting adversarial case: a same-origin include that itself includes a cross-origin
     * URL. The nested directive must be refused too, or the origin check would be a one-level trick.
     */
    @Test
    fun a_nested_cross_origin_include_is_also_refused() {
        val body = "!#include child.txt\n"
        val fetched = mutableListOf<String>()
        val expansion = ListPreprocessor.expand(body, base) { url ->
            fetched.add(url)
            when {
                url.endsWith("/child.txt") ->
                    "||child.example^\n!#include https://evil.example/deep.txt\n"
                else -> "||evil.example^\n"
            }
        }

        assertEquals(listOf("https://lists.example/sub/child.txt"), fetched)
        assertTrue(expansion.text.contains("||child.example^"))
        assertFalse(expansion.text.contains("||evil.example^"))
        assertTrue(expansion.skipped.any { it.contains("跨源 include") })
    }

    @Test
    fun a_failed_include_is_skipped_not_fatal() {
        val body = "||a.example^\n!#include missing.txt\n"
        val expansion = ListPreprocessor.expand(body, base) { null }
        assertTrue(expansion.text.contains("||a.example^"))
        assertTrue(expansion.skipped.single().contains("下载失败"))
    }

    @Test
    fun include_loops_are_bounded_by_depth_and_count() {
        // Every list includes itself: without a depth cap this never returns.
        var fetches = 0
        val expansion = ListPreprocessor.expand("!#include self.txt\n", base) {
            fetches++
            "!#include self.txt\n||loop.example^\n"
        }
        assertTrue("must terminate", fetches <= ListPreprocessor.MAX_INCLUDES)
        assertTrue(expansion.text.contains("||loop.example^"))
    }

    @Test
    fun the_include_count_cap_is_enforced() {
        val body = (1..40).joinToString("\n") { "!#include part$it.txt\n" }
        var fetches = 0
        val expansion = ListPreprocessor.expand(body, base) {
            fetches++
            "||part.example^\n"
        }
        assertEquals(ListPreprocessor.MAX_INCLUDES, fetches)
        assertTrue(expansion.skipped.any { it.contains("上限") })
    }

    @Test
    fun a_list_without_includes_is_returned_unchanged_apart_from_trailing_newline() {
        val body = "||a.example^\n||b.example^\n"
        val expansion = ListPreprocessor.expand(body, base) { error("must not fetch") }
        assertEquals("||a.example^\n||b.example^\n", expansion.text)
        assertEquals(listOf(base), expansion.fetchedUrls)
        assertTrue(expansion.skipped.isEmpty())
    }
}
