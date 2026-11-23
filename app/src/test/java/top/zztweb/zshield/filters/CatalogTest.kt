package top.zztweb.zshield.filters

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Acceptance test 2: `catalog.json` parsing and id uniqueness. */
class CatalogTest {

    private fun entry(
        id: String,
        name: String = "Name $id",
        category: String = "ads",
        url: String = "https://example.com/$id.txt",
    ) = """{"id":"$id","name":"$name","category":"$category","url":"$url"}"""

    @Test
    fun parses_every_field() {
        val entries = CatalogEntry.parseAll(
            """{"lists":[
                {"id":"a","name":"A","category":"privacy","url":"https://a.example/a.txt",
                 "mirrors":["https://b.example/a.txt"],"homepage":"https://a.example",
                 "license":"GPL-3.0","defaultEnabled":true}
            ]}"""
        )
        assertEquals(1, entries.size)
        val entry = entries.single()
        assertEquals("a", entry.id)
        assertEquals("A", entry.name)
        assertEquals("privacy", entry.category)
        assertEquals("https://a.example/a.txt", entry.url)
        assertEquals(listOf("https://b.example/a.txt"), entry.mirrors)
        assertEquals("https://a.example", entry.homepage)
        assertEquals("GPL-3.0", entry.license)
        assertTrue(entry.defaultEnabled)
        // The primary URL comes first, then the mirrors: that is the retry order.
        assertEquals(
            listOf("https://a.example/a.txt", "https://b.example/a.txt"),
            entry.candidates,
        )
    }

    @Test
    fun an_entry_without_mirrors_has_just_the_primary_url() {
        val entry = CatalogEntry.parseAll("""{"lists":[${entry("a")}]}""").single()
        assertTrue(entry.mirrors.isEmpty())
        assertEquals(listOf("https://example.com/a.txt"), entry.candidates)
    }

    @Test
    fun duplicate_ids_are_rejected() {
        val error = runCatching {
            CatalogEntry.parseAll("""{"lists":[${entry("dup")},${entry("dup")}]}""")
        }.exceptionOrNull()
        assertTrue(error is InvalidCatalogException)
        val message = requireNotNull(error).message.orEmpty()
        assertTrue(message, message.contains("重复 id"))
    }

    @Test
    fun missing_required_fields_are_rejected() {
        val cases = listOf(
            """{"lists":[{"name":"A","category":"ads","url":"https://a/b.txt"}]}""" to "id",
            """{"lists":[{"id":"a","category":"ads","url":"https://a/b.txt"}]}""" to "name",
            """{"lists":[{"id":"a","name":"A","url":"https://a/b.txt"}]}""" to "category",
            """{"lists":[{"id":"a","name":"A","category":"ads"}]}""" to "url",
        )
        for ((json, fragment) in cases) {
            val error = runCatching { CatalogEntry.parseAll(json) }.exceptionOrNull()
            assertTrue("$json must fail", error is InvalidCatalogException)
            val message = requireNotNull(error).message.orEmpty()
            assertTrue(message, message.contains(fragment))
        }
    }

    @Test
    fun unknown_categories_and_bad_urls_are_rejected() {
        val badCategory = runCatching {
            CatalogEntry.parseAll("""{"lists":[${entry("a", category = "trackers")}]}""")
        }.exceptionOrNull()
        assertTrue(badCategory is InvalidCatalogException)

        val badUrl = runCatching {
            CatalogEntry.parseAll("""{"lists":[${entry("a", url = "ftp://a/b.txt")}]}""")
        }.exceptionOrNull()
        assertTrue(badUrl is InvalidCatalogException)

        val badMirror = runCatching {
            CatalogEntry.parseAll(
                """{"lists":[{"id":"a","name":"A","category":"ads","url":"https://a/b.txt",
                     "mirrors":["not a url"]}]}"""
            )
        }.exceptionOrNull()
        assertTrue(badMirror is InvalidCatalogException)
    }

    @Test
    fun a_missing_lists_array_is_rejected() {
        val error = runCatching { CatalogEntry.parseAll("""{"entries":[]}""") }.exceptionOrNull()
        assertTrue(error is InvalidCatalogException)
    }

    @Test
    fun malformed_json_is_rejected_with_a_readable_message() {
        val error = runCatching { CatalogEntry.parseAll("{not json") }.exceptionOrNull()
        assertTrue(error is InvalidCatalogException)
        val message = requireNotNull(error).message.orEmpty()
        assertTrue(message, message.contains("JSON"))
    }

    /**
     * The shipped asset is checked here too: a typo in `catalog.json` would otherwise only show up on
     * a device, after an install.
     */
    @Test
    fun the_shipped_catalog_parses_and_has_unique_ids() {
        val asset = java.io.File("src/main/assets/filters/catalog.json")
        // Gradle runs unit tests with the module directory as the working directory; skip rather
        // than fail when the asset is not reachable (e.g. an IDE with a different cwd).
        if (!asset.isFile) return
        val entries = CatalogEntry.parseAll(asset.readText(Charsets.UTF_8))
        assertTrue("catalog must not be empty", entries.isNotEmpty())
        val ids = entries.map { it.id }
        assertEquals("catalog ids must be unique", ids.size, ids.toSet().size)
        // Task card §1 lists the lists that must be present.
        val required = listOf(
            "adguard-base", "adguard-tracking", "adguard-mobile", "adguard-url-tracking",
            "adguard-chinese", "adguard-annoyances", "adguard-dns",
            "easylist", "easyprivacy", "easylist-china",
            "ublock-filters", "ublock-privacy", "ublock-badware", "ublock-unbreak",
            "ublock-quick-fixes",
            "peter-lowe", "urlhaus", "hagezi-pro", "hagezi-multi-normal",
            "oisd-small", "oisd-big", "anti-ad", "cjx-annoyance",
        )
        for (id in required) {
            assertNotNull("catalog is missing required list $id", entries.firstOrNull { it.id == id })
        }
        // Default-enabled set from the task card.
        val defaults = entries.filter { it.defaultEnabled }.map { it.id }.toSet()
        assertEquals(
            setOf(
                "adguard-base", "adguard-tracking", "adguard-mobile", "adguard-url-tracking",
                "adguard-chinese", "easylist-china", "adguard-dns",
                "ublock-unbreak", "ublock-quick-fixes",
            ),
            defaults,
        )
        // Every URL must be https: filter lists are fetched over the network and a plaintext list is
        // trivially tamperable.
        for (entry in entries) {
            assertTrue("${entry.id} must use https: ${entry.url}", entry.url.startsWith("https://"))
            for (mirror in entry.mirrors) {
                assertTrue("${entry.id} mirror must use https: $mirror", mirror.startsWith("https://"))
            }
        }
    }

    @Test
    fun adguard_lists_use_the_ublock_compatible_build() {
        // adblock-rust parses uBO syntax; the `/extension/ublock/` build is the right one.
        val asset = java.io.File("src/main/assets/filters/catalog.json")
        if (!asset.isFile) return
        val entries = CatalogEntry.parseAll(asset.readText(Charsets.UTF_8))
        val adguard = entries.filter { it.url.contains("filters.adtidy.org/extension/ublock/") }
        assertTrue("expected several uBO-build AdGuard lists", adguard.size >= 6)
        // Nothing may point at the browser-extension-only or plaintext variants.
        for (entry in entries) {
            assertFalse("${entry.id}", entry.url.contains("/extension/chromium/"))
            assertFalse("${entry.id}", entry.url.contains("/filters/filters/"))
        }
    }

    @Test
    fun candidates_deduplicate_a_mirror_equal_to_the_primary() {
        val entry = CatalogEntry(
            id = "a",
            name = "A",
            category = "ads",
            url = "https://a/x.txt",
            mirrors = listOf("https://a/x.txt", "https://b/x.txt"),
        )
        assertEquals(listOf("https://a/x.txt", "https://b/x.txt"), entry.candidates)
    }

    @Test
    fun empty_entry_list_is_allowed() {
        assertEquals(emptyList<CatalogEntry>(), CatalogEntry.parseAll("""{"lists":[]}"""))
        assertNull(CatalogEntry.parseAll("""{"lists":[]}""").firstOrNull())
    }
}
