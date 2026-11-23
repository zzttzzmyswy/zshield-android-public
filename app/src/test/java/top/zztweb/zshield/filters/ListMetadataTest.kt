package top.zztweb.zshield.filters

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Acceptance test 2: `! Expires:` parsing and the rest of the list header. */
class ListMetadataTest {

    @Test
    fun parses_a_full_easylist_style_header() {
        val metadata = ListMetadata.parse(
            """
            [Adblock Plus 2.0]
            ! Title: EasyList
            ! Version: 202611080906
            ! Expires: 4 days
            ! Homepage: https://easylist.to/
            ! Licence: https://easylist.to/pages/licence.html
            ||ads.example^
            """.trimIndent()
        )
        assertEquals("EasyList", metadata.title)
        assertEquals("202611080906", metadata.version)
        assertEquals(96L, metadata.expiresHours)
        assertEquals("https://easylist.to/", metadata.homepage)
    }

    @Test
    fun parses_a_ublock_style_header() {
        val metadata = ListMetadata.parse(
            """
            ! Title: uBlock filters
            ! Last modified: Sat, 07 Nov 2026 02:04:14 +0000
            ! Expires: 5 days (update frequency)
            ! Homepage: https://github.com/uBlockOrigin/uAssets
            """.trimIndent()
        )
        assertEquals("uBlock filters", metadata.title)
        assertEquals(120L, metadata.expiresHours)
    }

    @Test
    fun stops_at_the_first_rule() {
        val metadata = ListMetadata.parse(
            """
            ! Title: First
            ||rule.example^
            ! Title: Not the header
            """.trimIndent()
        )
        assertEquals("First", metadata.title)
        assertEquals(1, metadata.headerLines)
    }

    @Test
    fun a_list_without_a_header_yields_nulls() {
        val metadata = ListMetadata.parse("||a.example^\n||b.example^")
        assertNull(metadata.title)
        assertNull(metadata.expiresHours)
        assertEquals(0, metadata.headerLines)
    }

    @Test
    fun expires_accepts_every_documented_unit() {
        assertEquals(1L, ListMetadata.parseExpiresHours("1 hour"))
        assertEquals(3L, ListMetadata.parseExpiresHours("3 hours"))
        assertEquals(24L, ListMetadata.parseExpiresHours("1 day"))
        assertEquals(96L, ListMetadata.parseExpiresHours("4 days"))
        assertEquals(168L, ListMetadata.parseExpiresHours("1 week"))
        assertEquals(336L, ListMetadata.parseExpiresHours("2 weeks"))
        // Bare number: ABP's own docs treat it as days.
        assertEquals(48L, ListMetadata.parseExpiresHours("2"))
        // Abbreviations uBO/AdGuard use.
        assertEquals(12L, ListMetadata.parseExpiresHours("12h"))
        assertEquals(48L, ListMetadata.parseExpiresHours("2d"))
        // Minutes round up to the one-hour minimum rather than to zero.
        assertEquals(1L, ListMetadata.parseExpiresHours("30 minutes"))
        // A trailing explanation is ignored.
        assertEquals(96L, ListMetadata.parseExpiresHours("4 days (update frequency)"))
        // Case-insensitive.
        assertEquals(96L, ListMetadata.parseExpiresHours("4 Days"))
    }

    @Test
    fun expires_rejects_nonsense() {
        assertNull(ListMetadata.parseExpiresHours(""))
        assertNull(ListMetadata.parseExpiresHours("soon"))
        assertNull(ListMetadata.parseExpiresHours("0 days"))
        assertNull(ListMetadata.parseExpiresHours("-4 days"))
    }

    @Test
    fun parsing_is_bounded_by_the_header_limit() {
        val builder = StringBuilder()
        for (index in 0 until 500) builder.append("! filler: $index\n")
        builder.append("! Title: Too late\n")
        val metadata = ListMetadata.parse(builder.toString())
        assertNull("the header must not be scanned past its limit", metadata.title)
        assertEquals(ListMetadata.HEADER_LIMIT, metadata.headerLines)
    }

    @Test
    fun the_first_value_wins_over_a_later_duplicate() {
        val metadata = ListMetadata.parse("! Title: First\n! Title: Second\n")
        assertEquals("First", metadata.title)
    }

    @Test
    fun comment_lines_without_a_key_are_ignored() {
        val metadata = ListMetadata.parse(
            "! just a comment\n! Checksum: abc\n! Title: Real\n"
        )
        assertEquals("Real", metadata.title)
        assertTrue(metadata.headerLines >= 3)
    }
}
