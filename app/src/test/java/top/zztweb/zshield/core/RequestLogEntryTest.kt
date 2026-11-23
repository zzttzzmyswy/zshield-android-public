package top.zztweb.zshield.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The Kotlin side of the `recentRequestsJson` contract (`core/src/http/log.rs` owns the other side).
 *
 * The point of these tests is the wire format: the field names, the outcome spellings, the three
 * entry kinds and the degradation rules. A rename on either side would silently empty the log page,
 * which is the one place a user or a reviewer looks to see *why* something was blocked.
 */
class RequestLogEntryTest {

    @Test
    fun `an http entry is parsed with the keys the core emits`() {
        val json = """
            [{"id":7,"kind":"http","timeMs":1234,"atMs":1234,"host":"ads.example.com",
              "url":"http://ads.example.com/banner.js","truncated":false,"method":"GET",
              "resourceType":"script","outcome":"blocked",
              "rule":"||ads.example.com^${'$'}script","thirdParty":true,"cosmetic":false}]
        """.trimIndent()

        val entries = RequestLogEntry.listFromJson(json)
        assertEquals(1, entries.size)
        val entry = entries[0]
        assertEquals(7L, entry.id)
        assertEquals(RequestLogEntry.Kind.HTTP, entry.kind)
        assertEquals(1234L, entry.timeMs)
        assertEquals("ads.example.com", entry.host)
        assertEquals("http://ads.example.com/banner.js", entry.url)
        assertFalse(entry.truncated)
        assertEquals("GET", entry.method)
        assertEquals("script", entry.resourceType)
        assertEquals(RequestLogEntry.Outcome.BLOCKED, entry.outcome)
        assertEquals("||ads.example.com^${'$'}script", entry.rule)
        assertNull("an omitted field must stay absent rather than become an empty string", entry.exceptionRule)
        assertTrue(entry.thirdParty)
    }

    @Test
    fun `a dns entry is parsed with its own fields`() {
        val json = """
            [{"id":1,"kind":"dns","timeMs":10,"host":"ads.example.com","outcome":"blocked","qtype":"A"}]
        """.trimIndent()
        val entry = RequestLogEntry.listFromJson(json).single()
        assertEquals(RequestLogEntry.Kind.DNS, entry.kind)
        assertEquals("A", entry.qtype)
        assertEquals(RequestLogEntry.Outcome.BLOCKED, entry.outcome)
        // The HTTP-only fields stay at their defaults rather than borrowing another entry's meaning.
        assertEquals("", entry.url)
        assertEquals("", entry.method)
        assertEquals("", entry.resourceType)
        assertNull(entry.cname)
    }

    @Test
    fun `a cname block carries the blocked step and the reason`() {
        val json = """
            [{"id":2,"kind":"dns","timeMs":20,"host":"metrics.clean-site.com","outcome":"blocked",
              "qtype":"A","reason":"cname","cname":"tracker.doubleclick.net"}]
        """.trimIndent()
        val entry = RequestLogEntry.listFromJson(json).single()
        assertEquals("cname", entry.reason)
        assertEquals("tracker.doubleclick.net", entry.cname)
        assertEquals("metrics.clean-site.com", entry.host)
    }

    @Test
    fun `a connection entry carries its reason`() {
        val json = """
            [{"id":3,"kind":"connection","timeMs":30,"host":"dns.google","outcome":"blocked","reason":"dot"}]
        """.trimIndent()
        val entry = RequestLogEntry.listFromJson(json).single()
        assertEquals(RequestLogEntry.Kind.CONNECTION, entry.kind)
        assertEquals("dot", entry.reason)
        assertEquals(RequestLogEntry.Outcome.BLOCKED, entry.outcome)
        assertTrue(entry.blocked)
    }

    @Test
    fun `every kind spelling round trips and an absent one means http`() {
        val json = """
            [{"id":1,"kind":"dns"},{"id":2,"kind":"connection"},{"id":3,"kind":"http"},{"id":4}]
        """.trimIndent()
        val kinds = RequestLogEntry.listFromJson(json).map { it.kind }
        assertEquals(
            listOf(
                RequestLogEntry.Kind.DNS,
                RequestLogEntry.Kind.CONNECTION,
                RequestLogEntry.Kind.HTTP,
                // Pre-MYS-2742 data has no `kind`, and every such entry was an HTTP request.
                RequestLogEntry.Kind.HTTP,
            ),
            kinds,
        )
        // An unknown spelling degrades the same way rather than throwing.
        assertEquals(
            RequestLogEntry.Kind.HTTP,
            RequestLogEntry.listFromJson("""[{"kind":"something-new"}]""").single().kind,
        )
    }

    @Test
    fun `every outcome spelling round trips`() {
        val json = """
            [{"outcome":"allowed"},{"outcome":"blocked"},{"outcome":"redirected"},
             {"outcome":"exception"},{"outcome":"cached"}]
        """.trimIndent()
        val outcomes = RequestLogEntry.listFromJson(json).map { it.outcome }
        assertEquals(
            listOf(
                RequestLogEntry.Outcome.ALLOWED,
                RequestLogEntry.Outcome.BLOCKED,
                RequestLogEntry.Outcome.REDIRECTED,
                RequestLogEntry.Outcome.EXCEPTION,
                RequestLogEntry.Outcome.CACHED,
            ),
            outcomes,
        )
    }

    @Test
    fun `an unknown outcome degrades to allowed instead of throwing`() {
        // The log is a diagnostic view; a newer core with a new outcome must not blank the page.
        val entries = RequestLogEntry.listFromJson("""[{"outcome":"something-new"}]""")
        assertEquals(RequestLogEntry.Outcome.ALLOWED, entries[0].outcome)
    }

    @Test
    fun `an entry written before the timeMs rename still parses`() {
        // The core used to emit `atMs` only. Both spellings are read so a mixed-version install shows
        // a timestamp instead of 1970.
        val entry = RequestLogEntry.listFromJson("""[{"id":1,"atMs":4321}]""").single()
        assertEquals(4321L, entry.timeMs)
    }

    @Test
    fun `a malformed document yields an empty list`() {
        // `Native.recentRequestsJson` returns `[]` for an unknown handle; anything else that does not
        // parse must behave the same way rather than crash the screen.
        assertTrue(RequestLogEntry.listFromJson("").isEmpty())
        assertTrue(RequestLogEntry.listFromJson("not json").isEmpty())
        assertTrue(RequestLogEntry.listFromJson("[]").isEmpty())
        assertTrue(RequestLogEntry.listFromJson("""{"id":1}""").isEmpty())
        // A non-object element is skipped, not fatal.
        assertEquals(1, RequestLogEntry.listFromJson("""[null,{"id":3}]""").size)
    }

    @Test
    fun `the capacity and url limit mirror the core`() {
        // These two numbers describe the core's ring buffer (`core/src/http/log.rs`); the UI sizes its
        // paging against them, so they are pinned here.
        assertEquals(2000, RequestLogEntry.CAPACITY)
        assertEquals(512, RequestLogEntry.MAX_URL_LENGTH)
    }

    @Test
    fun `entries keep their order so the newest id is the cursor`() {
        val json = """
            [{"id":1,"host":"a.example"},{"id":2,"host":"b.example"},{"id":3,"host":"c.example"}]
        """.trimIndent()
        val entries = RequestLogEntry.listFromJson(json)
        assertEquals(listOf(1L, 2L, 3L), entries.map { it.id })
        // Polling with the newest id returns nothing new; that is how the UI decides not to redraw.
        assertEquals(3L, entries.last().id)
    }

    @Test
    fun `only blocked and redirected count as a block`() {
        // The UI's "blocked" chip and the home screen's counter must agree about what a block is.
        assertTrue(RequestLogEntry(outcome = RequestLogEntry.Outcome.BLOCKED).blocked)
        assertTrue(RequestLogEntry(outcome = RequestLogEntry.Outcome.REDIRECTED).blocked)
        assertFalse(RequestLogEntry(outcome = RequestLogEntry.Outcome.ALLOWED).blocked)
        assertFalse(RequestLogEntry(outcome = RequestLogEntry.Outcome.EXCEPTION).blocked)
        assertFalse(RequestLogEntry(outcome = RequestLogEntry.Outcome.CACHED).blocked)
    }

    @Test
    fun `the old type name still refers to the new model`() {
        // `HttpRequestLogEntry` is a typealias kept for the call sites that predate the rename.
        val entry: HttpRequestLogEntry = RequestLogEntry(id = 5, kind = RequestLogEntry.Kind.DNS)
        assertEquals(RequestLogEntry.Kind.DNS, entry.kind)
        assertEquals(2000, HttpRequestLogEntry.CAPACITY)
    }
}
