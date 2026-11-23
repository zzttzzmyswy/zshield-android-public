package top.zztweb.zshield.https

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The `httpsBypassJson` contract (`docs/JNI.md` §7).
 *
 * The array is what the UI shows when a user asks "why is this app not filtered", so a field the core
 * renames must fail here rather than show a blank row on a device.
 */
class BypassEntryTest {

    @Test
    fun `the core's array parses into entries`() {
        val json = """
            [{"uid":10123,"host":"bank.example","expiresAtMs":1767225600000,
              "reason":"client_unknown_ca"},
             {"uid":10456,"host":"pin.example","expiresAtMs":1767225600000,
              "reason":"client_bad_certificate"}]
        """.trimIndent()
        val entries = BypassEntry.listFromJson(json)
        assertEquals(2, entries.size)
        assertEquals(10123, entries[0].uid)
        assertEquals("bank.example", entries[0].host)
        assertEquals(1767225600000L, entries[0].expiresAtMs)
        assertEquals("client_unknown_ca", entries[0].reason)
        assertEquals("client_bad_certificate", entries[1].reason)
    }

    @Test
    fun `an empty or malformed document is an empty list`() {
        // A disabled pipeline returns `[]`, and a truncated response must not crash the screen.
        assertTrue(BypassEntry.listFromJson("[]").isEmpty())
        assertTrue(BypassEntry.listFromJson("").isEmpty())
        assertTrue(BypassEntry.listFromJson("not json").isEmpty())
        assertTrue(BypassEntry.listFromJson("{}").isEmpty())
    }

    @Test
    fun `a partial entry keeps the fields it has`() {
        val entries = BypassEntry.listFromJson("""[{"host":"a.example"}]""")
        assertEquals(1, entries.size)
        assertEquals("a.example", entries[0].host)
        assertEquals(0, entries[0].uid)
        assertEquals("", entries[0].reason)
        assertEquals(0L, entries[0].expiresAtMs)
    }
}
