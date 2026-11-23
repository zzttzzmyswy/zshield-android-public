package top.zztweb.zshield.ui.https

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import top.zztweb.zshield.R

class HttpsStatusTest {

    private fun of(
        enabled: Boolean = true,
        fullMode: Boolean = true,
        generated: Boolean = true,
        installed: Boolean = true,
        decrypting: Boolean = false,
    ) = HttpsStatus.of(enabled, fullMode, generated, installed, decrypting)

    @Test
    fun offWinsOverEverything() {
        assertEquals(HttpsStatus.OFF, of(enabled = false, fullMode = false, generated = false, installed = false))
        assertEquals(HttpsStatus.OFF, of(enabled = false, decrypting = true))
    }

    @Test
    fun problemsAreReportedInTheOrderTheUserFixesThem() {
        assertEquals(HttpsStatus.DNS_ONLY_MODE, of(fullMode = false, generated = false, installed = false))
        assertEquals(HttpsStatus.NEEDS_CERT, of(generated = false, installed = false))
        assertEquals(HttpsStatus.NEEDS_INSTALL, of(installed = false))
        assertTrue(HttpsStatus.NEEDS_INSTALL.needsAction)
    }

    @Test
    fun readyUntilTheCoreReportsDecrypting() {
        assertEquals(HttpsStatus.READY, of())
        assertEquals(HttpsStatus.ACTIVE, of(decrypting = true))
        assertFalse(HttpsStatus.ACTIVE.needsAction)
    }

    @Test
    fun shouldDecryptMatchesTheServiceRule() {
        assertTrue(HttpsStatus.shouldDecrypt(enabled = true, fullMode = true, certInstalled = true))
        assertFalse(HttpsStatus.shouldDecrypt(enabled = false, fullMode = true, certInstalled = true))
        assertFalse(HttpsStatus.shouldDecrypt(enabled = true, fullMode = false, certInstalled = true))
        assertFalse(HttpsStatus.shouldDecrypt(enabled = true, fullMode = true, certInstalled = false))
    }

    @Test
    fun fingerprintIsGroupedLikeTheSystemScreen() {
        val hex = "00112233445566778899aabbccddeeff" + "0123456789abcdef0123456789abcdef"
        assertEquals(
            "00:11:22:33:44:55:66:77\n88:99:AA:BB:CC:DD:EE:FF\n01:23:45:67:89:AB:CD:EF\n01:23:45:67:89:AB:CD:EF",
            HttpsText.fingerprint(hex),
        )
        assertEquals("not-hex", HttpsText.fingerprint("not-hex"))
    }

    @Test
    fun reasonsMapToWordingAndUnknownFallsBack() {
        assertEquals(R.string.ui_https_reason_unknown_ca, HttpsText.reason("client_unknown_ca"))
        assertEquals(R.string.ui_https_reason_disconnect, HttpsText.reason("client_disconnect"))
        assertEquals(R.string.ui_https_reason_handshake, HttpsText.reason("client_handshake_failed"))
        assertEquals(R.string.ui_https_reason_handshake, HttpsText.reason("something_new"))
    }

    @Test
    fun hoursLeftRoundsUpAndStopsAtZero() {
        val hour = 3_600_000L
        assertEquals(24, HttpsText.hoursLeft(0, 24 * hour))
        assertEquals(1, HttpsText.hoursLeft(0, 1))
        assertEquals(2, HttpsText.hoursLeft(0, hour + 1))
        assertEquals(0, HttpsText.hoursLeft(10, 10))
        assertEquals(0, HttpsText.hoursLeft(10, 5))
    }

    @Test
    fun listEntriesSkipCommentsAndBlankLines() {
        val text = "! header\n!\n# section\nalipay.com\n\n  bank.example  # trailing\n#only comment\n"
        assertEquals(2, HttpsText.countListEntries(text))
    }
}
