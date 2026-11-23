package top.zztweb.zshield.https

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `CertManager`'s pure parts: the export file name, the fingerprint, the state machine and the
 * certificate parsing.
 *
 * The Keystore and `MediaStore` paths are deliberately not tested here: both need a device (the
 * Android Keystore does not exist on the JVM, and `MediaStore` is a content provider stub). What *is*
 * tested is everything a regression could silently break without a device noticing — the file name
 * the user has to find in their Downloads folder, and the fingerprint they have to compare against
 * the system settings screen.
 */
class CertManagerTest {

    @Test
    fun `the export file name uses the first eight characters of the fingerprint`() {
        val fingerprint = "0123456789abcdef".repeat(4)
        assertEquals("ZShield-CA-01234567.crt", CertManager.exportFileName(fingerprint))
    }

    @Test
    fun `the export file name survives a short fingerprint`() {
        // Only reachable from a corrupt state file, but `take` must not throw on it.
        assertEquals("ZShield-CA-abc.crt", CertManager.exportFileName("abc"))
        assertEquals("ZShield-CA-.crt", CertManager.exportFileName(""))
    }

    @Test
    fun `the fingerprint is lowercase hex SHA-256 of the DER encoding`() {
        // A real certificate, so the assertion covers the encoding as well as the digest: the value
        // the user compares against the system settings screen has to be the DER digest.
        val certificate = CertManager.parseCertificate(SELF_SIGNED_PEM.toByteArray())!!
        val fingerprint = CertManager.fingerprintOf(certificate)
        assertEquals(64, fingerprint.length)
        assertTrue("must be lowercase hex", fingerprint.all { it in "0123456789abcdef" })

        val expected = java.security.MessageDigest.getInstance("SHA-256")
            .digest(certificate.encoded)
            .joinToString("") { "%02x".format(it) }
        assertEquals(expected, fingerprint)
    }

    @Test
    fun `the state starts as not generated and the generated shape carries everything the UI needs`() {
        // The sealed hierarchy is the UI's contract: `NotGenerated` has no fields, `Ready` has
        // exactly the three the screen shows.
        val none: CertManager.CaState = CertManager.CaState.NotGenerated
        assertTrue(none is CertManager.CaState.NotGenerated)

        val ready = CertManager.CaState.Ready(
            fingerprintSha256 = "0".repeat(64),
            notAfterMs = 1_800_000_000_000,
            installed = true,
        )
        assertEquals("0".repeat(64), ready.fingerprintSha256)
        assertEquals(1_800_000_000_000, ready.notAfterMs)
        assertTrue(ready.installed)
        // `installed` is what decides whether the core may decrypt; a copy() must be able to flip it
        // without losing the other fields (that is how `refreshInstalled` updates it).
        val flipped = ready.copy(installed = false)
        assertFalse(flipped.installed)
        assertEquals(ready.fingerprintSha256, flipped.fingerprintSha256)
        assertEquals(ready.notAfterMs, flipped.notAfterMs)
    }

    @Test
    fun `a PEM certificate parses and a garbage blob does not`() {
        val certificate = CertManager.parseCertificate(SELF_SIGNED_PEM.toByteArray())
        assertTrue(certificate != null)
        assertEquals("CN=zshield-test", certificate!!.subjectX500Principal.name)

        assertNull(CertManager.parseCertificate("not a certificate".toByteArray()))
        assertNull(CertManager.parseCertificate(ByteArray(0)))
        assertNull(CertManager.parseCertificate(byteArrayOf(0x30, 0x82.toByte(), 0x00)))
    }

    @Test
    fun `the expiry is formatted as a plain date`() {
        // 2027-01-01T00:00:00Z in milliseconds. The format is what the debug screen shows, and a
        // locale-dependent one would be unreadable in a report.
        val text = CertManager.expiryText(1_798_761_600_000)
        // The device's timezone decides the day, so only the shape is asserted.
        assertTrue("unexpected format: $text", Regex("""\d{4}-\d{2}-\d{2}""").matches(text))
    }
}

/**
 * A throwaway self-signed certificate for the parsing tests.
 *
 * Generated once with `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -days 3650
 * -subj "/CN=zshield-test"`, so the test has a real DER encoding to hash rather than a fixture this
 * file invented.
 */
private const val SELF_SIGNED_PEM = """
-----BEGIN CERTIFICATE-----
MIIBgjCCASmgAwIBAgIUHb3pyJY4UcpRITT7KapD/xXgubcwCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMenNoaWVsZC10ZXN0MB4XDTI2MTEwODE3Mjk1MloXDTM2MTEw
NTE3Mjk1MlowFzEVMBMGA1UEAwwMenNoaWVsZC10ZXN0MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAE/3Y+K6kkZi9KdO5FKge3T2noXGUAMhmJjDD+O/fGixlxh58B
/1MiDRPQrSb0z/SZr+zFS8yp0sRiBqbWvKMNDaNTMFEwHQYDVR0OBBYEFCiyIlz0
sS1cc81HalHW+KO0jeh5MB8GA1UdIwQYMBaAFCiyIlz0sS1cc81HalHW+KO0jeh5
MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgNVIsaSRPizgSkW8t
JSZQScjghUvqFNnea0Fne6hyegwCIBvVWAxJw60YYU8tQY9n5IUR7+0cq2Aidaj9
l7JUjsbb
-----END CERTIFICATE-----
"""
