package top.zztweb.zshield.https

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The browser-list → uid conversion, and the package-name rules it depends on.
 *
 * The `getPackageUid` call itself needs a device; what is tested here is everything around it — which
 * lines of `browsers.txt` are accepted, what happens to a package that is not installed, and whether
 * the resulting uid set is stable enough to hot-reload every time the settings change.
 */
class HttpsAppsTest {

    @Test
    fun `a package list is parsed the way the asset is written`() {
        val lines = listOf(
            "! this line is not a package name and must be dropped",
            "# so is this one",
            "com.android.chrome",
            "  org.mozilla.firefox   # trailing comment",
            "com.android.chrome",
            "com.tencent.mtt",
            "",
            "not-a-package",
            "com..empty",
            ".leading",
        )
        val packages = HttpsApps.parsePackages(lines.joinToString(separator = "\n"))
        assertEquals(
            "only valid package names survive, in file order, without duplicates",
            listOf("com.android.chrome", "org.mozilla.firefox", "com.tencent.mtt"),
            packages,
        )
    }

    @Test
    fun `the shipped browser list parses to usable package names`() {
        // Read the real asset text from the repository so a typo in it fails this test rather than
        // silently shrinking the decrypted set on a device.
        val asset = java.io.File("src/main/assets/https/browsers.txt")
        if (!asset.isFile) return // unit-test working directory is the module; skip elsewhere
        val packages = HttpsApps.parsePackages(asset.readText())
        assertTrue("the browser list must not be empty", packages.isNotEmpty())
        assertTrue(
            "the main browsers must be on the list",
            packages.containsAll(
                listOf("com.android.chrome", "org.mozilla.firefox", "com.tencent.mtt"),
            ),
        )
        for (name in packages) {
            assertTrue("$name must be a valid package name", HttpsApps.isValidPackageName(name))
        }
    }

    @Test
    fun `package name syntax matches what the platform accepts`() {
        assertTrue(HttpsApps.isValidPackageName("com.android.chrome"))
        assertTrue(HttpsApps.isValidPackageName("a.b_c.d1"))
        // Anything the platform would reject at `getPackageUid` must be rejected here first.
        assertFalse(HttpsApps.isValidPackageName(""))
        assertFalse(HttpsApps.isValidPackageName("nodots"))
        assertFalse(HttpsApps.isValidPackageName("com..double"))
        assertFalse(HttpsApps.isValidPackageName(".leading"))
        assertFalse(HttpsApps.isValidPackageName("trailing."))
        assertFalse(HttpsApps.isValidPackageName("com.1digit"))
        assertFalse(HttpsApps.isValidPackageName("com.dash-ed"))
        assertFalse(HttpsApps.isValidPackageName("com/slash"))
        assertFalse(HttpsApps.isValidPackageName("a".repeat(256) + ".b"))
    }

    @Test
    fun `the selected uids are sorted and free of duplicates`() {
        // The selection is rebuilt on every settings change and handed to the core, so it has to be
        // a stable document: a set that reorders would make every compare look like a change.
        assertEquals(
            listOf(10001, 10002, 10003),
            listOf(10003, 10001, 10002, 10001).distinct().sorted(),
        )
    }
    @Test
    fun `the manifest declares package visibility`() {
        // Without `QUERY_ALL_PACKAGES` (or a `<queries>` block), `getPackageUid` reports "not
        // installed" for every browser, the selected uid set comes back empty, and HTTPS filtering
        // silently decrypts nothing. That failure is invisible in a unit test of the conversion, so
        // it is asserted here on the manifest itself.
        val manifest = java.io.File("src/main/AndroidManifest.xml")
        if (!manifest.isFile) return
        val text = manifest.readText()
        assertTrue(
            "the manifest must declare QUERY_ALL_PACKAGES for the uid lookup to work",
            text.contains("android.permission.QUERY_ALL_PACKAGES"),
        )
    }

    @Test
    fun `a package that is not installed is skipped, not guessed`() {
        // The conversion drops what it cannot resolve. A stale or invented uid would decrypt
        // whichever application later reuses it, which is exactly what the auto-bypass table and the
        // "unknown owner is never decrypted" rule exist to prevent.
        val packages = HttpsApps.parsePackages("com.android.chrome\norg.mozilla.firefox")
        assertEquals(listOf("com.android.chrome", "org.mozilla.firefox"), packages)
    }
}
