package top.zztweb.zshield.settings

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * `AppSettings` persistence contract (task card §2).
 *
 * The defaults matter as much as the round trip: `full` mode with QUIC and encrypted-DNS bypass
 * blocked is what makes the tunnel filter *every* connection, and a regression to `dns_only` would
 * silently drop all SNI-level protection while every other test still passed.
 *
 * [AppSettings] is a process-wide singleton (the UI writes it, the VPN service reads it), so each test
 * points it at its own temporary store first.
 */
class AppSettingsTest {

    @get:Rule
    val temporaryFolder = TemporaryFolder()

    private fun store(): SettingsStore =
        SettingsStore(File(temporaryFolder.root, AppSettings.STORE_DIR_NAME))

    /** Points the singleton at a fresh store and returns it. */
    private fun freshSettings(): SettingsStore {
        val store = store()
        AppSettings.initializeForTest(store)
        return store
    }

    @Test
    fun `defaults match the task card`() {
        val data = AppSettingsData()
        assertEquals(TunnelMode.FULL, data.mode)
        assertEquals(emptyList<String>(), data.excludedApps)
        assertTrue(data.blockQuic)
        assertTrue(data.blockEncryptedDnsBypass)
    }

    @Test
    fun `a missing file yields the defaults`() {
        freshSettings()
        assertEquals(AppSettingsData(), AppSettings.current)
        assertFalse(store().stateFile.exists())
    }

    @Test
    fun `changes survive a restart`() {
        val store = freshSettings()

        AppSettings.setMode(TunnelMode.DNS_ONLY)
        AppSettings.setExcludedApps(listOf("com.android.chrome"))
        AppSettings.setBlockQuic(false)
        AppSettings.setBlockEncryptedDnsBypass(false)

        // What happens after a process restart: a new store over the same directory.
        AppSettings.initializeForTest(SettingsStore(store.stateFile.parentFile!!))
        assertEquals(TunnelMode.DNS_ONLY, AppSettings.current.mode)
        assertEquals(listOf("com.android.chrome"), AppSettings.current.excludedApps)
        assertFalse(AppSettings.current.blockQuic)
        assertFalse(AppSettings.current.blockEncryptedDnsBypass)
    }

    @Test
    fun `every writer and reader share one state flow`() {
        // The bug this guards: two `AppSettings` instances would each own a `MutableStateFlow`, so a
        // write from the UI would never reach the VPN service that is about to read it.
        freshSettings()
        val seen = mutableListOf<AppSettingsData>()
        seen.add(AppSettings.state.value)
        AppSettings.setMode(TunnelMode.DNS_ONLY)
        seen.add(AppSettings.state.value)
        assertEquals(TunnelMode.FULL, seen[0].mode)
        assertEquals(TunnelMode.DNS_ONLY, seen[1].mode)
        // And the value is readable through both accessors without a new instance.
        assertEquals(TunnelMode.DNS_ONLY, AppSettings.current.mode)
    }

    @Test
    fun `the document carries the field names the core and the UI rely on`() {
        val json = AppSettingsData(
            mode = TunnelMode.DNS_ONLY,
            excludedApps = listOf("com.example.app"),
            blockQuic = false,
            httpsFiltering = true,
            httpsUserApps = listOf("com.example.app"),
            httpsExcludedHosts = listOf("bank.example"),
        ).toJson()
        // v2 adds the M3a HTTPS fields, v3 the M4a keep-alive intent; a v1/v2 document still loads
        // (see the tests below).
        assertEquals(3, json.getInt("version"))
        assertEquals("dns_only", json.getString("mode"))
        assertEquals("com.example.app", json.getJSONArray("excludedApps").getString(0))
        assertFalse(json.getBoolean("blockQuic"))
        assertTrue(json.getBoolean("blockEncryptedDnsBypass"))
        assertTrue(json.getBoolean("httpsFiltering"))
        assertEquals("com.example.app", json.getJSONArray("httpsUserApps").getString(0))
        assertEquals("bank.example", json.getJSONArray("httpsExcludedHosts").getString(0))
        // The intent fields are part of the document the service and the UI agree on, so their
        // names are asserted here rather than only through a round trip.
        assertFalse(json.getBoolean("protectionWanted"))
        assertFalse(json.getBoolean("revokedBySystem"))
    }

    @Test
    fun `unknown and withheld fields fall back to the defaults`() {
        // A document written by an older build has neither field; a future one may add fields this
        // build does not know. Both must load rather than throw.
        val data = AppSettingsData.fromJson("""{"version":1,"mode":"full","futureField":42}""")
        assertEquals(TunnelMode.FULL, data.mode)
        assertTrue(data.blockQuic)
        assertTrue(data.blockEncryptedDnsBypass)

        val unknownMode = AppSettingsData.fromJson("""{"mode":"sideways"}""")
        assertEquals(TunnelMode.FULL, unknownMode.mode)
    }

    @Test
    fun `invalid package names are dropped instead of reaching the platform`() {
        // `addDisallowedApplication` throws NameNotFoundException for a name the platform considers
        // malformed; filtering them here is what keeps one bad entry from taking the tunnel down.
        val cleaned = AppSettings.sanitizePackages(
            listOf(
                "com.android.chrome",
                "",
                "  ",
                "no_dots",
                "com..double",
                ".leading",
                "trailing.",
                "com.example.app",
                "com.android.chrome", // duplicate
                "com.9leading",
                "com.example.app_with_underscore",
            ),
        )
        assertEquals(
            listOf("com.android.chrome", "com.example.app", "com.example.app_with_underscore"),
            cleaned,
        )
    }

    @Test
    fun `the excluded list is bounded and sorted`() {
        val many = (1..300).map { "com.example.app$it" }
        val cleaned = AppSettings.sanitizePackages(many)
        assertEquals(AppSettings.MAX_EXCLUDED_APPS, cleaned.size)
        assertEquals(cleaned.sorted(), cleaned)
    }

    @Test
    fun `a corrupt file falls back to the defaults and is kept for inspection`() {
        val store = store()
        store.stateFile.parentFile!!.mkdirs()
        store.stateFile.writeText("{not json")
        AppSettings.initializeForTest(store)
        assertEquals(AppSettingsData(), AppSettings.current)
        assertTrue(File(store.stateFile.parentFile, "${AppSettings.STATE_FILE_NAME}.corrupt").exists())
    }

    @Test
    fun `writes are atomic and leave no temporary behind`() {
        val store = freshSettings()
        repeat(5) { index -> AppSettings.setExcludedApps(listOf("com.example.app$index")) }
        val leftovers = store.stateFile.parentFile!!
            .listFiles { file -> file.name.endsWith(".part") }
            .orEmpty()
        assertEquals(0, leftovers.size)
        assertEquals(listOf("com.example.app4"), AppSettings.current.excludedApps)
    }
    // ---- M3a: HTTPS settings ----

    @Test
    fun `https filtering is off by default`() {
        // Decrypting is a visible trust decision the user has to make; it must never come on by
        // itself, and it must never be inferred from an installed certificate either.
        val data = AppSettingsData()
        assertFalse(data.httpsFiltering)
        assertEquals(emptyList<String>(), data.httpsUserApps)
        assertEquals(emptyList<String>(), data.httpsExcludedHosts)
    }

    @Test
    fun `https settings survive a restart`() {
        freshSettings()
        AppSettings.setHttpsFiltering(true)
        AppSettings.setHttpsUserApps(listOf("com.example.app", "  com.example.app  ", "bad name"))
        AppSettings.setHttpsExcludedHosts(listOf("Bank.Example.", "https://nope/x", "pay.example"))

        val reloaded = store().read()
        assertTrue(reloaded.httpsFiltering)
        assertEquals(listOf("com.example.app"), reloaded.httpsUserApps)
        assertEquals(listOf("bank.example", "pay.example"), reloaded.httpsExcludedHosts)
    }

    @Test
    fun `a version 1 document still loads with https off`() {
        // The document grew a version and three fields; an old file must keep working exactly as
        // before, i.e. with HTTPS filtering off.
        val store = store()
        store.stateFile.parentFile!!.mkdirs()
        store.stateFile.writeText(
            """
            {"version":1,"mode":"full","excludedApps":["com.example.app"],
             "blockQuic":true,"blockEncryptedDnsBypass":true}
            """.trimIndent(),
        )
        AppSettings.initializeForTest(store)
        val current = AppSettings.current
        assertEquals(TunnelMode.FULL, current.mode)
        assertEquals(listOf("com.example.app"), current.excludedApps)
        assertFalse(current.httpsFiltering)
        assertEquals(emptyList<String>(), current.httpsUserApps)
        assertEquals(emptyList<String>(), current.httpsExcludedHosts)
    }

    @Test
    fun `the user package list is sanitised the same way as the tunnel exclusion list`() {
        freshSettings()
        AppSettings.setHttpsUserApps(listOf("com.b.app", "com.a.app", "com.b.app", "broken"))
        assertEquals(listOf("com.a.app", "com.b.app"), AppSettings.current.httpsUserApps)
    }

    @Test
    fun `excluded host names are normalised and capped`() {
        freshSettings()
        assertEquals(
            listOf("bank.example", "pay.example", "sub.bank.example"),
            AppSettings.sanitizeHosts(
                listOf("Bank.Example.", "pay.example", "sub.bank.example", "BANK.EXAMPLE"),
            ),
        )
        // Anything the core's suffix matcher cannot use is dropped rather than stored.
        assertEquals(
            emptyList<String>(),
            AppSettings.sanitizeHosts(
                listOf("", "nodot", "https://bank.example/x", "*.example", "a b.example"),
            ),
        )
        val many = (0 until AppSettings.MAX_HTTPS_EXCLUDED_HOSTS + 20).map { "h$it.example" }
        assertEquals(
            AppSettings.MAX_HTTPS_EXCLUDED_HOSTS,
            AppSettings.sanitizeHosts(many).size,
        )
    }

    @Test
    fun `protection intent defaults to off`() {
        // A fresh install must not start filtering on its own: the consent dialog has not been shown
        // and the user has not asked for anything.
        freshSettings()
        assertFalse(AppSettings.current.protectionWanted)
        assertFalse(AppSettings.current.revokedBySystem)
    }

    @Test
    fun `the user turning protection on and off is persisted`() {
        val store = freshSettings()

        AppSettings.setProtectionWanted(true)
        assertTrue(AppSettings.current.protectionWanted)
        assertTrue("a fresh store must have the intent on disk", store.read().protectionWanted)

        AppSettings.setProtectionWanted(false)
        assertFalse(AppSettings.current.protectionWanted)
        assertFalse(store.read().protectionWanted)
    }

    @Test
    fun `turning protection on clears a recorded revocation`() {
        // The user just re-asserted the intent the revocation interrupted, so the "why is it off"
        // hint is stale from that moment on.
        freshSettings()
        AppSettings.setProtectionWanted(true)
        AppSettings.setRevokedBySystem(true)
        assertTrue(AppSettings.current.revokedBySystem)

        AppSettings.setProtectionWanted(true)
        assertTrue(AppSettings.current.protectionWanted)
        assertFalse(AppSettings.current.revokedBySystem)
    }

    @Test
    fun `a system revocation leaves the user's intent alone`() {
        // The distinction the task card is explicit about: `onRevoke` records the revocation but
        // must not turn "protection on" into "protection off", or recovery would stop trying.
        val store = freshSettings()
        AppSettings.setProtectionWanted(true)

        AppSettings.setRevokedBySystem(true)

        assertTrue("intent survives a revocation", AppSettings.current.protectionWanted)
        assertTrue(AppSettings.current.revokedBySystem)
        val reloaded = store.read()
        assertTrue(reloaded.protectionWanted)
        assertTrue(reloaded.revokedBySystem)
    }

    @Test
    fun `intent and revocation survive a process restart`() {
        val store = freshSettings()
        AppSettings.setProtectionWanted(true)
        AppSettings.setRevokedBySystem(true)

        // A new process: the singleton is re-pointed at the same directory and must read the file.
        AppSettings.initializeForTest(store)

        assertTrue(AppSettings.current.protectionWanted)
        assertTrue(AppSettings.current.revokedBySystem)
    }

    @Test
    fun `a version 2 document loads with recovery off`() {
        // An upgrade from v0.0.9 has no keep-alive fields. Reading them as "off" is the safe answer:
        // an upgrade must never start a tunnel the user had switched off, and the cost is one toggle
        // to arm recovery (docs/KEEPALIVE.md).
        val store = store()
        store.stateFile.parentFile!!.mkdirs()
        store.stateFile.writeText(
            """
            {"version":2,"mode":"dns_only","excludedApps":[],"blockQuic":false,
             "blockEncryptedDnsBypass":true,"httpsFiltering":true,
             "httpsUserApps":["com.example.browser"],"httpsExcludedHosts":["bank.example"]}
            """.trimIndent(),
        )
        AppSettings.initializeForTest(store)
        val current = AppSettings.current
        assertEquals(TunnelMode.DNS_ONLY, current.mode)
        assertFalse(current.blockQuic)
        assertTrue(current.httpsFiltering)
        assertEquals(listOf("com.example.browser"), current.httpsUserApps)
        assertFalse("an upgraded document must not arm auto-recovery", current.protectionWanted)
        assertFalse(current.revokedBySystem)
    }

    @Test
    fun `the document version records the new shape`() {
        freshSettings()
        AppSettings.setProtectionWanted(true)
        assertEquals(3, AppSettingsData.VERSION)
        assertTrue(store().stateFile.readText().contains("\"version\":3"))
    }
}

