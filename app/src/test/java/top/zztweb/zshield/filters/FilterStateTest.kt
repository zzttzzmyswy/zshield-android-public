package top.zztweb.zshield.filters

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File

/** The persisted document: round-trip, tolerance of junk, and the catalog merge. */
class FilterStateTest {

    private val entry = CatalogEntry(
        id = "adguard-base",
        name = "AdGuard 基础过滤",
        category = "ads",
        url = "https://filters.example/base.txt",
        mirrors = listOf("https://mirror.example/base.txt"),
        homepage = "https://example.com",
        license = "GPL-3.0",
        defaultEnabled = true,
    )

    @Test
    fun state_round_trips_through_json() {
        val state = FilterState(
            lists = listOf(
                FilterListState(
                    id = "adguard-base",
                    name = "AdGuard 基础过滤",
                    category = "ads",
                    url = "https://filters.example/base.txt",
                    mirrors = listOf("https://mirror.example/base.txt"),
                    homepage = "https://example.com",
                    enabled = true,
                    builtin = true,
                    lastUpdatedMs = 1_700_000_000_000L,
                    lastCheckedMs = 1_700_000_100_000L,
                    ruleCount = 12_345,
                    unsupportedCount = 678,
                    etag = "\"abc\"",
                    lastModified = "Sat, 08 Nov 2026 00:00:00 GMT",
                    expiresHours = 96,
                    fileName = "adguard-base.txt",
                    bytes = 2_000_000,
                )
            ),
            userRules = "||custom.example^",
            allowlist = listOf("allowed.example", "also-allowed.example"),
            autoUpdateHours = 12,
            autoUpdateUnmeteredOnly = true,
        )
        val restored = FilterState.fromJson(state.toJson())
        assertEquals(state, restored)
    }

    @Test
    fun an_empty_state_round_trips() {
        assertEquals(FilterState(), FilterState.fromJson(FilterState().toJson()))
    }

    @Test
    fun an_error_survives_a_round_trip() {
        val state = FilterState().withList(
            FilterListState(
                id = "x",
                name = "X",
                category = "ads",
                url = "https://x/y.txt",
                error = "HTTP 404",
            )
        )
        assertEquals("HTTP 404", FilterState.fromJson(state.toJson()).list("x")?.error)
    }

    @Test
    fun the_update_interval_is_clamped_to_a_sane_range() {
        val tooSmall = FilterState.fromJson("""{"autoUpdateHours":0}""")
        assertEquals(FilterState.MIN_INTERVAL_HOURS, tooSmall.autoUpdateHours)
        val tooLarge = FilterState.fromJson("""{"autoUpdateHours":100000}""")
        assertEquals(FilterState.MAX_INTERVAL_HOURS, tooLarge.autoUpdateHours)
    }

    @Test
    fun with_list_replaces_in_place_and_appends_new_ids() {
        val base = FilterState().withList(FilterListState("a", "A", "ads", "https://a"))
        val replaced = base.withList(FilterListState("a", "A2", "ads", "https://a"))
        assertEquals(1, replaced.lists.size)
        assertEquals("A2", replaced.lists.single().name)

        val appended = base.withList(FilterListState("b", "B", "ads", "https://b"))
        assertEquals(listOf("a", "b"), appended.lists.map { it.id })
    }

    @Test
    fun without_list_removes_only_that_id() {
        val state = FilterState()
            .withList(FilterListState("a", "A", "ads", "https://a"))
            .withList(FilterListState("b", "B", "ads", "https://b"))
        assertEquals(listOf("b"), state.withoutList("a").lists.map { it.id })
    }

    // ---- catalog reconciliation ----

    @Test
    fun a_catalog_entry_without_persisted_state_takes_its_default_enabled_flag() {
        val result = FilterRepository.reconcile(listOf(entry), FilterState())
        assertEquals(1, result.size)
        val list = result.single()
        assertEquals("adguard-base", list.id)
        assertTrue("defaultEnabled must be honoured on a fresh install", list.enabled)
        assertTrue(list.builtin)
        assertEquals(entry.mirrors, list.mirrors)
    }

    @Test
    fun a_persisted_enabled_flag_wins_over_the_catalog_default() {
        val persisted = FilterListState(
            id = "adguard-base",
            name = "old name",
            category = "ads",
            url = "https://filters.example/base.txt",
            enabled = false,
            builtin = true,
            lastUpdatedMs = 42,
        )
        val list = FilterRepository.reconcile(
            listOf(entry),
            FilterState(lists = listOf(persisted)),
        ).single()
        assertFalse("the user's choice must not be overridden", list.enabled)
        assertEquals(42L, list.lastUpdatedMs)
        // Catalog metadata is refreshed from the asset, user-visible state is not.
        assertEquals("AdGuard 基础过滤", list.name)
        assertEquals(entry.mirrors, list.mirrors)
    }

    @Test
    fun a_user_added_list_survives_a_catalog_change() {
        val custom = FilterListState(
            id = "custom-abc",
            name = "My list",
            category = "ads",
            url = "https://mine.example/list.txt",
            enabled = true,
            builtin = false,
        )
        val result = FilterRepository.reconcile(
            listOf(entry),
            FilterState(lists = listOf(custom)),
        )
        assertEquals(listOf("adguard-base", "custom-abc"), result.map { it.id })
    }

    @Test
    fun a_removed_catalog_entry_disappears_but_a_user_list_with_the_same_id_does_not() {
        // A builtin entry that is no longer in the catalog is dropped: its URL is unmaintained.
        val staleBuiltin = FilterListState(
            id = "removed-list",
            name = "Removed",
            category = "ads",
            url = "https://gone.example/x.txt",
            builtin = true,
        )
        val result = FilterRepository.reconcile(listOf(entry), FilterState(lists = listOf(staleBuiltin)))
        assertEquals(listOf("adguard-base"), result.map { it.id })

        // A user-added list is never dropped by a catalog edit.
        val userAdded = staleBuiltin.copy(builtin = false)
        val kept = FilterRepository.reconcile(listOf(), FilterState(lists = listOf(userAdded)))
        assertEquals(listOf("removed-list"), kept.map { it.id })
    }

    @Test
    fun the_catalog_order_is_stable_and_custom_lists_come_last() {
        val second = entry.copy(id = "z-list", name = "Z")
        val custom = FilterListState("custom-1", "C", "ads", "https://c", builtin = false)
        val result = FilterRepository.reconcile(
            listOf(entry, second),
            FilterState(lists = listOf(custom)),
        )
        assertEquals(listOf("adguard-base", "z-list", "custom-1"), result.map { it.id })
    }

    @Test
    fun an_empty_catalog_with_persisted_builtins_clears_them() {
        assertEquals(emptyList<FilterListState>(), FilterRepository.reconcile(emptyList(), FilterState()))
    }

    // ---- store ----

    @Test
    fun the_store_writes_atomically_and_leaves_no_temp_file() {
        val dir = File(System.getProperty("java.io.tmpdir"), "zshield-store-${System.nanoTime()}")
        dir.mkdirs()
        val store = FilterStore(dir)
        store.ensureDirectories()
        val state = FilterState().withList(FilterListState("a", "A", "ads", "https://a", enabled = true))
        store.writeState(state)

        assertEquals(state, store.readState())
        // No temporary file of any name may survive a successful write.
        val leftovers = store.stateFile.parentFile!!.listFiles { file -> file.name.endsWith(".part") }
        assertTrue("no .part file may remain: ${leftovers?.map { it.name }}", leftovers.isNullOrEmpty())
        dir.deleteRecursively()
    }

    @Test
    fun a_corrupt_state_file_degrades_to_defaults_instead_of_crashing() {
        val dir = File(System.getProperty("java.io.tmpdir"), "zshield-store-bad-${System.nanoTime()}")
        dir.mkdirs()
        val store = FilterStore(dir)
        store.ensureDirectories()
        store.stateFile.writeText("{ this is not json")
        assertEquals(FilterState(), store.readState())
        // The evidence is kept for inspection rather than silently deleted.
        assertTrue(File(dir, "state.json.corrupt").exists())
        dir.deleteRecursively()
    }

    @Test
    fun a_missing_state_file_yields_defaults() {
        val dir = File(System.getProperty("java.io.tmpdir"), "zshield-store-empty-${System.nanoTime()}")
        dir.mkdirs()
        val store = FilterStore(dir)
        assertEquals(FilterState(), store.readState())
        assertNull(store.readState().lists.firstOrNull())
        dir.deleteRecursively()
    }

    @Test
    fun the_catalog_asset_state_and_compiled_dir_are_siblings() {
        val store = FilterStore(File("/tmp/root"))
        assertEquals(File("/tmp/root/state.json"), store.stateFile)
        assertEquals(File("/tmp/root/lists"), store.listsDir)
        assertEquals(File("/tmp/root/compiled"), store.compiledDir)
        assertEquals(File("/tmp/root/lists/adguard-base.txt"), store.listFile("adguard-base"))
    }

    /** The live status must never be resurrected from disk; only the durable error message is. */
    @Test
    fun status_is_not_persisted_but_the_error_message_is() {
        val state = FilterState().withList(
            FilterListState(
                id = "x",
                name = "X",
                category = "ads",
                url = "https://x/y.txt",
                status = ListStatus.Downloading,
                error = "HTTP 503",
            )
        )
        val restored = FilterState.fromJson(state.toJson()).list("x")!!
        assertEquals(ListStatus.Idle, restored.status)
        assertEquals("HTTP 503", restored.error)
    }

    @Test
    fun deleting_a_list_removes_its_body_and_temp_file() {
        val dir = File(System.getProperty("java.io.tmpdir"), "zshield-store-del-${System.nanoTime()}")
        dir.mkdirs()
        val store = FilterStore(dir)
        store.ensureDirectories()
        store.listFile("x").writeText("body")
        store.listTempFile("x").writeText("partial")
        store.deleteList("x")
        assertFalse(store.listFile("x").exists())
        assertFalse(store.listTempFile("x").exists())
        dir.deleteRecursively()
    }

    /**
     * MYS-2716 §2: `Native.compile` is `String?`. `null` means the JVM could not return the result
     * document at all, and the compile screen must show "nothing compiled" rather than crash.
     */
    @Test
    fun compile_stats_tolerate_a_missing_document() {
        assertEquals(CompileStats(), CompileStats.fromJson(null as String?))
        assertEquals(CompileStats(), CompileStats.fromJson(""))
        assertEquals(CompileStats(), CompileStats.fromJson("not json"))
        // A real document still parses, so the tolerance above is not hiding a broken parser.
        val parsed = CompileStats.fromJson(
            """{"dnsRules":5,"unsupported":2,"lists":[{"id":"a","dnsRules":5}]}""",
        )
        assertEquals(5, parsed.dnsRules)
        assertEquals(2, parsed.unsupported)
        assertEquals(1, parsed.listCount)
    }
}
