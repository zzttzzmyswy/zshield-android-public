package top.zztweb.zshield.filters

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File

/**
 * MYS-2742 §修复①: enabling a list, or adding a subscription, must download it.
 *
 * The reported bug was that `setEnabled` / `addCustom` only wrote state and scheduled a compile, so a
 * list with no body stayed at 「等待下载」 until the next app start. These tests drive the repository
 * against a scripted transport and a scripted compile, and assert what the user sees: a body on
 * disk, a rule count from the compile, and an error message when the download fails.
 */
class FilterRepositoryDownloadTest {

    private lateinit var dir: File
    private lateinit var store: FilterStore
    private lateinit var transport: FakeTransport

    /** Every compile request the repository made, in order. */
    private val compileRequests = mutableListOf<String>()

    /** Every per-URL line the updater emitted (MYS-2742 补充要求 4). */
    private val logLines = mutableListOf<String>()

    private var budgetMs: Long = ListUpdater.DEFAULT_BUDGET_MS

    private val body = """
        ! Title: Sample
        ||ads.example^
        ||tracker.example^
    """.trimIndent() + "\n"

    private fun entry(
        id: String,
        url: String = "https://lists.example/$id.txt",
        defaultEnabled: Boolean = false,
    ) = CatalogEntry(
        id = id,
        name = "Name $id",
        category = "ads",
        url = url,
        defaultEnabled = defaultEnabled,
    )

    @Before
    fun setUp() {
        dir = File(System.getProperty("java.io.tmpdir"), "zshield-repo-${System.nanoTime()}")
        dir.mkdirs()
        store = FilterStore(dir)
        store.ensureDirectories()
        transport = FakeTransport()
        compileRequests.clear()
        logLines.clear()
        budgetMs = ListUpdater.DEFAULT_BUDGET_MS

        FilterRepository.resetForTest()
        // No real debounce: the assertions are about what the download triggered, not about timing.
        FilterRepository.compileDebounceMs = 0
        // `Native.compile` is a JNI call, so the compile is scripted. The result it returns is the
        // same document the core produces (`core/src/compile.rs::CompileStats`).
        FilterRepository.compileFunction = { request ->
            compileRequests.add(request)
            val ids = Regex("\"id\":\"([^\"]+)\"").findAll(request).map { it.groupValues[1] }.toList()
            val perList = ids.joinToString(",") { id ->
                """{"id":"$id","lines":3,"dnsRules":2,"networkRules":0,"cosmeticRules":0,"unsupported":1,"bytes":64}"""
            }
            """{"lists":[$perList],"totalLines":${ids.size * 3},"dnsRules":${ids.size * 2},
               "networkRules":0,"cosmeticRules":0,"unsupported":${ids.size},
               "networkOnly":0,"dnsBlockRules":${ids.size * 2},"dnsExceptionRules":0,
               "allowlist":0,"elapsedMs":5,"dnsBytes":100,"engineBytes":200}""".trimIndent()
        }
        FilterRepository.lastErrorFunction = { "" }
        FilterRepository.reloadFunction = { _, _ -> true }
    }

    @After
    fun tearDown() {
        FilterRepository.resetForTest()
        FilterRepository.compileDebounceMs = FilterRepository.COMPILE_DEBOUNCE_MS
        dir.deleteRecursively()
    }

    private fun repository(vararg entries: CatalogEntry) {
        // No `Context`: a toggle only downloads and compiles, neither of which touches one.
        FilterRepository.initializeForTest(
            context = null,
            store = store,
            entries = entries.toList(),
            transport = transport,
            log = { logLines.add(it) },
            budgetMs = budgetMs,
        )
    }

    private fun state(id: String): FilterListState? =
        FilterRepository.lists.value.firstOrNull { it.id == id }

    /**
     * Wait until the debounced download-then-compile pass has finished.
     *
     * The pass runs on the repository's own IO scope, so there is no handle to join from outside;
     * this polls the observable state the UI polls. The debounce is 0 in these tests, but the pass is
     * still a coroutine, so the wait is a real poll rather than a yield.
     */
    private fun settle() = runBlocking {
        val deadline = System.currentTimeMillis() + 10_000
        while (System.currentTimeMillis() < deadline) {
            val compiled = FilterRepository.compileState.value
            val settling = FilterRepository.lists.value.any {
                it.status == ListStatus.Downloading ||
                    it.status == ListStatus.Compiling ||
                    it.status == ListStatus.Queued
            }
            if (!settling && (compiled is CompileState.Done || compiled is CompileState.Failed)) {
                return@runBlocking
            }
            delay(10)
        }
        throw AssertionError(
            "the pass never settled: compile=${FilterRepository.compileState.value} " +
                "lists=" + FilterRepository.lists.value.map { Triple(it.id, it.status, it.error) },
        )
    }

    @Test
    fun `enabling a list with no body downloads it and then compiles it`() = runBlocking {
        transport.onBody("https://lists.example/a.txt", body)
        repository(entry("a"))

        FilterRepository.setEnabled("a", true)
        settle()

        // 1. The body is on disk, which is what "downloaded" means.
        assertEquals(1, transport.requestsFor("https://lists.example/a.txt").size)
        assertTrue("a body must be written", store.listFile("a").isFile)
        assertEquals(body, store.listFile("a").readText())

        // 2. The list is no longer "等待下载": it has content and a rule count from the compile.
        val list = state("a")
        assertNotNull(list)
        assertTrue("the list must have content: $list", list!!.hasContent)
        assertEquals(2L, list.ruleCount)
        assertEquals(ListStatus.Idle, list.status)
        assertNull(list.error)

        // 3. It was compiled (this is what turns the download into filtering).
        assertTrue("a compile must have run", compileRequests.isNotEmpty())
        assertTrue(compileRequests.last().contains("\"a\""))
    }

    @Test
    fun `adding a custom url downloads it without a second call`() = runBlocking {
        val url = "https://lists.example/custom.txt"
        transport.onBody(url, body)
        repository()

        val id = FilterRepository.addCustom(url, "我的订阅").getOrThrow()
        settle()

        assertEquals(1, transport.requestsFor(url).size)
        val list = state(id)
        assertNotNull(list)
        assertTrue("the added list must have content: $list", list!!.hasContent)
        assertEquals("我的订阅", list.name)
        assertEquals(2L, list.ruleCount)
    }

    @Test
    fun `re-adding a known url does not download it again`() = runBlocking {
        val url = "https://lists.example/custom.txt"
        transport.onBody(url, body)
        repository()

        val first = FilterRepository.addCustom(url, null).getOrThrow()
        settle()
        assertEquals(1, transport.requestsFor(url).size)

        val second = FilterRepository.addCustom(url, null).getOrThrow()
        settle()
        assertEquals("the same URL must map to the same id", first, second)
        assertEquals(
            "a list that already has a body must not be fetched again by re-adding it",
            1,
            transport.requestsFor(url).size,
        )
    }

    @Test
    fun `enabling three lists in a row downloads one round`() = runBlocking {
        // The acceptance criterion for a burst of toggles: three enabled lists, three bodies, one
        // visit to each URL — and no URL fetched twice.
        //
        // A real debounce window is what makes this true (the production value is 1 s), so this test
        // uses one instead of the zero the other tests use: with no window there is nothing to
        // coalesce and the assertion would be about scheduling luck rather than about behaviour.
        FilterRepository.compileDebounceMs = 200
        transport.onBody("https://lists.example/a.txt", body)
        transport.onBody("https://lists.example/b.txt", body)
        transport.onBody("https://lists.example/c.txt", body)
        repository(entry("a"), entry("b"), entry("c"))

        FilterRepository.setEnabled("a", true)
        FilterRepository.setEnabled("b", true)
        FilterRepository.setEnabled("c", true)
        settle()

        assertEquals(1, transport.requestsFor("https://lists.example/a.txt").size)
        assertEquals(1, transport.requestsFor("https://lists.example/b.txt").size)
        assertEquals(1, transport.requestsFor("https://lists.example/c.txt").size)
        listOf("a", "b", "c").forEach { id ->
            assertTrue("$id must have content", state(id)!!.hasContent)
        }
    }

    @Test
    fun `a failed download leaves the error on the list`() = runBlocking {
        transport.onFailure("https://lists.example/a.txt", "HTTP 404")
        repository(entry("a"))

        FilterRepository.setEnabled("a", true)
        settle()

        val list = state("a")
        assertNotNull(list)
        assertFalse("a failed download must not look downloaded", list!!.hasContent)
        assertEquals(ListStatus.Error("https://lists.example/a.txt: HTTP 404"), list.status)
        assertNotNull("the reason must survive for the UI to show it", list.error)
        assertTrue(list.error!!.contains("404"))
    }

    @Test
    fun `a list that already has a body is not downloaded again by a toggle`() = runBlocking {
        // The other half of the fix: it must download *missing* bodies, not every toggle. A list the
        // user merely switches back on keeps its copy and only recompiles.
        store.writeAtomically(store.listFile("a"), body.toByteArray())
        store.writeState(
            FilterState(
                lists = listOf(
                    FilterListState(
                        id = "a",
                        name = "Name a",
                        category = "ads",
                        url = "https://lists.example/a.txt",
                        enabled = false,
                        builtin = true,
                        fileName = "a.txt",
                        lastUpdatedMs = 1_700_000_000_000L,
                    ),
                ),
            ),
        )
        repository(entry("a"))

        FilterRepository.setEnabled("a", true)
        settle()

        assertTrue("no network traffic for a list that already has a body", transport.requests.isEmpty())
        assertTrue(state("a")!!.enabled)
    }

    @Test
    fun `disabling a list downloads nothing`() = runBlocking {
        repository(entry("a"))
        FilterRepository.setEnabled("a", true)
        // Start from a downloaded list, then turn it off.
        transport.onBody("https://lists.example/a.txt", body)
        settle()
        transport.requests.clear()

        FilterRepository.setEnabled("a", false)
        settle()

        assertTrue("disabling must not fetch anything", transport.requests.isEmpty())
        assertFalse(state("a")!!.enabled)
    }

    // ---------------------------------------------------------------------------------------
    // Review of PR #14, item 1: no network on the caller's thread.
    // ---------------------------------------------------------------------------------------

    @Test
    fun `update all never touches the network on the calling thread`() {
        // The production caller is a Compose button, i.e. `Dispatchers.Main`. This test calls
        // `updateAll` from the *main* dispatcher with a transport that records the thread it was
        // called on, which reproduces the `NetworkOnMainThreadException` from the review exactly:
        // before the fix, every `HttpURLConnection` call happened on "main".
        transport.onBody("https://lists.example/a.txt", body)
        repository(entry("a"))
        runBlocking { FilterRepository.setEnabled("a", true) }
        settle()
        transport.threads.clear()

        // `runBlocking(Main)` cannot be used without the Android main looper, so the "caller is the
        // main thread" condition is modelled the way the platform enforces it: everything the call
        // happens on inherits a name, and any work escaping to another thread is visible.
        runBlocking {
            val caller = Thread.currentThread().name
            FilterRepository.updateAll(force = true)
            assertTrue(
                "the transport must have run, otherwise the assertion is vacuous: " +
                    transport.threads,
                transport.threads.isNotEmpty(),
            )
            assertTrue(
                "no download may run on the calling thread ($caller): ${transport.threads}",
                transport.threads.none { it == caller },
            )
            assertTrue(
                "downloads must run on an IO worker, not the caller: ${transport.threads}",
                transport.threads.all { it.contains("DefaultDispatcher") || it.contains("IO") },
            )
        }
    }

    @Test
    fun `toggling a list never touches the network on the calling thread`() {
        transport.onBody("https://lists.example/a.txt", body)
        repository(entry("a"))

        runBlocking {
            val caller = Thread.currentThread().name
            FilterRepository.setEnabled("a", true)
            settle()
            assertTrue(transport.threads.isNotEmpty())
            assertTrue(
                "no download may run on the calling thread ($caller): ${transport.threads}",
                transport.threads.none { it == caller },
            )
        }
    }

    // ---------------------------------------------------------------------------------------
    // Review of PR #14, item 2: a compile must not clear a download error.
    // ---------------------------------------------------------------------------------------

    @Test
    fun `a successful compile keeps the download error of a list that has old content`() =
        runBlocking {
            // A list with **old content** whose refresh failed: the old copy keeps filtering, so it is
            // part of the compile, and before the fix the compile's success branch wiped the error.
            store.writeAtomically(store.listFile("a"), body.toByteArray())
            store.writeState(
                FilterState(
                    lists = listOf(
                        FilterListState(
                            id = "a",
                            name = "Name a",
                            category = "ads",
                            url = "https://lists.example/a.txt",
                            enabled = true,
                            builtin = true,
                            fileName = "a.txt",
                            lastUpdatedMs = 1_700_000_000_000L,
                        ),
                    ),
                ),
            )
            transport.onFailure("https://lists.example/a.txt", "HTTP 500")
            repository(entry("a"))

            FilterRepository.updateAll(force = true)
            settle()

            val failed = state("a")!!
            assertTrue("the list still has its old body", failed.hasContent)
            assertEquals(ListStatus.Error("https://lists.example/a.txt: HTTP 500"), failed.status)
            assertNotNull("the download error must be visible", failed.error)

            // A compile now succeeds for this list (it has content) — and must not clear the error.
            FilterRepository.compileNow()

            val after = state("a")!!
            assertEquals(ListStatus.Error("https://lists.example/a.txt: HTTP 500"), after.status)
            assertEquals(
                "only a successful download may clear the error",
                "https://lists.example/a.txt: HTTP 500",
                after.error,
            )
        }

    @Test
    fun `a successful download clears the error it replaces`() = runBlocking {
        // The other side of the contract: the error does go away, and only on a download that works.
        transport.onFailure("https://lists.example/a.txt", "HTTP 500")
        repository(entry("a", defaultEnabled = true))
        FilterRepository.updateAll(force = true)
        settle()
        assertNotNull(state("a")!!.error)

        transport.onBody("https://lists.example/a.txt", body)
        FilterRepository.updateAll(force = true)
        settle()

        val recovered = state("a")!!
        assertNull("a successful download clears the error", recovered.error)
        assertEquals(ListStatus.Idle, recovered.status)
    }

    // ---------------------------------------------------------------------------------------
    // Review of PR #14, items 3 / 5 / 7: priority lane, bounded concurrency, queued status.
    // ---------------------------------------------------------------------------------------

    /**
     * Give a list a body on disk and persisted state, as if it had been downloaded before.
     *
     * Needed by the tests that care about what a 「全部更新」 round does to lists that *have* content:
     * a list without one would also be picked up by the toggle lane, which would muddy the point.
     */
    private fun seedDownloaded(id: String, enabled: Boolean = true) {
        store.writeAtomically(store.listFile(id), body.toByteArray())
        val current = store.readState()
        store.writeState(
            current.withList(
                FilterListState(
                    id = id,
                    name = "Name $id",
                    category = "ads",
                    url = "https://lists.example/$id.txt",
                    enabled = enabled,
                    builtin = true,
                    fileName = "$id.txt",
                    lastUpdatedMs = 1_700_000_000_000L,
                    lastCheckedMs = 0,
                ),
            ),
        )
    }

    private fun writeCompileArtifacts() {
        val compiler = FilterRepository.compileFunction
        FilterRepository.compileFunction = { request ->
            listOf("dns.bin", "engine.bin", "extras.txt").forEach { name ->
                File(store.compiledDir, name).writeText("compiled-$name")
            }
            compiler(request)
        }
    }

    @Test
    fun automatic_update_reuses_unchanged_artifacts_but_manual_update_compiles() = runBlocking {
        seedDownloaded("a")
        transport.onNotModified("https://lists.example/a.txt")
        writeCompileArtifacts()
        repository(entry("a"))
        FilterRepository.compileNow()
        assertEquals(1, compileRequests.size)

        // Android may start this job along with Application initialization. A 304 and the next
        // not-due pass must not replace startup reuse with an unconditional native compile.
        FilterRepository.updateAll(force = false)
        assertEquals(1, compileRequests.size)
        FilterRepository.updateAll(force = false)
        assertEquals(1, compileRequests.size)
        assertEquals(1, transport.requestsFor("https://lists.example/a.txt").size)

        FilterRepository.updateAll(force = true)
        assertEquals(2, compileRequests.size)
    }

    @Test
    fun automatic_update_compiles_when_the_download_changes_content() = runBlocking {
        seedDownloaded("a")
        transport.onBody("https://lists.example/a.txt", body + "||new.example^\n")
        writeCompileArtifacts()
        repository(entry("a"))
        FilterRepository.compileNow()
        FilterRepository.updateAll(force = false)
        assertEquals(2, compileRequests.size)
        assertTrue(store.listFile("a").readText().contains("||new.example^"))
    }

    @Test
    fun `a newly enabled list downloads without waiting for a full update round`() = runBlocking {
        // The MYSWY report: a list enabled while 「全部更新」 is running sits at 「等待下载」 for
        // minutes. `a` is held open below, so if the toggle lane still took `updateLock` the newly
        // enabled `c` could not start before the round finished — which is exactly the bug.
        val roundBlocked = java.util.concurrent.atomic.AtomicBoolean(false)
        val release = java.util.concurrent.CountDownLatch(1)
        transport.beforeAnswer = { url ->
            if (url.contains("/a.txt")) {
                roundBlocked.set(true)
                release.await(20, java.util.concurrent.TimeUnit.SECONDS)
            }
        }
        seedDownloaded("a")
        transport.onBody("https://lists.example/a.txt", body)
        transport.onBody("https://lists.example/c.txt", body)
        repository(entry("a", defaultEnabled = true), entry("c"))

        // On its own dispatcher: `runBlocking`'s event loop only advances while this coroutine
        // suspends, so a `launch` on its dispatcher would never run while we wait below.
        val round = launch(Dispatchers.Default) { FilterRepository.updateAll(force = true) }
        try {
            withTimeout(20_000) {
                while (!roundBlocked.get()) delay(10)
            }

            // Enable a never-downloaded list while the round is blocked on `a`.
            FilterRepository.setEnabled("c", true)

            withTimeout(30_000) {
                while (transport.requestsFor("https://lists.example/c.txt").isEmpty()) delay(10)
            }
            assertEquals(
                "a newly enabled list must start downloading during the round, not after it",
                1,
                transport.requestsFor("https://lists.example/c.txt").size,
            )
            assertEquals(
                "the round must still have been blocked when the new list downloaded",
                ListStatus.Downloading,
                state("a")!!.status,
            )
        } finally {
            release.countDown()
            round.join()
            settle()
        }

        assertTrue(state("c")!!.hasContent)
        assertTrue(transport.requestsFor("https://lists.example/a.txt").isNotEmpty())
    }

    @Test
    fun `a full update downloads at most three lists at once`() = runBlocking {
        val active = java.util.concurrent.atomic.AtomicInteger()
        val peak = java.util.concurrent.atomic.AtomicInteger()
        val ids = listOf("a", "b", "c", "d", "e", "f")
        ids.forEach { id ->
            seedDownloaded(id)
            transport.onBody("https://lists.example/$id.txt", body)
        }
        transport.beforeAnswer = { _ ->
            // Increment once, outside the CAS loop: a retried `updateAndGet` would count the same
            // fetch twice and make the peak assertion lie.
            val current = active.incrementAndGet()
            peak.updateAndGet { seen -> maxOf(seen, current) }
            Thread.sleep(20)
            active.decrementAndGet()
        }
        repository(*ids.map { entry(it, defaultEnabled = true) }.toTypedArray())

        withTimeout(60_000) { FilterRepository.updateAll(force = true) }

        assertEquals(
            "「全部更新」 must not exceed ${FilterRepository.DOWNLOAD_CONCURRENCY} concurrent downloads",
            FilterRepository.DOWNLOAD_CONCURRENCY,
            peak.get(),
        )
        ids.forEach { id -> assertTrue("$id must still have content", state(id)!!.hasContent) }
    }

    @Test
    fun `lists waiting for a download slot show as queued`() = runBlocking {
        // 补充要求 3: the queueing status exists so a waiting list does not read as 「等待下载」.
        val seen = java.util.Collections.synchronizedSet(mutableSetOf<String>())
        val ids = listOf("a", "b", "c", "d")
        ids.forEach { id ->
            seedDownloaded(id)
            transport.onBody("https://lists.example/$id.txt", body)
        }
        transport.beforeAnswer = { _ ->
            // Four lists, three slots: while three are in flight the fourth is visibly waiting.
            seen.addAll(FilterRepository.lists.value.map { "${it.id}=${it.status}" })
            Thread.sleep(50)
        }
        repository(*ids.map { entry(it, defaultEnabled = true) }.toTypedArray())

        withTimeout(60_000) { FilterRepository.updateAll(force = true) }

        assertTrue(
            "a list waiting for a slot must be reported as Queued: $seen",
            seen.any { it.endsWith("=Queued") },
        )
    }

    @Test
    fun `every candidate url is logged with its elapsed time and result`() = runBlocking {
        transport.onFailure("https://lists.example/a.txt", "HTTP 404 Not Found")
        repository(entry("a"))

        FilterRepository.setEnabled("a", true)
        settle()

        assertTrue("a line per candidate URL: $logLines", logLines.isNotEmpty())
        assertTrue(
            "the line must carry the URL, the result and the elapsed time: $logLines",
            logLines.any {
                it.contains("https://lists.example/a.txt") &&
                    it.contains("HTTP 404") &&
                    it.contains("ms")
            },
        )
    }

    @Test
    fun `a list with no body is downloaded before lists that only need a refresh`() = runBlocking {
        // 补充要求 1: the lists the user is waiting on go first. Five lists, three slots: with every
        // download held open, exactly the first three in priority order get a slot. Both
        // content-less lists must be among them, whatever order the IO threads happen to run in.
        val release = java.util.concurrent.CountDownLatch(1)
        // Recorded inside the hook: the fake transport only logs a request after the hook returns,
        // and the hook is what holds every download open here.
        val started = java.util.Collections.synchronizedList(mutableListOf<String>())
        transport.beforeAnswer = { url ->
            started.add(url)
            release.await(20, java.util.concurrent.TimeUnit.SECONDS)
        }
        for (id in listOf("r1", "r2", "r3")) {
            seedDownloaded(id)
            transport.onBody("https://lists.example/$id.txt", body)
        }
        transport.onBody("https://lists.example/fresh1.txt", body)
        transport.onBody("https://lists.example/fresh2.txt", body)
        repository(
            entry("r1", defaultEnabled = true),
            entry("r2", defaultEnabled = true),
            entry("r3", defaultEnabled = true),
            entry("fresh1", defaultEnabled = true),
            entry("fresh2", defaultEnabled = true),
        )

        val round = launch(Dispatchers.Default) { FilterRepository.updateAll(force = true) }
        try {
            withTimeout(20_000) {
                while (started.size < 3) delay(10)
            }
            delay(200) // a fourth request would have to wait for a slot; give it the chance to appear
            val inFlight = synchronized(started) { started.toList() }
            assertEquals("three slots, three downloads in flight: $inFlight", 3, inFlight.size)
            assertTrue(
                "both content-less lists must hold a slot before any refresh waits: $inFlight",
                inFlight.containsAll(
                    listOf("https://lists.example/fresh1.txt", "https://lists.example/fresh2.txt"),
                ),
            )
        } finally {
            release.countDown()
            round.join()
            settle()
        }
    }
}
