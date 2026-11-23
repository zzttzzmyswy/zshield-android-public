package top.zztweb.zshield.filters

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File

/**
 * A transport whose answers are scripted per URL, recording every request.
 *
 * The acceptance criterion is "条件请求 304 不触发重编译（可用本地 HTTP 测试服务器或注入假传输层）";
 * this is the injected fake, which makes the interesting cases (304, mirror fallback, HTML body,
 * same-bytes-200) cheap and deterministic.
 */
class FakeTransport(
    var maxBytes: Int = Int.MAX_VALUE,
) : FilterTransport {

    data class Request(val url: String, val etag: String?, val lastModified: String?)

    val requests = mutableListOf<Request>()

    /**
     * The name of the thread each `fetch` ran on.
     *
     * Recorded so a test can prove no download happens on the caller's thread — the
     * `NetworkOnMainThreadException` regression from the MYS-2742 review is exactly "which thread is
     * this on", which no amount of mocking `HttpURLConnection` would show.
     */
    val threads = java.util.Collections.synchronizedList(mutableListOf<String>())

    /** Runs before the scripted answer, so a test can hold a download open. */
    @Volatile
    var beforeAnswer: ((String) -> Unit)? = null

    /** URL → scripted answer; a missing entry means "connection refused". */
    private val answers = LinkedHashMap<String, () -> DownloadResult>()

    fun on(url: String, answer: () -> DownloadResult) {
        answers[url] = answer
    }

    fun onBody(url: String, body: String, etag: String? = null, lastModified: String? = null) {
        on(url) {
            DownloadResult.Downloaded(
                body = body.toByteArray(),
                etag = etag,
                lastModified = lastModified,
                finalUrl = url,
            )
        }
    }

    fun onNotModified(url: String) {
        on(url) { DownloadResult.NotModified }
    }

    fun onFailure(url: String, message: String = "HTTP 404") {
        on(url) { throw DownloadException(message) }
    }

    override fun fetch(
        url: String,
        etag: String?,
        lastModified: String?,
        deadlineMs: Long,
    ): DownloadResult {
        threads.add(Thread.currentThread().name)
        val hook = beforeAnswer
        hook?.invoke(url)
        synchronized(requests) { requests.add(Request(url, etag, lastModified)) }
        val answer = synchronized(answers) { answers[url] }
            ?: throw DownloadException("connection refused: $url")
        return answer()
    }

    fun requestsFor(url: String): List<Request> =
        synchronized(requests) { requests.filter { it.url == url } }
}

/** The list updater's behaviour, tested without Android. */
class ListUpdaterTest {

    private lateinit var dir: File
    private lateinit var store: FilterStore
    private lateinit var transport: FakeTransport
    private var clock = 1_700_000_000_000L

    private val body = """
        ! Title: Sample
        ! Expires: 1 day
        ||ads.example^
        ||tracker.example^
    """.trimIndent() + "\n"

    @Before
    fun setUp() {
        dir = File(System.getProperty("java.io.tmpdir"), "zshield-updater-${System.nanoTime()}")
        dir.mkdirs()
        store = FilterStore(dir)
        store.ensureDirectories()
        transport = FakeTransport()
        clock = 1_700_000_000_000L
    }

    private fun updater() = ListUpdater(store, transport, now = { clock })

    private fun state(
        id: String = "sample",
        url: String = "https://lists.example/a.txt",
        etag: String? = null,
        lastModified: String? = null,
        lastCheckedMs: Long = 0,
        fileName: String? = null,
        mirrors: List<String> = emptyList(),
    ) = FilterListState(
        id = id,
        name = id,
        category = "ads",
        url = url,
        mirrors = mirrors,
        etag = etag,
        lastModified = lastModified,
        lastCheckedMs = lastCheckedMs,
        fileName = fileName,
    )

    @Test
    fun a_fresh_download_is_written_and_reported_as_updated() {
        transport.onBody("https://lists.example/a.txt", body, etag = "\"v1\"", lastModified = "Sat, 08 Nov 2026 00:00:00 GMT")
        val outcome = updater().update(state(), force = false)

        assertTrue(outcome is UpdateOutcome.Updated)
        val updated = (outcome as UpdateOutcome.Updated).state
        assertEquals("\"v1\"", updated.etag)
        assertEquals("Sat, 08 Nov 2026 00:00:00 GMT", updated.lastModified)
        assertEquals(clock, updated.lastUpdatedMs)
        assertEquals(body.toByteArray().size.toLong(), updated.bytes)
        assertEquals(24L, updated.expiresHours)
        assertNull(updated.error)
        assertArrayEquals(body.toByteArray(), store.listFile("sample").readBytes())
    }

    /** The acceptance criterion: a 304 must not rewrite the file and must not ask for a compile. */
    @Test
    fun a_304_keeps_the_body_and_reports_not_modified() {
        transport.onBody("https://lists.example/a.txt", body, etag = "\"v1\"")
        val first = updater().update(state(), force = false) as UpdateOutcome.Updated
        val writtenAt = store.listFile("sample").lastModified()

        clock += 3_600_000L
        transport.requests.clear()
        transport.onNotModified("https://lists.example/a.txt")
        // `force` because the list declares `! Expires: 1 day` and only an hour has passed; the due
        // check is covered by its own test.
        val outcome = updater().update(first.state, force = true)

        assertTrue("304 must map to NotModified", outcome is UpdateOutcome.NotModified)
        val after = (outcome as UpdateOutcome.NotModified).state
        assertEquals("the body must not be rewritten", writtenAt, store.listFile("sample").lastModified())
        assertEquals("lastUpdatedMs must not move", first.state.lastUpdatedMs, after.lastUpdatedMs)
        assertEquals(clock, after.lastCheckedMs)
        // The validators went out on the conditional request.
        val request = transport.requestsFor("https://lists.example/a.txt").single()
        assertEquals("\"v1\"", request.etag)
        assertNull(after.error)
    }

    @Test
    fun the_conditional_validators_are_replayed_on_the_next_request() {
        transport.onBody("https://lists.example/a.txt", body, etag = "\"v2\"", lastModified = "LM")
        val first = updater().update(state(), force = false) as UpdateOutcome.Updated

        clock += 25 * 3_600_000L
        transport.onNotModified("https://lists.example/a.txt")
        updater().update(first.state, force = false)

        val last = transport.requests.last()
        assertEquals("\"v2\"", last.etag)
        assertEquals("LM", last.lastModified)
    }

    @Test
    fun an_html_body_leaves_the_previous_copy_in_place() {
        transport.onBody("https://lists.example/a.txt", body, etag = "\"v1\"")
        val first = updater().update(state(), force = false) as UpdateOutcome.Updated
        val goodBytes = store.listFile("sample").readBytes()

        clock += 25 * 3_600_000L
        transport.onBody(
            "https://lists.example/a.txt",
            "<!DOCTYPE html><html><body>portal</body></html>",
        )
        val outcome = updater().update(first.state, force = true)

        assertTrue(outcome is UpdateOutcome.Failed)
        assertTrue((outcome as UpdateOutcome.Failed).message.contains("HTML"))
        assertArrayEquals("the last good body must survive", goodBytes, store.listFile("sample").readBytes())
        assertNotNull(outcome.state.error)
        assertEquals(first.state.lastUpdatedMs, outcome.state.lastUpdatedMs)
    }

    @Test
    fun every_failing_mirror_is_reported_and_the_previous_copy_survives() {
        val initial = state(
            url = "https://primary.example/a.txt",
            mirrors = listOf("https://mirror1.example/a.txt", "https://mirror2.example/a.txt"),
        )
        transport.onFailure("https://primary.example/a.txt", "HTTP 403")
        transport.onFailure("https://mirror1.example/a.txt", "HTTP 500")
        transport.onFailure("https://mirror2.example/a.txt", "timeout")

        val outcome = updater().update(initial, force = false)
        assertTrue(outcome is UpdateOutcome.Failed)
        val message = (outcome as UpdateOutcome.Failed).message
        assertTrue(message, message.contains("primary"))
        assertTrue(message, message.contains("mirror1"))
        assertTrue(message, message.contains("mirror2"))
        assertEquals(3, transport.requests.size)
    }

    @Test
    fun a_failing_primary_falls_through_to_a_mirror_and_the_working_url_is_remembered() {
        val initial = state(
            url = "https://primary.example/a.txt",
            mirrors = listOf("https://mirror.example/a.txt"),
        )
        transport.onFailure("https://primary.example/a.txt", "HTTP 404")
        transport.onBody("https://mirror.example/a.txt", body, etag = "\"m1\"")

        val outcome = updater().update(initial, force = false)
        assertTrue(outcome is UpdateOutcome.Updated)
        assertEquals(
            "the working mirror becomes the URL to try first",
            "https://mirror.example/a.txt",
            (outcome as UpdateOutcome.Updated).state.url,
        )
    }

    @Test
    fun a_200_with_identical_bytes_is_reported_as_not_modified() {
        transport.onBody("https://lists.example/a.txt", body, etag = "\"v1\"")
        val first = updater().update(state(), force = false) as UpdateOutcome.Updated

        clock += 25 * 3_600_000L
        transport.onBody("https://lists.example/a.txt", body, etag = "\"v1\"")
        val outcome = updater().update(first.state, force = false)

        assertTrue(
            "identical content must not trigger a recompile",
            outcome is UpdateOutcome.NotModified,
        )
    }

    @Test
    fun a_changed_body_is_reported_as_updated() {
        transport.onBody("https://lists.example/a.txt", body, etag = "\"v1\"")
        val first = updater().update(state(), force = false) as UpdateOutcome.Updated

        clock += 25 * 3_600_000L
        val changed = body + "||new.example^\n"
        transport.onBody("https://lists.example/a.txt", changed, etag = "\"v2\"")
        val outcome = updater().update(first.state, force = false)

        assertTrue(outcome is UpdateOutcome.Updated)
        assertArrayEquals(changed.toByteArray(), store.listFile("sample").readBytes())
    }

    @Test
    fun the_expires_header_sets_the_minimum_update_interval() {
        transport.onBody("https://lists.example/a.txt", body, etag = "\"v1\"")
        val first = updater().update(state(), force = false) as UpdateOutcome.Updated
        // The sample list declares `! Expires: 1 day`, so a check one hour later is not due.
        clock += 3_600_000L
        transport.requests.clear()

        val outcome = updater().update(first.state, force = false)
        assertTrue(outcome is UpdateOutcome.NotDue)
        assertTrue("no request may be made when the list is not due", transport.requests.isEmpty())
    }

    @Test
    fun forcing_ignores_the_expires_interval() {
        transport.onBody("https://lists.example/a.txt", body, etag = "\"v1\"")
        val first = updater().update(state(), force = false) as UpdateOutcome.Updated
        clock += 1_000L
        transport.requests.clear()
        transport.onNotModified("https://lists.example/a.txt")

        val outcome = updater().update(first.state, force = true)
        assertTrue(outcome is UpdateOutcome.NotModified)
        assertEquals(1, transport.requests.size)
    }

    @Test
    fun a_list_without_an_expires_header_uses_the_default_interval() {
        transport.onBody(
            "https://lists.example/a.txt",
            "||first.example^\n||second.example^\n||third.example^\n",
            etag = "x",
        )
        val first = updater().update(state(), force = false) as UpdateOutcome.Updated
        assertNull(first.state.expiresHours)

        clock += 60_000L
        assertTrue(updater().update(first.state, force = false) is UpdateOutcome.NotDue)

        clock += FilterState.DEFAULT_INTERVAL_HOURS * 3_600_000L
        transport.onNotModified("https://lists.example/a.txt")
        assertFalse(updater().update(first.state, force = false) is UpdateOutcome.NotDue)
    }

    @Test
    fun a_never_checked_list_is_always_due() {
        assertTrue(updater().isDue(state()))
    }

    @Test
    fun the_body_file_name_is_recorded_and_resolvable() {
        transport.onBody("https://lists.example/a.txt", body)
        val outcome = updater().update(state(), force = false) as UpdateOutcome.Updated
        assertEquals("sample.txt", outcome.state.fileName)
        assertNotNull(updater().bodyFile(outcome.state))
    }

    @Test
    fun an_invalid_list_id_cannot_escape_the_lists_directory() {
        // A path-traversal id must not be able to leave `lists/`. The exact spelling is an
        // implementation detail; what matters is that no separator and no `..` survives.
        for (raw in listOf("../../etc/passwd", "..", "../x", "a/b", "a\\b", "/abs", "a/../../b")) {
            val safe = FilterStore.sanitizeId(raw)
            assertFalse("$raw -> $safe must not contain a separator", safe.contains('/'))
            assertFalse("$raw -> $safe must not contain ..", safe.contains(".."))
            assertTrue("$raw -> $safe must not be empty", safe.isNotEmpty())
        }
        assertTrue(FilterStore.sanitizeId("a/b").contains("a_b"))
        assertEquals("list", FilterStore.sanitizeId(""))
    }

    @Test
    fun a_body_larger_than_the_cap_is_rejected_by_the_transport_contract() {
        // The transport enforces the 30 MB cap; this test pins the constant the updater relies on.
        assertEquals(30 * 1024 * 1024, HttpUrlConnectionTransport.DEFAULT_MAX_BYTES)
        // And a transport that refuses oversize bodies surfaces as a failure, not a crash.
        val strict = FakeTransport()
        strict.on("https://lists.example/a.txt") {
            throw DownloadException("文件过大：超过上限 30 MB", retryable = false)
        }
        val updater = ListUpdater(store, strict, now = { clock })
        val outcome = updater.update(state(), force = false)
        assertTrue(outcome is UpdateOutcome.Failed)
        assertTrue((outcome as UpdateOutcome.Failed).message.contains("过大"))
    }

    // ---------------------------------------------------------------------------------------
    // MYS-2742 补充要求 2 / 4: per-list total budget, mirror fallthrough, per-URL logging.
    // ---------------------------------------------------------------------------------------

    /**
     * A transport that burns scripted wall-clock time per URL, like a slow origin.
     *
     * [ignoreDeadline] models the case the budget exists for: a socket read that returns later than
     * the granted slice, so time really is spent rather than refunded.
     */
    private class SlowTransport(
        private val clock: () -> Long,
        private val advance: (Long) -> Unit,
        private val costOf: (String) -> Long,
        private val answer: (String) -> DownloadResult? = { null },
        private val ignoreDeadline: Boolean = false,
    ) : FilterTransport {
        val attempted = mutableListOf<String>()

        override fun fetch(
            url: String,
            etag: String?,
            lastModified: String?,
            deadlineMs: Long,
        ): DownloadResult {
            attempted.add(url)
            val cost = costOf(url)
            // A real socket stops at the deadline with a timeout; unless this fake is asked to
            // overrun, it reports the same thing without waiting 90 real seconds.
            if (!ignoreDeadline && deadlineMs > 0 && clock() + cost > deadlineMs) {
                advance((deadlineMs - clock()).coerceAtLeast(0L))
                throw DownloadException("超时：超过总时长上限", retryable = true, timeout = true)
            }
            advance(cost)
            return answer(url) ?: throw DownloadException("connection refused: $url")
        }
    }

    @Test
    fun a_slow_transfer_hits_the_total_budget_and_falls_through_to_the_mirror() {
        // 补充要求 2: the whole list — every mirror — has a total budget. The old code only had a
        // per-read timeout, so a server that trickles bytes never failed at all.
        val lines = mutableListOf<String>()
        val slow = SlowTransport(
            clock = { clock },
            advance = { clock += it },
            costOf = { url -> if (url.contains("slow")) 50_000L else 10_000L },
            answer = { url ->
                if (url.contains("slow")) {
                    null
                } else {
                    DownloadResult.Downloaded(
                        body = body.toByteArray(),
                        etag = "\"m\"",
                        lastModified = null,
                        finalUrl = url,
                    )
                }
            },
        )
        val updater = ListUpdater(store, slow, budgetMs = 90_000L, log = { lines.add(it) }, now = { clock })
        val target = state(
            url = "https://slow.example/a.txt",
            mirrors = listOf("https://mirror.example/a.txt"),
        )

        val outcome = updater.update(target, force = false)

        assertTrue("the mirror must serve the list", outcome is UpdateOutcome.Updated)
        assertEquals("https://mirror.example/a.txt", (outcome as UpdateOutcome.Updated).state.url)
        assertEquals(
            "both candidates must be attempted in order",
            listOf("https://slow.example/a.txt", "https://mirror.example/a.txt"),
            slow.attempted,
        )
        // 补充要求 4: one line per candidate URL, saying how long it took and how it ended.
        assertEquals(lines.toString(), 2, lines.size)
        assertTrue(lines[0], lines[0].contains("slow.example") && lines[0].contains("timeout"))
        assertTrue(lines[1], lines[1].contains("mirror.example") && lines[1].contains("-> ok"))
        assertTrue("the line must carry an elapsed time", lines[1].contains("ms"))
    }

    @Test
    fun a_list_whose_mirrors_all_exhaust_the_budget_fails_with_a_timeout() {
        val slow = SlowTransport(
            clock = { clock },
            advance = { clock += it },
            costOf = { 60_000L },
        )
        val updater = ListUpdater(store, slow, budgetMs = 90_000L, log = {}, now = { clock })
        val target = state(
            url = "https://slow1.example/a.txt",
            mirrors = listOf("https://slow2.example/a.txt"),
        )

        val outcome = updater.update(target, force = false)

        assertTrue(outcome is UpdateOutcome.Failed)
        val message = (outcome as UpdateOutcome.Failed).message
        assertTrue("the reason must say it timed out: $message", message.contains("超时"))
        assertEquals("both mirrors are attempted", 2, slow.attempted.size)
    }

    @Test
    fun a_mirror_is_skipped_when_the_budget_is_already_gone() {
        // Once the budget is spent the remaining mirrors must not each start a fresh 30 s read. This
        // models an origin that overruns the slice it was granted, which is the only way the budget
        // can run out before the candidate list does.
        val lines = mutableListOf<String>()
        val slow = SlowTransport(
            clock = { clock },
            advance = { clock += it },
            costOf = { 80_000L },
            ignoreDeadline = true,
        )
        val updater = ListUpdater(store, slow, budgetMs = 90_000L, log = { lines.add(it) }, now = { clock })
        val target = state(
            url = "https://a.example/a.txt",
            mirrors = listOf("https://b.example/a.txt", "https://c.example/a.txt"),
        )

        val outcome = updater.update(target, force = false)

        assertTrue(outcome is UpdateOutcome.Failed)
        assertTrue(
            "the budget must stop the round before every mirror is tried: ${slow.attempted}",
            slow.attempted.size < 3,
        )
        assertTrue(
            "the skipped mirror must still be logged: $lines",
            lines.any { it.contains("budget exhausted") },
        )
    }

    @Test
    fun an_http_error_is_logged_with_its_status() {
        val lines = mutableListOf<String>()
        transport.onFailure("https://lists.example/a.txt", "HTTP 404 Not Found")
        val updater = ListUpdater(store, transport, log = { lines.add(it) }, now = { clock })

        updater.update(state(), force = false)

        assertEquals(1, lines.size)
        assertTrue(lines[0], lines[0].contains("HTTP 404"))
        assertTrue(lines[0], lines[0].contains("lists.example"))
    }
}
