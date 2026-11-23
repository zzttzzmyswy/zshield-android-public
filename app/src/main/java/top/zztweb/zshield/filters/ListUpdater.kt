package top.zztweb.zshield.filters

import java.io.File

/**
 * One list's download outcome, as the repository records it.
 *
 * Kept separate from [FilterListState] so the update logic can be tested without a store or a
 * coroutine scope: it is a plain value in, a plain value out.
 */
sealed interface UpdateOutcome {
    /** Body downloaded and replaced the previous copy. */
    data class Updated(
        val state: FilterListState,
        val metadata: ListMetadata,
        val skippedIncludes: List<String>,
    ) : UpdateOutcome

    /** `304 Not Modified`: nothing changed, so nothing needs recompiling. */
    data class NotModified(val state: FilterListState) : UpdateOutcome

    /** Every mirror failed; the previous copy (if any) is still in place. */
    data class Failed(val state: FilterListState, val message: String) : UpdateOutcome

    /** The list is not due yet (its `! Expires:` interval has not elapsed). */
    data class NotDue(val state: FilterListState) : UpdateOutcome
}

/**
 * What happened to one candidate URL, for the logcat line MYS-2742 补充要求 4 asks for.
 *
 * The point is answering "which origin is slow from here" without a debugger: one line per URL, with
 * the elapsed time and a machine-readable-ish verdict.
 */
internal data class Attempt(
    val url: String,
    val elapsedMs: Long,
    /** `ok` / `not-modified` / `timeout` / `HTTP 404` / a short failure label. */
    val result: String,
    val bytes: Long = 0,
    val success: Boolean = false,
)

/**
 * Downloads and installs a single filter list.
 *
 * This class is the *behaviour* of the update system with all Android dependencies (Context,
 * coroutines, JobScheduler) removed, which is what makes the interesting rules testable on the JVM:
 *
 * - a conditional request that returns `304` must not touch the file and must not ask for a
 *   recompile (task card §2 / acceptance test 2);
 * - a body that fails the [ListSanity] check must leave the previous copy in place and record an
 *   error rather than overwrite good rules with an HTML page;
 * - mirrors are tried in order, and the winning URL is remembered so the next update starts there;
 * - an unchanged `ETag`/`Last-Modified` pair on a `200` response still counts as "updated" (the
 *   server may be re-serving the same bytes), so the file is rewritten but the *content* is
 *   compared and an unchanged body is reported as [UpdateOutcome.NotModified] to avoid a pointless
 *   recompile;
 * - **the whole list, all mirrors included, has [budgetMs] to finish** (MYS-2742 补充要求 2). A
 *   mirror that times out or exhausts the budget falls through to the next one with whatever time is
 *   left, and the budget is over only when every mirror has failed.
 */
class ListUpdater(
    private val store: FilterStore,
    private val transport: FilterTransport,
    /**
     * Total wall-clock budget for one list's download, across every mirror.
     *
     * 90 s is the task card's number. It is split between the candidates still to try (see [update]),
     * so no single mirror can spend all of it: with a primary and one mirror each gets 45 s, which is
     * connect timeout (15 s) + read timeout (30 s) — the budget therefore never makes a healthy origin
     * fail earlier than it already would, it only bounds the *total*.
     */
    private val budgetMs: Long = DEFAULT_BUDGET_MS,
    /**
     * Sink for the per-URL lines. Defaults to logcat in production; tests pass a collector so the
     * "one line per candidate URL with elapsed time and result" requirement is assertable.
     */
    private val log: (String) -> Unit = { message -> android.util.Log.i("ZShield", message) },
    private val now: () -> Long = System::currentTimeMillis,
) {

    /**
     * Update one list.
     *
     * @param state current state of the list.
     * @param force skip the `! Expires:` due check ("全部更新" from the UI).
     */
    fun update(state: FilterListState, force: Boolean): UpdateOutcome {
        if (!force && !isDue(state)) {
            return UpdateOutcome.NotDue(state)
        }

        val deadline = now() + budgetMs
        val errors = mutableListOf<String>()
        val urls = state.candidates
        for ((index, url) in urls.withIndex()) {
            val remaining = deadline - now()
            if (remaining <= 0L) {
                errors.add("$url: 超时：超过总时长上限（${budgetMs / 1000} s）")
                report(Attempt(url, 0, "skipped: budget exhausted"))
                continue
            }
            // Each candidate gets a slice of whatever is left, so a primary that hangs cannot take the
            // whole budget down with it: with three mirrors and 90 s that is ~30 s each, which is the
            // pre-existing per-read timeout and therefore no slower than before for a healthy origin.
            val attemptDeadline = attemptDeadlineMs(deadline, index, urls.size)
            val startedAt = now()
            val result = try {
                transport.fetch(url, state.etag, state.lastModified, attemptDeadline)
            } catch (error: DownloadException) {
                val label = when {
                    error.timeout -> "timeout"
                    else -> error.message ?: "failed"
                }
                errors.add("$url: ${error.message}")
                report(Attempt(url, now() - startedAt, label))
                continue
            } catch (error: Exception) {
                errors.add("$url: ${error.message ?: error::class.java.simpleName}")
                report(Attempt(url, now() - startedAt, error::class.java.simpleName))
                continue
            }
            when (result) {
                is DownloadResult.NotModified -> {
                    report(Attempt(url, now() - startedAt, "not-modified", success = true))
                    return UpdateOutcome.NotModified(
                        state.copy(
                            lastCheckedMs = now(),
                            error = null,
                        )
                    )
                }
                is DownloadResult.Downloaded -> {
                    val verdict = ListSanity.check(result.body)
                    if (verdict is ListSanity.Verdict.Rejected) {
                        errors.add("$url: ${verdict.reason}")
                        report(
                            Attempt(url, now() - startedAt, "rejected: ${verdict.reason}", result.body.size.toLong()),
                        )
                        continue
                    }
                    report(
                        Attempt(url, now() - startedAt, "ok", result.body.size.toLong(), success = true),
                    )
                    val metadata = ListMetadata.parse(String(result.body, Charsets.UTF_8))
                    // Remember the mirror that actually worked, so the next update goes straight
                    // there instead of paying the failed primary's timeout every time.
                    return install(state.copy(url = url), result, metadata)
                }
            }
        }
        return UpdateOutcome.Failed(
            state.copy(lastCheckedMs = now(), error = errors.joinToString("；").ifEmpty { "下载失败" }),
            errors.joinToString("；").ifEmpty { "下载失败" },
        )
    }

    /** Budget handed to one candidate URL; see [update]. */
    private fun attemptDeadlineMs(deadline: Long, index: Int, count: Int): Long {
        val remaining = deadline - now()
        if (remaining <= 0L) return 0L
        val left = (count - index).coerceAtLeast(1)
        return now() + (remaining / left).coerceAtLeast(1L)
    }

    /**
     * Emit one logcat line for one candidate URL.
     *
     * Format is stable because the delivery evidence quotes it:
     * `list candidate: <url> -> <result> in <elapsed> ms, <bytes> B`.
     */
    private fun report(attempt: Attempt) {
        val size = if (attempt.bytes > 0) ", ${attempt.bytes} B" else ""
        log("list candidate: ${attempt.url} -> ${attempt.result} in ${attempt.elapsedMs} ms$size")
    }

    /** Default per-list budget; see the [budgetMs] constructor parameter. */
    companion object {
        const val DEFAULT_BUDGET_MS: Long = 90_000L
    }

    /** Write a validated body and produce the new list state. */
    fun install(
        state: FilterListState,
        download: DownloadResult.Downloaded,
        metadata: ListMetadata,
    ): UpdateOutcome {
        val bodyFile = store.listFile(state.id)
        val previous = if (bodyFile.isFile) runCatching { bodyFile.readBytes() }.getOrNull() else null
        val changed = previous == null || !previous.contentEquals(download.body)
        if (changed) {
            store.writeAtomically(bodyFile, download.body)
        }
        val newState = state.copy(
            lastUpdatedMs = if (changed) now() else state.lastUpdatedMs.coerceAtLeast(now()),
            lastCheckedMs = now(),
            etag = download.etag ?: state.etag,
            lastModified = download.lastModified ?: state.lastModified,
            expiresHours = metadata.expiresHours ?: state.expiresHours,
            error = null,
            fileName = bodyFile.name,
            bytes = download.body.size.toLong(),
        )
        return if (changed) {
            UpdateOutcome.Updated(newState, metadata, emptyList())
        } else {
            // Same bytes as before: the server did not honour the conditional request, but there is
            // nothing new to compile, so report it as unchanged.
            UpdateOutcome.NotModified(newState)
        }
    }

    /**
     * Whether a list is due for a check.
     *
     * A list that declares `! Expires:` is never polled faster than that declaration; a list that
     * does not is checked at the caller's interval (the repository's, normally 24 h). A list that
     * has never been fetched is always due.
     */
    fun isDue(state: FilterListState): Boolean {
        if (state.lastCheckedMs <= 0) return true
        val minimumIntervalMs = (state.expiresHours ?: FilterState.DEFAULT_INTERVAL_HOURS.toLong()) *
            60L * 60L * 1000L
        return now() - state.lastCheckedMs >= minimumIntervalMs
    }

    /** The body file for a list, if it exists. */
    fun bodyFile(state: FilterListState): File? {
        val name = state.fileName ?: return null
        val file = File(store.listsDir, name)
        return file.takeIf { it.isFile }
    }
}
