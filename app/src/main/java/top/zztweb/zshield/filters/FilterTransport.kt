package top.zztweb.zshield.filters

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.zip.GZIPInputStream

/**
 * One HTTP GET of a filter list, reduced to what the updater needs.
 *
 * A condititional request that the server answers with `304` produces [NotModified]; any other
 * usable answer produces [Downloaded] with the body and the validators to send next time.
 */
sealed interface DownloadResult {
    /** The server confirmed the cached copy is current; nothing was transferred. */
    data object NotModified : DownloadResult

    /**
     * A fresh copy.
     *
     * @param etag `ETag` response header, sent back as `If-None-Match` next time.
     * @param lastModified `Last-Modified` response header, sent back as `If-Modified-Since`.
     */
    data class Downloaded(
        val body: ByteArray,
        val etag: String?,
        val lastModified: String?,
        val finalUrl: String,
    ) : DownloadResult
}

/** A download that failed in a way the caller must report (and retry later). */
class DownloadException(
    message: String,
    /** Whether trying another mirror could plausibly succeed. */
    val retryable: Boolean = true,
    /**
     * Whether the attempt ran out of time rather than being refused.
     *
     * The updater reports this differently from an HTTP error so logcat says 「超时」 for a slow
     * origin instead of pasting the whole Chinese message (MYS-2742 补充要求 4).
     */
    val timeout: Boolean = false,
    cause: Throwable? = null,
) : IOException(message, cause)

/**
 * The HTTP transport for list downloads.
 *
 * An interface rather than a direct `HttpURLConnection` call so the update logic (mirror fallback,
 * conditional-request handling, atomic replace, "304 means no recompile") can be unit-tested
 * against a scripted transport — those tests would otherwise need a live server or a real device.
 * Production uses [HttpUrlConnectionTransport], which is deliberately the only place in the app that
 * opens a socket for lists (task card: no OkHttp).
 */
fun interface FilterTransport {
    /**
     * Fetch [url].
     *
     * @param etag validator from the previous download, or `null`.
     * @param lastModified validator from the previous download, or `null`.
     * @param deadlineMs absolute wall-clock deadline (`System.currentTimeMillis()` based) the whole
     *   transfer must finish by, or `0` for no deadline. It exists because the per-read timeout
     *   alone cannot bound a *slow* transfer: an origin that trickles one byte a second never
     *   triggers it, and before MYS-2742 such a list could occupy a download slot for ever.
     * @throws DownloadException when the request fails, exceeds [deadlineMs], or the body is not a
     *   plausible list.
     */
    fun fetch(url: String, etag: String?, lastModified: String?, deadlineMs: Long): DownloadResult
}

/**
 * `HttpURLConnection` implementation of [FilterTransport].
 *
 * Behaviour worth stating because each line is a decision:
 * - gzip is requested via `Accept-Encoding` because filter lists compress ~5×; when the server
 *   answers `Content-Encoding: gzip` the body is inflated here (some servers gzip regardless of a
 *   missing `Accept-Encoding`, so the header is checked, not assumed);
 * - a `304` is returned as [DownloadResult.NotModified] without reading a body;
 * - the body is capped at [maxBytes] *while streaming*, so a hostile or misconfigured server cannot
 *   exhaust memory before the size is known;
 * - the whole transfer is bounded by the caller's `deadlineMs`, not only by the per-read timeout:
 *   the remaining budget is re-checked between reads, so a server that dribbles bytes without ever
 *   stalling long enough to hit [readTimeoutMs] still fails in bounded time;
 * - only `200` is accepted. A `3xx` is followed by `HttpURLConnection` itself (redirects are on by
 *   default); a `404`/`403` is a mirror-worthy failure, a `5xx` is retryable later.
 */
class HttpUrlConnectionTransport(
    private val maxBytes: Int = DEFAULT_MAX_BYTES,
    private val connectTimeoutMs: Int = 15_000,
    private val readTimeoutMs: Int = 30_000,
    private val userAgent: String = DEFAULT_USER_AGENT,
    private val now: () -> Long = System::currentTimeMillis,
) : FilterTransport {

    override fun fetch(
        url: String,
        etag: String?,
        lastModified: String?,
        deadlineMs: Long,
    ): DownloadResult {
        val connection = try {
            URL(url).openConnection() as HttpURLConnection
        } catch (error: Exception) {
            throw DownloadException("无法解析地址 $url：${error.message}", retryable = false, cause = error)
        }
        try {
            connection.instanceFollowRedirects = true
            // A socket timeout longer than the remaining budget would let one mirror eat the whole
            // list's budget and leave nothing for the mirrors behind it, which is exactly the "one
            // slow origin drags everything" behaviour MYS-2742 补充要求 2 removes.
            val remaining = remainingMs(deadlineMs)
            connection.connectTimeout = boundedTimeout(connectTimeoutMs, remaining)
            connection.readTimeout = boundedTimeout(readTimeoutMs, remaining)
            connection.requestMethod = "GET"
            connection.setRequestProperty("User-Agent", userAgent)
            connection.setRequestProperty("Accept-Encoding", "gzip")
            connection.setRequestProperty("Accept", "text/plain, */*")
            // Conditional request: the server answers 304 when nothing changed, which is the whole
            // point of storing the validators (task card §2).
            if (etag != null) connection.setRequestProperty("If-None-Match", etag)
            if (lastModified != null) connection.setRequestProperty("If-Modified-Since", lastModified)

            val status = connection.responseCode
            if (status == HttpURLConnection.HTTP_NOT_MODIFIED) return DownloadResult.NotModified
            if (status != HttpURLConnection.HTTP_OK) {
                // 4xx means this URL will not serve us (moved, forbidden, gone): try a mirror.
                // 5xx may be transient, but a mirror is still the better next move.
                throw DownloadException(
                    "HTTP $status ${connection.responseMessage.orEmpty()}".trim(),
                    retryable = status >= 500,
                )
            }

            val declaredLength = connection.contentLengthLong
            if (declaredLength > maxBytes) {
                throw DownloadException(
                    "文件过大：${declaredLength / 1024 / 1024} MB 超过上限 ${maxBytes / 1024 / 1024} MB",
                    retryable = false,
                )
            }
            val encoding = connection.contentEncoding.orEmpty().lowercase()
            val stream: InputStream = connection.inputStream.let { raw ->
                if (encoding.contains("gzip")) GZIPInputStream(raw) else raw
            }
            val body = stream.use { readCapped(it, maxBytes, url, deadlineMs) }
            return DownloadResult.Downloaded(
                body = body,
                etag = connection.getHeaderField("ETag")?.trim()?.takeIf { it.isNotEmpty() },
                lastModified = connection.getHeaderField("Last-Modified")?.trim()?.takeIf { it.isNotEmpty() },
                finalUrl = connection.url?.toString() ?: url,
            )
        } catch (error: DownloadException) {
            throw error
        } catch (error: java.net.SocketTimeoutException) {
            throw DownloadException(
                "超时：${describe(deadlineMs)}",
                retryable = true,
                timeout = true,
                cause = error,
            )
        } finally {
            connection.disconnect()
        }
    }

    /** Milliseconds left before [deadlineMs]; [Long.MAX_VALUE] when there is no deadline. */
    private fun remainingMs(deadlineMs: Long): Long =
        if (deadlineMs <= 0L) Long.MAX_VALUE else (deadlineMs - now()).coerceAtLeast(0L)

    /**
     * A socket timeout that never outlives the caller's budget.
     *
     * Floor of 1 ms rather than 0: `HttpURLConnection` reads `0` as "wait for ever".
     */
    private fun boundedTimeout(configured: Int, remaining: Long): Int =
        if (remaining >= configured) configured else remaining.coerceAtLeast(1L).toInt()

    private fun describe(deadlineMs: Long): String =
        if (deadlineMs <= 0L) "读取超时" else "超过总时长上限"

    /** Fail with a typed timeout as soon as the budget is gone. */
    private fun checkDeadline(deadlineMs: Long) {
        if (deadlineMs > 0L && now() >= deadlineMs) {
            throw DownloadException("超时：超过总时长上限", retryable = true, timeout = true)
        }
    }

    /** Read at most [limit] bytes, failing loudly instead of growing without bound. */
    private fun readCapped(stream: InputStream, limit: Int, url: String, deadlineMs: Long): ByteArray {
        val out = ByteArrayOutputStream(INITIAL_BUFFER)
        val buffer = ByteArray(CHUNK)
        var total = 0
        while (true) {
            // Checked per chunk: a server that sends a byte every second never trips `readTimeout`,
            // so the elapsed-time check is what actually bounds a slow transfer.
            checkDeadline(deadlineMs)
            val read = stream.read(buffer)
            if (read < 0) break
            total += read
            if (total > limit) {
                throw DownloadException(
                    "文件过大：超过上限 ${limit / 1024 / 1024} MB（$url）",
                    retryable = false,
                )
            }
            out.write(buffer, 0, read)
        }
        return out.toByteArray()
    }

    companion object {
        /** Task card §2: 30 MB per file. */
        const val DEFAULT_MAX_BYTES: Int = 30 * 1024 * 1024
        private const val INITIAL_BUFFER = 64 * 1024
        private const val CHUNK = 32 * 1024

        /**
         * A plain, honest UA. Some CDNs reject requests without one; nothing here identifies the
         * user (no version+device fingerprinting), which is what `docs/DESIGN.md` §11 requires.
         */
        const val DEFAULT_USER_AGENT = "ZShield/1.0 (filter list updater)"
    }
}
