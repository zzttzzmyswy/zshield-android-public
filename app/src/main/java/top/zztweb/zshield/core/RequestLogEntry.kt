package top.zztweb.zshield.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * One entry of the recent-request log, as returned by [Native.recentRequestsJson].
 *
 * Mirrors `core/src/http/log.rs::RequestLogEntry` (`serde(rename_all = "camelCase")`). The two sides
 * are the contract; both are documented in `docs/JNI.md` §6.4.
 *
 * # Three kinds of entry (MYS-2742)
 *
 * The log used to hold only HTTP requests, so with HTTPS filtering off — where almost every block
 * happens at the DNS layer — it looked empty while the "已拦截" counter kept climbing. One array now
 * carries three layers under one id sequence:
 *
 * | [kind] | what it is | [outcome] |
 * |---|---|---|
 * | [Kind.DNS] | one DNS query | `blocked` / `allowed` / `cached` |
 * | [Kind.CONNECTION] | one blocked connection or datagram | `blocked` |
 * | [Kind.HTTP] | one request judged by the plaintext/decrypted pipeline | `allowed` / `blocked` / `redirected` / `exception` |
 *
 * Fields a kind does not use are absent on the wire, so a DNS line is read with [qtype] set and
 * [url]/[method]/[resourceType] empty. Missing fields degrade to their defaults rather than throwing:
 * an older core's log still renders.
 */
data class RequestLogEntry(
    /** Monotonic id, shared by all three kinds; pass the newest one back as `sinceId`. */
    val id: Long = 0,
    /** Which layer produced this entry. Absent on the wire means [Kind.HTTP] (pre-MYS-2742 data). */
    val kind: Kind = Kind.HTTP,
    /** Milliseconds since the tunnel started. */
    val timeMs: Long = 0,
    /** Hostname without the port; for a connection entry, the SNI/Host or `ip:port`. */
    val host: String = "",
    val outcome: Outcome = Outcome.ALLOWED,
    /** The blocking rule, when the layer can name one (`compile` with `debugRules` for HTTP). */
    val rule: String? = null,
    /**
     * Why it was blocked: `cname` for a DNS CNAME-chain hit, or `rule` / `encrypted_dns` / `dot` /
     * `quic` for a connection-level block.
     */
    val reason: String? = null,
    /** DNS entries only: the CNAME step that was blocked, when the block came from the chain. */
    val cname: String? = null,
    /** DNS entries only: `A`, `AAAA`, `HTTPS`, ... */
    val qtype: String = "",
    /** HTTP entries only: the matched URL, truncated at [MAX_URL_LENGTH] bytes. */
    val url: String = "",
    /** HTTP entries only: true when [url] was cut. */
    val truncated: Boolean = false,
    /** HTTP entries only. */
    val method: String = "",
    /** HTTP entries only: the inferred resource type (`document`, `script`, `image`, ...). */
    val resourceType: String = "",
    /** HTTP entries only: the exception rule that cancelled a block. */
    val exceptionRule: String? = null,
    /** HTTP entries only: whether the request came from another site. */
    val thirdParty: Boolean = false,
    /** HTTP entries only: whether the response body was rewritten to inject cosmetic rules. */
    val cosmetic: Boolean = false,
) {
    /** Which layer produced an entry. */
    enum class Kind(val wireName: String) {
        /** One DNS query, including allowed and cache-hit ones. */
        DNS("dns"),

        /** One connection-level block (rule, refused DoT, encrypted-DNS endpoint, dropped QUIC). */
        CONNECTION("connection"),

        /** One HTTP request judged by the plaintext or decrypted pipeline. */
        HTTP("http"),
        ;

        companion object {
            /**
             * An unknown or absent spelling degrades to [HTTP]: every entry written before MYS-2742
             * was one, so old data keeps rendering with its own fields.
             */
            fun fromWireName(name: String): Kind =
                entries.firstOrNull { it.wireName == name } ?: HTTP
        }
    }

    /** What happened to this entry. */
    enum class Outcome(val wireName: String) {
        ALLOWED("allowed"),
        BLOCKED("blocked"),
        REDIRECTED("redirected"),
        EXCEPTION("exception"),

        /** Answered from the DNS cache (MYS-2742). */
        CACHED("cached"),
        ;

        companion object {
            /** Unknown spellings degrade to [ALLOWED] rather than throwing: this is a log view. */
            fun fromWireName(name: String): Outcome =
                entries.firstOrNull { it.wireName == name } ?: ALLOWED
        }
    }

    /** True when this entry is a block, i.e. one of the lines the home screen's counter counts. */
    val blocked: Boolean
        get() = outcome == Outcome.BLOCKED || outcome == Outcome.REDIRECTED

    companion object {
        /** Entries the core keeps (`core/src/http/log.rs::REQUEST_LOG_CAPACITY`). */
        const val CAPACITY = 2000

        /** Longest URL the core stores (`core/src/http/log.rs::MAX_LOGGED_URL`). */
        const val MAX_URL_LENGTH = 512

        /**
         * Parse the array `Native.recentRequestsJson` returns.
         *
         * A malformed document yields an empty list rather than an exception: the log is a diagnostic
         * view, and a parse failure there must not take down the screen that shows it.
         */
        fun listFromJson(json: String): List<RequestLogEntry> {
            if (json.isBlank()) return emptyList()
            val array = runCatching { JSONArray(json) }.getOrNull() ?: return emptyList()
            return buildList {
                for (index in 0 until array.length()) {
                    val entry = array.optJSONObject(index) ?: continue
                    add(fromJson(entry))
                }
            }
        }

        fun fromJson(json: JSONObject): RequestLogEntry {
            val timeMs = if (json.has("timeMs")) json.optLong("timeMs") else json.optLong("atMs")
            return RequestLogEntry(
                id = json.optLong("id"),
                kind = Kind.fromWireName(json.optString("kind", "")),
                timeMs = timeMs,
                host = json.optString("host", ""),
                outcome = Outcome.fromWireName(json.optString("outcome", "")),
                rule = json.optString("rule", "").ifBlank { null },
                reason = json.optString("reason", "").ifBlank { null },
                cname = json.optString("cname", "").ifBlank { null },
                qtype = json.optString("qtype", ""),
                url = json.optString("url", ""),
                truncated = json.optBoolean("truncated", false),
                method = json.optString("method", ""),
                resourceType = json.optString("resourceType", ""),
                exceptionRule = json.optString("exceptionRule", "").ifBlank { null },
                thirdParty = json.optBoolean("thirdParty", false),
                cosmetic = json.optBoolean("cosmetic", false),
            )
        }
    }
}

/**
 * The old name, kept so existing call sites (and `docs/JNI.md`) do not have to change at once.
 *
 * The type was called `HttpRequestLogEntry` while the log only carried HTTP requests (M2b). It now
 * carries DNS and connection entries too, so the name was wrong; this alias keeps a mixed-version
 * tree compiling without a second model.
 */
typealias HttpRequestLogEntry = RequestLogEntry
