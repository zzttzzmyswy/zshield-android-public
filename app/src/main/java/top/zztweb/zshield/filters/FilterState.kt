package top.zztweb.zshield.filters

import org.json.JSONArray
import org.json.JSONObject

/**
 * Everything the filter system remembers across restarts, in one document.
 *
 * The whole point of keeping it in a single JSON file (rather than a database) is that it is a few
 * kilobytes of plain data that can be inspected with `adb shell cat` when something goes wrong, and
 * written atomically in one `rename` — see [FilterStore]. A relational store would add megabytes of
 * dependency for a table with one row per list.
 */
data class FilterState(
    /** Per-list state, keyed by [FilterListState.id]. */
    val lists: List<FilterListState> = emptyList(),
    /** The user's custom rules, verbatim. */
    val userRules: String = "",
    /** Domains the user always wants resolved. */
    val allowlist: List<String> = emptyList(),
    /** Periodic update interval in hours. */
    val autoUpdateHours: Int = FilterState.DEFAULT_INTERVAL_HOURS,
    /** Whether periodic updates run only on unmetered networks. */
    val autoUpdateUnmeteredOnly: Boolean = false,
) {
    fun list(id: String): FilterListState? = lists.firstOrNull { it.id == id }

    /** Replace one list's state, keeping the order stable. */
    fun withList(updated: FilterListState): FilterState {
        val index = lists.indexOfFirst { it.id == updated.id }
        return if (index < 0) {
            copy(lists = lists + updated)
        } else {
            copy(lists = lists.toMutableList().also { it[index] = updated })
        }
    }

    fun withoutList(id: String): FilterState = copy(lists = lists.filterNot { it.id == id })

    companion object {
        /** Bumped when the document layout changes incompatibly; readers ignore unknown fields. */
        const val VERSION = 1

        const val DEFAULT_INTERVAL_HOURS = 24

        /** Smallest and largest periodic interval the UI may choose, in hours. */
        const val MIN_INTERVAL_HOURS = 1
        const val MAX_INTERVAL_HOURS = 24 * 30

        fun fromJson(json: String): FilterState {
            val root = JSONObject(json)
            val array = root.optJSONArray("lists") ?: JSONArray()
            val lists = buildList {
                for (index in 0 until array.length()) {
                    array.optJSONObject(index)?.let { add(FilterListState.fromJson(it)) }
                }
            }
            val allowArray = root.optJSONArray("allowlist") ?: JSONArray()
            val allowlist = buildList {
                for (index in 0 until allowArray.length()) {
                    allowArray.optString(index).trim().takeIf { it.isNotEmpty() }?.let { add(it) }
                }
            }
            return FilterState(
                lists = lists,
                userRules = root.optString("userRules", ""),
                allowlist = allowlist,
                autoUpdateHours = root.optInt("autoUpdateHours", DEFAULT_INTERVAL_HOURS)
                    .coerceIn(MIN_INTERVAL_HOURS, MAX_INTERVAL_HOURS),
                autoUpdateUnmeteredOnly = root.optBoolean("autoUpdateUnmeteredOnly", false),
            )
        }
    }

    fun toJson(): String {
        val root = JSONObject()
        root.put("version", VERSION)
        val array = JSONArray()
        lists.forEach { array.put(it.toJson()) }
        root.put("lists", array)
        root.put("userRules", userRules)
        root.put("allowlist", JSONArray(allowlist))
        root.put("autoUpdateHours", autoUpdateHours)
        root.put("autoUpdateUnmeteredOnly", autoUpdateUnmeteredOnly)
        return root.toString()
    }
}

/**
 * Persisted state of one list.
 *
 * [status] is deliberately **not** persisted as an error: a download that failed last week says
 * nothing about now, and a stale red badge after a restart would be a lie. Only `Idle` survives a
 * restart; everything else is recomputed by the first update.
 */
data class FilterListState(
    /** Stable id: catalog id, or `custom-<hash>` / `file-<hash>` for user-added lists. */
    val id: String,
    val name: String,
    val category: String,
    val url: String,
    /** Fallback URLs from the catalog, tried in order after [url]. */
    val mirrors: List<String> = emptyList(),
    val homepage: String = "",
    val enabled: Boolean = false,
    /** True for catalog entries: they cannot be removed, only disabled. */
    val builtin: Boolean = false,
    val lastUpdatedMs: Long = 0,
    val lastCheckedMs: Long = 0,
    /** Rules the last compile counted for this list. */
    val ruleCount: Long = 0,
    /** Rules from this list the engine could not use. */
    val unsupportedCount: Long = 0,
    /** Validator state for conditional requests. */
    val etag: String? = null,
    val lastModified: String? = null,
    /** `! Expires:` from the list header, in hours; the updater never polls faster than this. */
    val expiresHours: Long? = null,
    /** Last error message, or `null` when the last operation succeeded. */
    val error: String? = null,
    /** Where the downloaded text lives, when it exists. */
    val fileName: String? = null,
    /** Size of the downloaded text, for the UI. */
    val bytes: Long = 0,
    /**
     * What this list is doing right now (`Idle` / `Downloading` / `Compiling` / `Error`).
     *
     * Deliberately **not** persisted: the document must describe facts (last update time, last
     * error), never an in-flight operation, or a restart would resurrect a "Downloading" badge that
     * has not been true for days. `fromJson` therefore always starts at [ListStatus.Idle], and
     * [error] carries the durable part of an error.
     */
    val status: ListStatus = ListStatus.Idle,
) {
    /** Whether a usable copy of this list is on disk. */
    val hasContent: Boolean get() = fileName != null && lastUpdatedMs > 0

    /** The URL to request first, then its mirrors, without duplicates. */
    val candidates: List<String> get() = (listOf(url) + mirrors).distinct()

    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id)
        put("name", name)
        put("category", category)
        put("url", url)
        put("mirrors", JSONArray(mirrors))
        put("homepage", homepage)
        put("enabled", enabled)
        put("builtin", builtin)
        put("lastUpdatedMs", lastUpdatedMs)
        put("lastCheckedMs", lastCheckedMs)
        put("ruleCount", ruleCount)
        put("unsupportedCount", unsupportedCount)
        etag?.let { put("etag", it) }
        lastModified?.let { put("lastModified", it) }
        expiresHours?.let { put("expiresHours", it) }
        error?.let { put("error", it) }
        fileName?.let { put("fileName", it) }
        put("bytes", bytes)
    }

    companion object {
        fun fromJson(json: JSONObject): FilterListState = FilterListState(
            id = json.optString("id"),
            name = json.optString("name"),
            category = json.optString("category", "ads"),
            url = json.optString("url"),
            mirrors = json.optJSONArray("mirrors")?.let { array ->
                buildList {
                    for (index in 0 until array.length()) {
                        array.optString(index).trim().takeIf { it.isNotEmpty() }?.let { add(it) }
                    }
                }
            } ?: emptyList(),
            homepage = json.optString("homepage", ""),
            enabled = json.optBoolean("enabled", false),
            builtin = json.optBoolean("builtin", false),
            lastUpdatedMs = json.optLong("lastUpdatedMs", 0),
            lastCheckedMs = json.optLong("lastCheckedMs", 0),
            ruleCount = json.optLong("ruleCount", 0),
            unsupportedCount = json.optLong("unsupportedCount", 0),
            etag = json.optString("etag", "").takeIf { it.isNotEmpty() },
            lastModified = json.optString("lastModified", "").takeIf { it.isNotEmpty() },
            expiresHours = if (json.has("expiresHours")) json.optLong("expiresHours") else null,
            error = json.optString("error", "").takeIf { it.isNotEmpty() },
            fileName = json.optString("fileName", "").takeIf { it.isNotEmpty() },
            bytes = json.optLong("bytes", 0),
        )
    }
}

/** What a list is doing right now. Never persisted; see [FilterListState]. */
sealed interface ListStatus {
    data object Idle : ListStatus

    /**
     * Waiting for a download slot ("全部更新" runs at most
     * [FilterRepository.DOWNLOAD_CONCURRENCY] lists at a time).
     *
     * A list in this state is *not* stuck: it has been picked up by a pass and is waiting its turn.
     * It exists so the screen can say 「排队中」 instead of the misleading 「等待下载」, which read as
     * "nothing will ever happen" in the MYSWY report that started MYS-2742.
     */
    data object Queued : ListStatus

    data object Downloading : ListStatus
    data object Compiling : ListStatus
    data class Error(val message: String) : ListStatus
}

/** Progress of a compile, as the UI shows it. */
sealed interface CompileState {
    data object Idle : CompileState
    data object Running : CompileState
    data class Done(val stats: CompileStats) : CompileState
    data class Failed(val message: String) : CompileState
}

/**
 * `CompileStats` as returned by `Native.compile` (`docs/JNI.md`).
 *
 * Mirrors the Rust struct field for field; a field the core stops sending degrades to `0` rather
 * than throwing, so an older core cannot break a newer UI.
 */
data class CompileStats(
    val totalLines: Long = 0,
    val dnsRules: Long = 0,
    val networkRules: Long = 0,
    val cosmeticRules: Long = 0,
    val unsupported: Long = 0,
    val networkOnly: Long = 0,
    val dnsBlockRules: Long = 0,
    val dnsExceptionRules: Long = 0,
    val allowlist: Long = 0,
    val elapsedMs: Long = 0,
    val dnsBytes: Long = 0,
    val engineBytes: Long = 0,
    val listCount: Int = 0,
    /** Per-list counts, keyed by list id. */
    val perList: Map<String, ListCompileStats> = emptyMap(),
) {
    companion object {
        /**
         * Parse the compile result. `null` (the core could not allocate the string) and a document
         * that is not JSON both yield the all-default value: a compile that produced no readable
         * statistics must not crash the screen that reports it (MYS-2716 §2).
         */
        fun fromJson(json: String?): CompileStats {
            if (json.isNullOrBlank()) return CompileStats()
            val root = runCatching { JSONObject(json) }.getOrNull() ?: return CompileStats()
            val array = root.optJSONArray("lists") ?: JSONArray()
            val perList = LinkedHashMap<String, ListCompileStats>()
            for (index in 0 until array.length()) {
                val item = array.optJSONObject(index) ?: continue
                val id = item.optString("id")
                if (id.isEmpty()) continue
                perList[id] = ListCompileStats(
                    lines = item.optLong("lines"),
                    dnsRules = item.optLong("dnsRules"),
                    networkRules = item.optLong("networkRules"),
                    cosmeticRules = item.optLong("cosmeticRules"),
                    unsupported = item.optLong("unsupported"),
                    bytes = item.optLong("bytes"),
                )
            }
            return CompileStats(
                totalLines = root.optLong("totalLines"),
                dnsRules = root.optLong("dnsRules"),
                networkRules = root.optLong("networkRules"),
                cosmeticRules = root.optLong("cosmeticRules"),
                unsupported = root.optLong("unsupported"),
                networkOnly = root.optLong("networkOnly"),
                dnsBlockRules = root.optLong("dnsBlockRules"),
                dnsExceptionRules = root.optLong("dnsExceptionRules"),
                allowlist = root.optLong("allowlist"),
                elapsedMs = root.optLong("elapsedMs"),
                dnsBytes = root.optLong("dnsBytes"),
                engineBytes = root.optLong("engineBytes"),
                listCount = perList.size,
                perList = perList,
            )
        }
    }
}

/** Per-list counters inside [CompileStats]. */
data class ListCompileStats(
    val lines: Long = 0,
    val dnsRules: Long = 0,
    val networkRules: Long = 0,
    val cosmeticRules: Long = 0,
    val unsupported: Long = 0,
    val bytes: Long = 0,
)
