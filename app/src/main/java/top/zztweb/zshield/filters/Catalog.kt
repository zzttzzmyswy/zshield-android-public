package top.zztweb.zshield.filters

import org.json.JSONArray
import org.json.JSONObject

/**
 * One entry of the built-in subscription catalog (`assets/filters/catalog.json`).
 *
 * The catalog is data, not code: it ships as an asset so a list URL can be corrected without
 * touching Kotlin, and so the UI can list every available list even before anything is downloaded.
 *
 * Field semantics (task card §1, `docs/DESIGN.md` fixed decision 8):
 * - [id] is stable forever: it keys the on-disk state, so renaming it would orphan a user's enabled
 *   flags and their downloaded copy;
 * - [mirrors] are tried in order when [url] fails, which is what keeps the built-in set usable on
 *   networks that block a particular host;
 * - [defaultEnabled] is what "首次启动按默认启用集下载" means — nothing else is enabled implicitly.
 */
data class CatalogEntry(
    /** Stable identifier; never changes once published. */
    val id: String,
    /** Display name shown in the UI. */
    val name: String,
    /** Grouping for the UI: `ads`, `privacy`, `security`, `annoyance`, `regional`, `dns`. */
    val category: String,
    /** Primary download URL. */
    val url: String,
    /** Fallback URLs, tried in order after [url]. */
    val mirrors: List<String> = emptyList(),
    /** Project homepage, shown in the UI. */
    val homepage: String = "",
    /** SPDX-ish license name of the list content. */
    val license: String = "",
    /** Whether the list is enabled on a fresh install. */
    val defaultEnabled: Boolean = false,
) {
    /** Every candidate URL: primary first, then mirrors. */
    val candidates: List<String>
        get() = (listOf(url) + mirrors).distinct()

    companion object {
        /**
         * Parse the catalog document.
         *
         * Throws [InvalidCatalogException] on structural problems, including a duplicate `id`: two
         * entries sharing an id would silently share one on-disk state slot, which is the kind of
         * bug that only shows up as "my list is enabled but empty".
         */
        fun parseAll(json: String): List<CatalogEntry> {
            val root = runCatching { JSONObject(json) }.getOrElse { error ->
                throw InvalidCatalogException("catalog.json 不是合法 JSON：${error.message}")
            }
            val array = root.optJSONArray("lists")
                ?: throw InvalidCatalogException("catalog.json 缺少 lists 数组")
            val entries = ArrayList<CatalogEntry>(array.length())
            val seen = HashSet<String>(array.length())
            for (index in 0 until array.length()) {
                val objectValue = array.optJSONObject(index)
                    ?: throw InvalidCatalogException("catalog.json lists[$index] 不是对象")
                val entry = parseEntry(objectValue, index)
                if (!seen.add(entry.id)) {
                    throw InvalidCatalogException("catalog.json 存在重复 id：${entry.id}")
                }
                entries.add(entry)
            }
            return entries
        }

        private fun parseEntry(json: JSONObject, index: Int): CatalogEntry {
            val id = json.optString("id").trim()
            if (id.isEmpty()) throw InvalidCatalogException("catalog.json lists[$index] 缺少 id")
            val name = json.optString("name").trim()
            if (name.isEmpty()) throw InvalidCatalogException("catalog.json lists[$index] ($id) 缺少 name")
            val category = json.optString("category").trim()
            if (category !in CATEGORIES) {
                throw InvalidCatalogException(
                    "catalog.json lists[$index] ($id) 的 category 非法：$category"
                )
            }
            val url = json.optString("url").trim()
            requireHttpUrl(url) { "catalog.json lists[$index] ($id) 的 url 非法：$url" }
            val mirrors = buildList {
                val mirrorArray: JSONArray? = json.optJSONArray("mirrors")
                if (mirrorArray != null) {
                    for (position in 0 until mirrorArray.length()) {
                        val mirror = mirrorArray.optString(position).trim()
                        requireHttpUrl(mirror) {
                            "catalog.json lists[$index] ($id) 的 mirrors[$position] 非法：$mirror"
                        }
                        add(mirror)
                    }
                }
            }
            return CatalogEntry(
                id = id,
                name = name,
                category = category,
                url = url,
                mirrors = mirrors,
                homepage = json.optString("homepage").trim(),
                license = json.optString("license").trim(),
                defaultEnabled = json.optBoolean("defaultEnabled", false),
            )
        }

        private fun requireHttpUrl(value: String, message: () -> String) {
            if (!value.startsWith("https://") && !value.startsWith("http://")) throw InvalidCatalogException(message())
        }

        /** The six category values `docs/DESIGN.md` and the UI agree on. */
        val CATEGORIES = setOf("ads", "privacy", "security", "annoyance", "regional", "dns")
    }
}

/** The catalog asset could not be understood. */
class InvalidCatalogException(message: String) : IllegalArgumentException(message)
