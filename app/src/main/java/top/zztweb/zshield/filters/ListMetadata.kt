package top.zztweb.zshield.filters

/**
 * The metadata a filter list declares about itself in its header comments.
 *
 * AdGuard/uBO/EasyList all put it there in the same shape:
 *
 * ```
 * ! Title: EasyList
 * ! Version: 202611080906
 * ! Expires: 4 days
 * ! Homepage: https://easylist.to/
 * ! Redirect: ...
 * ```
 *
 * [expires] is the one with a behavioural effect: it is the shortest interval at which this list's
 * author expects it to be refetched, so the updater never polls a list faster than the list itself
 * asks for (task card §2).
 */
data class ListMetadata(
    val title: String? = null,
    val version: String? = null,
    /** Parsed from `! Expires:`, in hours; `null` when the list does not declare one. */
    val expiresHours: Long? = null,
    val homepage: String? = null,
    /** How many header lines were examined before the first rule. */
    val headerLines: Int = 0,
) {
    companion object {
        /**
         * Only the first [HEADER_LIMIT] lines are read: every real list puts its metadata at the
         * top, and scanning a 2 MB file to find a header is a waste on a phone.
         */
        const val HEADER_LIMIT = 64

        fun parse(text: String): ListMetadata {
            var title: String? = null
            var version: String? = null
            var expires: Long? = null
            var homepage: String? = null
            var examined = 0
            for (rawLine in text.lineSequence()) {
                if (examined >= HEADER_LIMIT) break
                val line = rawLine.trim()
                if (line.isEmpty()) continue
                // `[Adblock Plus 2.0]` is a header line too, but carries nothing we use.
                if (line.startsWith("[")) {
                    examined++
                    continue
                }
                if (!line.startsWith("!")) break
                examined++
                val body = line.removePrefix("!").trim()
                val colon = body.indexOf(':')
                if (colon <= 0) continue
                val key = body.substring(0, colon).trim().lowercase()
                val value = body.substring(colon + 1).trim()
                if (value.isEmpty()) continue
                when (key) {
                    "title" -> title = title ?: value
                    "version" -> version = version ?: value
                    "expires" -> expires = expires ?: parseExpiresHours(value)
                    "homepage" -> homepage = homepage ?: value
                }
            }
            return ListMetadata(title, version, expires, homepage, examined)
        }

        /**
         * Parse an `Expires:` value into hours.
         *
         * Accepts the AdGuard/uBO forms (`4 days`, `12 hours`, `1 day`) and the ABP form where the
         * value is followed by a parenthesised explanation (`4 days (update frequency)`). Numbers
         * without a unit are read as days, which is what ABP's own docs mean by a bare number.
         */
        fun parseExpiresHours(value: String): Long? {
            // A negative or signed value is nonsense; rejecting it here keeps `-4 days` from being
            // read as `4 days` by the digits-only pattern below.
            if (value.trimStart().startsWith("-") || value.trimStart().startsWith("+")) return null
            val match = EXPIRES_PATTERN.find(value.trim()) ?: return null
            val amount = match.groupValues[1].toLongOrNull() ?: return null
            if (amount <= 0) return null
            val unit = match.groupValues[2].lowercase()
            val hours = when {
                unit.startsWith("min") -> (amount / 60).coerceAtLeast(1)
                unit.startsWith("h") -> amount
                unit.startsWith("d") -> amount * 24
                unit.startsWith("w") -> amount * 24 * 7
                else -> amount * 24
            }
            return hours
        }

        private val EXPIRES_PATTERN = Regex(
            """(\d+)\s*(minutes?|mins?|hours?|hrs?|h|days?|d|weeks?|w)?""",
            RegexOption.IGNORE_CASE,
        )
    }
}
