package top.zztweb.zshield.filters

import java.net.URI

/**
 * Decides whether a downloaded body is really a filter list.
 *
 * This exists because the failure it prevents is silent and expensive: a captive portal or a
 * misdirected mirror answers `200 OK` with an HTML page, and without a check that page would be
 * written over a working list, compiled into zero rules, and the user would simply stop being
 * protected. So the body is rejected — the previous copy stays in place and the error is recorded
 * (task card §2: "做「像过滤列表」的合理性检查（非 HTML、规则行占比）后原子替换").
 */
object ListSanity {

    /** A body shorter than this cannot carry a useful rule set. */
    const val MIN_BYTES = 32

    /** Below this ratio of rule-looking lines the body is not a list. */
    const val MIN_RULE_RATIO = 0.05

    /** How many lines to sample when computing the ratio. */
    private const val SAMPLE_LINES = 2_000

    sealed interface Verdict {
        data object Ok : Verdict

        /** Rejected; [reason] is shown to the user next to the list. */
        data class Rejected(val reason: String) : Verdict
    }

    /**
     * Check a downloaded body.
     *
     * @param body raw bytes as received.
     * @param allowHostsOnly hosts-format lists have no `!` header and no `##`; they are still rules,
     *   so the ratio test is what matters, not the presence of AdGuard-style markers.
     */
    fun check(body: ByteArray, contentType: String? = null): Verdict {
        if (body.size < MIN_BYTES) {
            return Verdict.Rejected("内容过短（${body.size} 字节），不像过滤列表")
        }
        // HTML is checked on the first bytes, before any decoding, so a huge page is rejected
        // without paying for a UTF-8 conversion.
        val head = String(body, 0, minOf(body.size, 512), Charsets.UTF_8)
        val trimmedHead = head.trimStart('\uFEFF', ' ', '\t', '\r', '\n').lowercase()
        if (trimmedHead.startsWith("<!doctype html") || trimmedHead.startsWith("<html")) {
            return Verdict.Rejected("返回的是 HTML 页面（很可能是门户劫持或镜像错误）")
        }
        if (contentType != null && contentType.contains("text/html", ignoreCase = true)) {
            return Verdict.Rejected("Content-Type 为 HTML（$contentType）")
        }

        val text = runCatching { String(body, Charsets.UTF_8) }.getOrNull()
            ?: return Verdict.Rejected("内容不是 UTF-8 文本")
        if (text.indexOf('\u0000') >= 0) {
            return Verdict.Rejected("内容是二进制数据")
        }

        var examined = 0
        var rules = 0
        for (line in text.lineSequence()) {
            if (examined >= SAMPLE_LINES) break
            examined++
            if (looksLikeRule(line)) rules++
        }
        if (examined == 0) return Verdict.Rejected("内容为空")
        val ratio = rules.toDouble() / examined
        if (rules == 0) {
            return Verdict.Rejected("没有任何可识别的规则行")
        }
        if (ratio < MIN_RULE_RATIO) {
            return Verdict.Rejected(
                "规则行占比过低（${"%.1f".format(ratio * 100)}%），不像过滤列表"
            )
        }
        return Verdict.Ok
    }

    /** Whether a line is one of the shapes a filter list uses for a rule. */
    fun looksLikeRule(rawLine: String): Boolean {
        val line = rawLine.trim()
        if (line.isEmpty()) return false
        if (line.startsWith("!") || line.startsWith("#") || line.startsWith("[")) return false
        // Adblock network/cosmetic/hosts rule starts.
        if (line.startsWith("||") || line.startsWith("|") || line.startsWith("@@")) return true
        if (line.contains("##") || line.contains("#@#") || line.contains("#?#")) return true
        if (line.startsWith("/") && line.endsWith("/")) return true
        // A bare domain, or `<ip> <domain>` (hosts format).
        val firstToken = line.substringBefore(' ').substringBefore('\t')
        if (isPlausibleDomain(firstToken) || line.split(' ', '\t').any { isPlausibleDomain(it) }) return true
        return looksLikeBareNetworkRule(line)
    }

    /**
     * Whether a line is a network rule that neither starts with `||` nor names a domain.
     *
     * These are the *majority* of EasyList's body — `-ad-manager/$~stylesheet`,
     * `&rb=&uuid=$third-party`, `.ads.controller.js$script`, `-banner-ads-$~stylesheet` — and without
     * this branch the sanity check counted them as non-rules. On a real device that made a genuine
     * EasyList download score 0.4% and be rejected as "not a filter list", so EasyList could never be
     * turned on (found by the MYS-2742 device test; the unit tests only used synthetic `||host^`
     * lists, which is why it went unnoticed until now).
     *
     * The shape being recognised is narrow on purpose: a **single token** (prose has spaces), built
     * only from characters a rule can use, containing at least one piece of rule syntax. HTML is
     * rejected before this runs, so `</div>`-style fragments cannot reach it.
     */
    private fun looksLikeBareNetworkRule(line: String): Boolean {
        if (line.any { it.isWhitespace() }) return false
        if (line.length < MIN_BARE_RULE_LENGTH) return false
        if (line.none { it.isLetterOrDigit() }) return false
        if (line.any { !isRuleChar(it) }) return false
        return line.any { it in BARE_RULE_SYNTAX }
    }

    /** Shortest bare network rule worth counting; `a.b` is a domain rule and is handled earlier. */
    private const val MIN_BARE_RULE_LENGTH = 3

    /**
     * Whether [character] is one a non-domain network rule is built from.
     *
     * Deliberately excludes `<`/`>` (markup), `\`, `{`/`}`, and `#` (only cosmetic rules use it, and
     * the `##` branch above already claims those). Non-ASCII is allowed because an IDN or a
     * percent-decoded path can contain it.
     */
    private fun isRuleChar(character: Char): Boolean = when {
        character in 'a'..'z' || character in 'A'..'Z' || character in '0'..'9' -> true
        character in "-_.~:/?=&%*|^[]$+,;@()'\"" -> true
        character.code >= 0x80 -> true
        else -> false
    }

    /** Rule syntax markers; at least one is what separates `-ad-sidebar.$image` from a bare word. */
    private const val BARE_RULE_SYNTAX = "/?=&%*|^$~+."

    private fun isPlausibleDomain(token: String): Boolean {
        if (token.isEmpty() || token.length > 253) return false
        if (token.contains('/') || token.contains('#')) return false
        if (token.equals("localhost", ignoreCase = true)) return false
        val labels = token.trimEnd('.').split('.')
        if (labels.size < 2) return false
        return labels.all { label ->
            label.isNotEmpty() && label.length <= 63 &&
                label.all { it.isLetterOrDigit() || it == '-' || it == '_' }
        }
    }
}

/**
 * Applies list-to-list composition before a list is handed to the compiler.
 *
 * The only directive handled is `!#include`, and only same-origin (AdGuard's rule: an include may
 * not point at another host, so a list cannot be used to make the app fetch an arbitrary URL). The
 * restriction is enforced here rather than at download time because that is where the base URL of
 * the including list is known.
 */
object ListPreprocessor {

    /** Maximum nesting depth, so a cycle or a pathological chain cannot loop forever. */
    const val MAX_INCLUDE_DEPTH = 3

    /** Maximum number of includes expanded from one list. */
    const val MAX_INCLUDES = 20

    /** One line of an `!#include`-expanded list, with where it came from. */
    data class Expansion(
        val text: String,
        /** URLs that were fetched, in order (the list itself plus every include). */
        val fetchedUrls: List<String>,
        /** Includes that were skipped, with why — surfaced in the list status. */
        val skipped: List<String>,
    )

    /**
     * Expand `!#include` directives in [text].
     *
     * @param text list body.
     * @param baseUrl the URL [text] was downloaded from; includes must share its origin.
     * @param fetch fetches one URL (normally the same [FilterTransport] the updater uses).
     */
    fun expand(text: String, baseUrl: String, fetch: (String) -> String?): Expansion {
        val fetched = mutableListOf<String>()
        val skipped = mutableListOf<String>()
        var includeCount = 0
        var currentFetched = 0

        fun expandInto(body: String, base: String, depth: Int): String {
            if (depth > MAX_INCLUDE_DEPTH) return body
            val output = StringBuilder(body.length)
            var first = true
            for (line in body.lineSequence()) {
                if (!first) output.append('\n')
                first = false
                val trimmed = line.trim()
                if (!trimmed.startsWith("!#include", ignoreCase = true)) {
                    output.append(line)
                    continue
                }
                if (includeCount >= MAX_INCLUDES) {
                    skipped.add("超过 $MAX_INCLUDES 条 include 上限，忽略：$trimmed")
                    output.append(line)
                    continue
                }
                val target = trimmed.substring("!#include".length).trim()
                val resolved = runCatching { URI(base).resolve(target).toString() }.getOrNull()
                if (resolved == null) {
                    skipped.add("无法解析 include 地址：$target")
                    continue
                }
                if (!sameOrigin(base, resolved)) {
                    skipped.add("跨源 include 被拒绝：$resolved")
                    continue
                }
                includeCount++
                val included = fetch(resolved)
                if (included == null) {
                    skipped.add("include 下载失败：$resolved")
                    continue
                }
                currentFetched++
                fetched.add(resolved)
                output.append(expandInto(included, resolved, depth + 1))
            }
            return output.toString()
        }

        val expanded = expandInto(text, baseUrl, 1)
        if (currentFetched == 0 && fetched.isEmpty()) {
            // Keep the original URL in the record so callers can always report what was used.
            fetched.add(baseUrl)
        } else {
            fetched.add(0, baseUrl)
        }
        return Expansion(expanded, fetched, skipped)
    }

    /** Whether two URLs share scheme, host and port — the same-origin test AdGuard specifies. */
    fun sameOrigin(base: String, candidate: String): Boolean {
        val a = runCatching { URI(base) }.getOrNull() ?: return false
        val b = runCatching { URI(candidate) }.getOrNull() ?: return false
        val schemeA = a.scheme?.lowercase() ?: return false
        val schemeB = b.scheme?.lowercase() ?: return false
        if (schemeA != schemeB) return false
        val hostA = a.host?.lowercase() ?: return false
        val hostB = b.host?.lowercase() ?: return false
        if (hostA != hostB) return false
        return effectivePort(a) == effectivePort(b)
    }

    private fun effectivePort(uri: URI): Int = when {
        uri.port > 0 -> uri.port
        uri.scheme.equals("https", ignoreCase = true) -> 443
        else -> 80
    }
}
