package top.zztweb.zshield.ui.https

import top.zztweb.zshield.R

/**
 * What the HTTPS page (and its summary row in Settings) tells the user, derived from four facts
 * that live in different places: the user's intent (`AppSettings.httpsFiltering`), the tunnel mode,
 * the certificate state, and what the running core reports (`VpnStats.httpsFiltering`).
 *
 * Kept free of Android types so every combination is testable on the JVM. The order of the checks
 * is the order the user has to fix things in: a missing certificate is reported before a missing
 * install, and both before "the tunnel is not running".
 */
enum class HttpsStatus(val summary: Int, val needsAction: Boolean) {
    /** The switch is off. */
    OFF(R.string.ui_https_status_off, needsAction = false),

    /** On, but the tunnel only routes DNS, so there is no TLS to decrypt. */
    DNS_ONLY_MODE(R.string.ui_https_status_dns_only, needsAction = true),

    /** On, but no root certificate exists yet. */
    NEEDS_CERT(R.string.ui_https_status_needs_cert, needsAction = true),

    /** On, a certificate exists, but the system store does not hold it. */
    NEEDS_INSTALL(R.string.ui_https_status_needs_install, needsAction = true),

    /** Everything is in place; it takes effect when protection is turned on. */
    READY(R.string.ui_https_status_ready, needsAction = false),

    /** The running core is decrypting. */
    ACTIVE(R.string.ui_https_status_active, needsAction = false),
    ;

    companion object {
        /**
         * @param enabled the user's switch.
         * @param fullMode whether the tunnel routes all traffic (HTTPS needs it).
         * @param certGenerated whether a root certificate exists.
         * @param certInstalled whether the system user store holds it.
         * @param coreDecrypting what the running core reports; `false` while stopped.
         */
        fun of(
            enabled: Boolean,
            fullMode: Boolean,
            certGenerated: Boolean,
            certInstalled: Boolean,
            coreDecrypting: Boolean,
        ): HttpsStatus = when {
            !enabled -> OFF
            !fullMode -> DNS_ONLY_MODE
            !certGenerated -> NEEDS_CERT
            !certInstalled -> NEEDS_INSTALL
            coreDecrypting -> ACTIVE
            else -> READY
        }

        /**
         * Whether the tunnel *should* be decrypting, which is the same rule `ZShieldVpnService`
         * applies when it builds the config. The page compares this with what the core reports to
         * decide whether a rebuild is needed after a change it cannot hot-apply.
         */
        fun shouldDecrypt(enabled: Boolean, fullMode: Boolean, certInstalled: Boolean): Boolean =
            enabled && fullMode && certInstalled
    }
}

/**
 * Display helpers for the HTTPS page. Pure, for the same reason as [HttpsStatus].
 */
object HttpsText {

    /**
     * The stable reason strings of `BypassEntry.reason` (`docs/JNI.md` §7) mapped to user wording.
     * An unknown reason falls back to the generic "handshake failed" rather than showing a code.
     */
    fun reason(code: String): Int = when (code) {
        "client_unknown_ca" -> R.string.ui_https_reason_unknown_ca
        "client_bad_certificate" -> R.string.ui_https_reason_bad_cert
        "client_certificate_unknown" -> R.string.ui_https_reason_cert_unknown
        "client_certificate_required" -> R.string.ui_https_reason_cert_required
        "client_disconnect" -> R.string.ui_https_reason_disconnect
        else -> R.string.ui_https_reason_handshake
    }

    /**
     * A SHA-256 hex fingerprint as colon-separated uppercase byte pairs — the notation Android's own
     * certificate details screen uses, so the user can compare them — in four lines of 8 bytes, which
     * fit a phone width in monospace without wrapping mid-line. Anything that is not 64 hex
     * characters is returned unchanged.
     */
    fun fingerprint(hex: String): String {
        val clean = hex.trim().uppercase()
        if (clean.length != 64 || !clean.all { it in '0'..'9' || it in 'A'..'F' }) return hex
        return clean.chunked(2).chunked(8).joinToString("\n") { it.joinToString(":") }
    }

    /** Whole hours left until [expiresAtMs], at least 1 while the entry is still live. */
    fun hoursLeft(nowMs: Long, expiresAtMs: Long): Long {
        val left = expiresAtMs - nowMs
        if (left <= 0) return 0
        return ((left + HOUR_MS - 1) / HOUR_MS).coerceAtLeast(1)
    }

    /**
     * Count the entries of a bundled host or package list: one per line, `#` starts a comment,
     * `!` lines are file-level comments (the AdGuard convention the assets follow).
     */
    fun countListEntries(text: String): Int =
        text.lineSequence()
            .map { it.substringBefore('#').trim() }
            .count { it.isNotEmpty() && !it.startsWith('!') }

    private const val HOUR_MS = 3_600_000L
}
