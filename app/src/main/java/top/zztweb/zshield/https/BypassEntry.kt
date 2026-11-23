package top.zztweb.zshield.https

import org.json.JSONArray
import org.json.JSONObject

/**
 * One entry of the HTTPS auto-bypass table (`httpsBypassJson`, `docs/JNI.md` §7).
 *
 * A pair lands here when the client refused ZShield's certificate — a pinned application, one that
 * does not trust user CAs, or one that aborts the handshake. It is then passed through, unchanged, for
 * 24 hours, so the application keeps working instead of failing on every connection
 * (`docs/DESIGN.md` decision 7).
 *
 * @param uid the owning application's uid. Android reports uids, and the package name is looked up
 *   only for display.
 * @param host the hostname that was refused.
 * @param expiresAtMs when the entry stops applying, in milliseconds since the Unix epoch.
 * @param reason which handshake failure produced it (`client_unknown_ca`, `client_bad_certificate`,
 *   `client_certificate_unknown`, `client_certificate_required`, `client_disconnect`,
 *   `client_handshake_failed`). Stable strings: the UI translates them, so they are part of the
 *   contract.
 */
data class BypassEntry(
    val uid: Int,
    val host: String,
    val expiresAtMs: Long,
    val reason: String,
) {
    companion object {
        /** Parse the array `Native.httpsBypassJson` returns. A malformed document is an empty list. */
        fun listFromJson(json: String): List<BypassEntry> {
            if (json.isBlank()) return emptyList()
            val array = runCatching { JSONArray(json) }.getOrNull() ?: return emptyList()
            val entries = ArrayList<BypassEntry>(array.length())
            for (index in 0 until array.length()) {
                val item = array.optJSONObject(index) ?: continue
                entries.add(fromJson(item))
            }
            return entries
        }

        private fun fromJson(json: JSONObject): BypassEntry = BypassEntry(
            uid = json.optInt("uid"),
            host = json.optString("host"),
            expiresAtMs = json.optLong("expiresAtMs"),
            reason = json.optString("reason"),
        )
    }
}
