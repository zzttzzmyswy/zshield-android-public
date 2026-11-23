package top.zztweb.zshield.vpn

import android.content.Context
import java.io.File

/**
 * Materialises the rule files the core should load (see the M0 task card):
 *
 * - `assets/rules/builtin-test.txt` is extracted into app-private storage on every start, so an
 *   updated asset replaces the old copy;
 * - every `*.txt` in `files/rules/` is appended, in name order, which is the hook used to push extra
 *   rules with `adb push` during real-device testing (subscriptions arrive in M1).
 *
 * Rule files are plain text so the core's parser is the only thing that has to understand them.
 */
object RuleStorage {

    /** Directory scanned for user-supplied rule files. */
    const val EXTERNAL_RULE_DIR = "rules"

    private const val BUILTIN_ASSET = "rules/builtin-test.txt"
    private const val BUILTIN_FILE_NAME = "builtin-test.txt"
    private const val ENCRYPTED_DNS_ASSET = "rules/encrypted-dns-hosts.txt"
    private const val ENCRYPTED_DNS_FILE_NAME = "encrypted-dns-hosts.txt"
    private const val HTTPS_EXCLUDED_ASSET = "https/excluded-hosts.txt"
    private const val HTTPS_EXCLUDED_FILE_NAME = "https-excluded-hosts.txt"

    /**
     * Writes the built-in rules to the app's private files directory and returns the absolute
     * paths of all rule files the core should read, in load order.
     */
    fun prepareRuleFiles(context: Context): List<String> {
        val paths = mutableListOf<String>()
        val builtin = extractBuiltin(context)
        if (builtin != null) paths.add(builtin)

        val externalDir = File(context.filesDir, EXTERNAL_RULE_DIR)
        if (externalDir.isDirectory) {
            externalDir.listFiles()
                ?.filter { it.isFile && it.name.endsWith(".txt", ignoreCase = true) }
                ?.sortedBy { it.name }
                ?.forEach { paths.add(it.absolutePath) }
        }
        return paths
    }

    private fun extractBuiltin(context: Context): String? {
        val target = File(context.filesDir, BUILTIN_FILE_NAME)
        return try {
            // Always rewrite: the asset is the source of truth and is tiny.
            context.assets.open(BUILTIN_ASSET).use { input ->
                target.outputStream().use { output -> input.copyTo(output) }
            }
            target.absolutePath
        } catch (error: Exception) {
            // A missing asset must not stop the tunnel: filtering just falls back to the external
            // rule files, and the failure is visible in logcat.
            android.util.Log.w("ZShield", "cannot extract built-in rules", error)
            null
        }
    }

    /**
     * Writes the bundled HTTPS exclusion list to private storage and returns its absolute path.
     *
     * Same contract as [prepareEncryptedDnsHosts]: the core reads a real file, it is rewritten on
     * every start so an updated asset wins, and an empty string means "no built-in list" rather than
     * a reason to refuse to start. Without the list the user's own exclusions still apply — but
     * banking and payment domains would be decrypted, which is exactly what the list exists to
     * prevent, so a missing asset is logged loudly.
     */
    fun prepareHttpsExcludedHosts(context: Context): String {
        val target = File(context.filesDir, HTTPS_EXCLUDED_FILE_NAME)
        return try {
            context.assets.open(HTTPS_EXCLUDED_ASSET).use { input ->
                target.outputStream().use { output -> input.copyTo(output) }
            }
            target.absolutePath
        } catch (error: Exception) {
            android.util.Log.w("ZShield", "cannot extract the HTTPS exclusion list", error)
            ""
        }
    }

    /**
     * Writes the bundled encrypted-DNS host list to private storage and returns its absolute path.
     *
     * The core reads this file, so it has to exist as a real file rather than an asset stream. Like
     * the built-in rules it is rewritten on every start, so an updated asset always wins. An empty
     * string means "no list", which the core treats as "no fixed DoH/DoT blocklist" — never as a
     * reason to refuse to start.
     */
    fun prepareEncryptedDnsHosts(context: Context): String {
        val target = File(context.filesDir, ENCRYPTED_DNS_FILE_NAME)
        return try {
            context.assets.open(ENCRYPTED_DNS_ASSET).use { input ->
                target.outputStream().use { output -> input.copyTo(output) }
            }
            target.absolutePath
        } catch (error: Exception) {
            android.util.Log.w("ZShield", "cannot extract the encrypted-dns host list", error)
            ""
        }
    }
}
