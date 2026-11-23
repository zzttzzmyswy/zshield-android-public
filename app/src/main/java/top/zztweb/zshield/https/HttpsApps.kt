package top.zztweb.zshield.https

import android.content.Context
import android.content.pm.PackageManager
import android.util.Log

/**
 * Which applications the HTTPS filter decrypts, expressed as uids.
 *
 * The core works in uids because that is what `ConnectivityManager` reports for a connection; the
 * user and the asset files work in package names. This object is the one conversion between the two,
 * so the mapping rule exists once and can be tested without a device.
 *
 * # The two lists
 *
 * - **built-in browsers** (`assets/https/browsers.txt`): the applications that ship a system trust
 *   store and therefore accept a user-installed CA. Decrypting anything else is pointless at best
 *   (it would be refused) and harmful at worst (a pinning app would break) — the auto-bypass table
 *   covers the case where the list is wrong.
 * - **the user's own selection** (`AppSettings.httpsUserApps`): an explicit opt-in for an application
 *   the list does not know about.
 *
 * Both are converted here, and a package that is not installed is skipped: a browser the user
 * uninstalled must not keep a stale uid in the set, because Android reuses uids.
 */
object HttpsApps {

    private const val TAG = "ZShield"
    private const val BROWSER_ASSET = "https/browsers.txt"

    /**
     * The built-in browser package list, read from the asset.
     *
     * A missing asset is not fatal: HTTPS filtering then applies only to the user's own selections,
     * and the reason is logged. The alternative — refusing to enable the feature — would be worse.
     */
    fun browserPackages(context: Context): List<String> = try {
        context.assets.open(BROWSER_ASSET).bufferedReader().use { reader ->
            parsePackages(reader.readText())
        }
    } catch (error: Exception) {
        Log.w(TAG, "cannot read the browser list asset", error)
        emptyList()
    }

    /**
     * Parse a package list: one entry per line, `#` comments, blank lines and duplicates dropped.
     *
     * Kept separate from the asset read so the format is testable on the JVM.
     */
    fun parsePackages(text: String): List<String> {
        val seen = LinkedHashSet<String>()
        for (line in text.lineSequence()) {
            val trimmed = line.substringBefore('#').trim()
            if (trimmed.isEmpty()) continue
            // Android package names are `[A-Za-z0-9_]` segments joined by `.`; anything else would
            // make `getPackageUid` throw, so it is dropped here rather than at the lookup.
            if (isValidPackageName(trimmed)) seen.add(trimmed)
        }
        return seen.toList()
    }

    /**
     * Convert package names to uids, dropping the ones that are not installed.
     *
     * `getPackageUid` needs no permission for this (it answers for packages the caller can see, and
     * the application id of another app is public information); a `NameNotFoundException` means the
     * package is gone and its name is skipped.
     */
    fun uidsFor(context: Context, packages: Collection<String>): List<Int> {
        val manager = context.packageManager
        val uids = LinkedHashSet<Int>()
        for (name in packages) {
            if (!isValidPackageName(name)) continue
            try {
                uids.add(
                    manager.getPackageUid(name, 0),
                )
            } catch (error: PackageManager.NameNotFoundException) {
                // Not installed: drop it. Keeping a stale uid would silently decrypt whichever app
                // reuses that uid later.
                Log.i(TAG, "https: package $name is not installed, skipping")
            }
        }
        return uids.toList()
    }

    /**
     * The uid set the core should decrypt: the installed browsers plus the user's own picks.
     *
     * Deduplicated and sorted so a settings diff is stable and a repeated call produces the same
     * document (which matters because the core hot-reloads it).
     */
    fun selectedUids(
        context: Context,
        userPackages: Collection<String>,
        browsers: Collection<String> = browserPackages(context),
    ): List<Int> = uidsFor(context, browsers + userPackages).sorted()

    /** Java package-name syntax, which is what the platform checks. */
    fun isValidPackageName(name: String): Boolean {
        if (name.length > 255 || !name.contains('.')) return false
        return name.split('.').all { segment ->
            segment.isNotEmpty() &&
                segment.all { character -> character.isLetterOrDigit() || character == '_' } &&
                !segment.first().isDigit()
        }
    }
}
