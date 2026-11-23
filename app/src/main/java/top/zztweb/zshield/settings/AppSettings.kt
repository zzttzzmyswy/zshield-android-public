package top.zztweb.zshield.settings

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.io.IOException

/** How much of the network the tunnel carries. Mirrors `Mode` in `core/src/config.rs`. */
enum class TunnelMode(val wireName: String) {
    /** Route `0.0.0.0/0` and `::/0`: SNI/Host blocking, QUIC dropping, per-connection policy. */
    FULL("full"),

    /** Route only the virtual DNS addresses; the M0/M1 behaviour, kept as a light mode. */
    DNS_ONLY("dns_only"),
    ;

    companion object {
        fun fromWireName(name: String?): TunnelMode =
            entries.firstOrNull { it.wireName == name } ?: FULL
    }
}

/**
 * User-visible tunnel settings, persisted as one JSON document in the app's private files.
 *
 * Deliberately the same shape as M1's [top.zztweb.zshield.filters.FilterState]: a small file written
 * atomically (`temp + fsync + rename`), readable with `adb shell cat`, no database dependency.
 *
 * A process-wide singleton, for the same reason [top.zztweb.zshield.filters.FilterRepository] is one:
 * the debug UI writes a setting and the VPN service reads it on the next start, and two instances of
 * a class that owns its own `MutableStateFlow` would each keep their own copy — the write would land
 * in the file but the reader's flow would never see it, so a live screen would disagree with the
 * tunnel. `initialize` is idempotent and every accessor is safe before it (defaults are returned).
 */
object AppSettings {

    private lateinit var store: SettingsStore
    private val mutableState = MutableStateFlow(AppSettingsData())

    /** Current snapshot; collectors see every write. */
    val state: StateFlow<AppSettingsData> = mutableState.asStateFlow()

    /** Current snapshot, without collecting. */
    val current: AppSettingsData get() = mutableState.value

    /**
     * Loads the persisted settings. Idempotent: a second call (Application, VPN service, Activity)
     * does not re-read the file or reset the flow.
     */
    @Synchronized
    fun initialize(context: Context) {
        if (::store.isInitialized) return
        store = SettingsStore(File(context.applicationContext.filesDir, STORE_DIR_NAME))
        mutableState.value = store.read()
    }

    /** Test seam: point the singleton at an explicit store. */
    internal fun initializeForTest(settingsStore: SettingsStore) {
        store = settingsStore
        mutableState.value = settingsStore.read()
    }

    /** TUN mode. Rebuilding the tunnel is required for a change to take effect. */
    fun setMode(mode: TunnelMode) = update { it.copy(mode = mode) }

    /**
     * Packages excluded from the tunnel (`VpnService.Builder.addDisallowedApplication`).
     *
     * Blank entries and duplicates are dropped here rather than at the builder, and the list is kept
     * sorted so a settings diff is stable. Whether a package is installed is *not* checked here: an
     * app can be installed after the exclusion is configured, and the VPN service skips unknown names
     * at build time (logging them), which is the behaviour the task card asks for.
     */
    fun setExcludedApps(packages: List<String>) = update {
        it.copy(excludedApps = sanitizePackages(packages))
    }

    /** Whether UDP/443 is dropped so browsers fall back to TCP/TLS. */
    fun setBlockQuic(enabled: Boolean) = update { it.copy(blockQuic = enabled) }

    /** Whether TCP/853 and known public DoH/DoT hosts are refused. */
    fun setBlockEncryptedDnsBypass(enabled: Boolean) = update {
        it.copy(blockEncryptedDnsBypass = enabled)
    }

    /**
     * Whether HTTPS connections from the selected applications are decrypted (M3a).
     *
     * Stored as the user's intent, not as the effective state: the tunnel only decrypts once the CA
     * is actually installed, and that is decided where the config is built
     * ([top.zztweb.zshield.https.CertManager.state]). Keeping the intent separate means the switch
     * does not silently turn itself off when the certificate is removed from the system settings.
     */
    fun setHttpsFiltering(enabled: Boolean) = update { it.copy(httpsFiltering = enabled) }

    /**
     * Applications the user explicitly opted into decrypting, in addition to the built-in browsers.
     *
     * Same sanitisation as [setExcludedApps]: a bogus package name would make the platform throw at
     * the uid lookup, and the list is kept sorted so a diff is stable.
     */
    fun setHttpsUserApps(packages: List<String>) = update {
        it.copy(httpsUserApps = sanitizePackages(packages))
    }

    /**
     * Hostnames the user never wants decrypted, in addition to `assets/https/excluded-hosts.txt`.
     *
     * Entries are normalised to lowercase without a trailing dot, de-duplicated and kept in the
     * user's order: the core parses them the same way it parses the asset, and the user's own
     * ordering is what they see back in the UI.
     */
    fun setHttpsExcludedHosts(hosts: List<String>) = update {
        it.copy(httpsExcludedHosts = sanitizeHosts(hosts))
    }

    /**
     * Records what the user wants: filtering on ([wanted] = true) or off.
     *
     * This is *intent*, not state (M4a, `docs/KEEPALIVE.md`). It is written only by something the
     * user did — the UI switch, the notification's pause action, the quick-settings tile — and it is
     * what every automatic recovery path consults before touching the tunnel. A kill, a reboot, an
     * app upgrade or a system revocation must never rewrite it: those are not the user changing
     * their mind, and treating them as "off" is exactly how a protector ends up silently off.
     *
     * Turning protection back on also clears [AppSettingsData.revokedBySystem], because the user has
     * just re-asserted the intent that the revocation interrupted.
     */
    fun setProtectionWanted(wanted: Boolean) = update {
        if (wanted) {
            it.copy(protectionWanted = true, revokedBySystem = false)
        } else {
            it.copy(protectionWanted = false)
        }
    }

    /**
     * Records that the system withdrew the VPN (for example another VPN app took the interface).
     *
     * Deliberately separate from [setProtectionWanted]: the user still wants protection, so the
     * recovery paths keep trying, but the UI has to explain why the tunnel is down
     * (`HealthState.revokedBySystem`) instead of showing a switch that looks "on" for no reason.
     */
    fun setRevokedBySystem(revoked: Boolean) = update { it.copy(revokedBySystem = revoked) }

    /**
     * Reduce a host list to usable names.
     *
     * A `*`-style wildcard or a URL is dropped rather than guessed at: the core matches by suffix, so
     * `https://bank.example/x` would never match and silently do nothing.
     */
    fun sanitizeHosts(hosts: List<String>): List<String> {
        val seen = LinkedHashSet<String>()
        for (raw in hosts) {
            val host = raw.trim().trimEnd('.').lowercase()
            if (host.isEmpty() || host.length > 253) continue
            if (host.contains('/') || host.contains('*') || host.contains(' ')) continue
            if (!host.contains('.')) continue
            seen.add(host)
            if (seen.size >= MAX_HTTPS_EXCLUDED_HOSTS) break
        }
        return seen.toList()
    }

    private fun update(transform: (AppSettingsData) -> AppSettingsData) {
        synchronized(this) {
            val next = transform(mutableState.value)
            if (next == mutableState.value) return
            if (::store.isInitialized) store.write(next)
            mutableState.value = next
        }
    }

    const val STORE_DIR_NAME = "settings"
    const val STATE_FILE_NAME = "app-settings.json"
    const val MAX_EXCLUDED_APPS = 200
    const val MAX_HTTPS_EXCLUDED_HOSTS = 500

    /**
     * Reduce a package list to something `addDisallowedApplication` can accept.
     *
     * A bare package name is `[a-zA-Z0-9_]` segments joined by `.`; anything else is dropped instead
     * of being passed to the platform, where it throws `NameNotFoundException` and takes the whole
     * tunnel down with it.
     */
    fun sanitizePackages(packages: List<String>): List<String> =
        packages
            .asSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && isValidPackageName(it) }
            .distinct()
            .sorted()
            .take(MAX_EXCLUDED_APPS)
            .toList()

    /** Java package-name syntax, which is what the platform checks. */
    fun isValidPackageName(name: String): Boolean {
        if (name.length > 255 || !name.contains('.')) return false
        val segments = name.split('.')
        return segments.all { segment ->
            segment.isNotEmpty() &&
                segment.all { character -> character.isLetterOrDigit() || character == '_' } &&
                !segment.first().isDigit()
        }
    }
}

/**
 * Immutable snapshot of [AppSettings]. Field names here are the Kotlin source of truth for the
 * on-disk JSON (`AppSettingsData.toJson`).
 */
data class AppSettingsData(
    /** `full` by default: the whole point of M2a is that filtering works for every connection. */
    val mode: TunnelMode = TunnelMode.FULL,
    /** Packages whose traffic bypasses the tunnel entirely. */
    val excludedApps: List<String> = emptyList(),
    val blockQuic: Boolean = true,
    val blockEncryptedDnsBypass: Boolean = true,
    /**
     * Whether the user wants HTTPS filtering (M3a).
     *
     * Off by default: decrypting a connection is a visible trust decision, and it only works after
     * the user installs the CA. The tunnel additionally requires the certificate to be installed, so
     * "on but not installed" filters nothing rather than failing every handshake.
     */
    val httpsFiltering: Boolean = false,
    /** Applications the user opted into decrypting, beyond the built-in browser list. */
    val httpsUserApps: List<String> = emptyList(),
    /** Extra hostnames never to decrypt, beyond `assets/https/excluded-hosts.txt`. */
    val httpsExcludedHosts: List<String> = emptyList(),
    /**
     * Whether the user wants protection on — the persisted *intent* that every automatic recovery
     * path consults (M4a, `docs/KEEPALIVE.md`).
     *
     * Only [AppSettings.setProtectionWanted] writes it, and only in response to a user action. A
     * kill, a reboot, an upgrade or a system revocation leaves it alone: "the tunnel is down" and
     * "the user turned it off" are different facts, and only the second one should stop recovery.
     *
     * A fresh install starts at `false` (protection begins when the user turns it on). A document
     * written before M4a has no such field and also reads as `false`, so an upgrade never starts a
     * tunnel the user had switched off; the cost is that an upgrading user arms auto-recovery with
     * one toggle, which `docs/KEEPALIVE.md` documents.
     */
    val protectionWanted: Boolean = false,
    /**
     * True when the *system* took the VPN away (another VPN app was preferred, the user revoked
     * consent for this app, the profile changed).
     *
     * Kept apart from [protectionWanted] on purpose: after a revocation the user still wants
     * protection, so recovery keeps trying, but the UI has to explain why nothing is filtered
     * ([top.zztweb.zshield.health.HealthState.revokedBySystem]) rather than showing a switch that
     * claims to be on.
     */
    val revokedBySystem: Boolean = false,
) {
    fun toJson(): JSONObject {
        val root = JSONObject()
        root.put("version", VERSION)
        root.put("mode", mode.wireName)
        root.put("excludedApps", JSONArray(excludedApps))
        root.put("blockQuic", blockQuic)
        root.put("blockEncryptedDnsBypass", blockEncryptedDnsBypass)
        root.put("httpsFiltering", httpsFiltering)
        root.put("httpsUserApps", JSONArray(httpsUserApps))
        root.put("httpsExcludedHosts", JSONArray(httpsExcludedHosts))
        root.put("protectionWanted", protectionWanted)
        root.put("revokedBySystem", revokedBySystem)
        return root
    }

    companion object {
        /**
         * Bumped when the document layout changes incompatibly; unknown fields are ignored.
         *
         * v2 adds the M3a HTTPS settings, v3 the M4a keep-alive intent. Neither bump is needed for
         * compatibility — an older document simply has no such fields and falls back to the defaults,
         * which are the safe ones — but the number records which shape the file has.
         */
        const val VERSION = 3

        fun fromJson(json: String): AppSettingsData {
            val root = JSONObject(json)
            val excluded = stringList(root.optJSONArray("excludedApps"))
            return AppSettingsData(
                mode = TunnelMode.fromWireName(root.optString("mode")),
                excludedApps = AppSettings.sanitizePackages(excluded),
                blockQuic = root.optBoolean("blockQuic", true),
                blockEncryptedDnsBypass = root.optBoolean("blockEncryptedDnsBypass", true),
                httpsFiltering = root.optBoolean("httpsFiltering", false),
                httpsUserApps = AppSettings.sanitizePackages(
                    stringList(root.optJSONArray("httpsUserApps")),
                ),
                httpsExcludedHosts = AppSettings.sanitizeHosts(
                    stringList(root.optJSONArray("httpsExcludedHosts")),
                ),
                protectionWanted = root.optBoolean("protectionWanted", false),
                revokedBySystem = root.optBoolean("revokedBySystem", false),
            )
        }
    }
}

/**
 * On-disk home of [AppSettingsData].
 *
 * Writes are atomic on POSIX (`rename` within one filesystem), so a crash mid-write leaves either the
 * old file or the new one — never a truncated document that would silently reset every setting.
 */
/** Read a JSON array of strings, tolerating absent entries and non-string values. */
private fun stringList(array: JSONArray?): List<String> {
    if (array == null) return emptyList()
    return buildList {
        for (index in 0 until array.length()) {
            array.optString(index).takeIf { it.isNotBlank() }?.let { add(it) }
        }
    }
}

class SettingsStore(private val rootDir: File) {

    constructor(context: Context) : this(File(context.filesDir, AppSettings.STORE_DIR_NAME))

    val stateFile: File get() = File(rootDir, AppSettings.STATE_FILE_NAME)

    fun read(): AppSettingsData {
        val file = stateFile
        if (!file.isFile) return AppSettingsData()
        return try {
            AppSettingsData.fromJson(file.readText(Charsets.UTF_8))
        } catch (error: Exception) {
            // A corrupt settings file must not brick filtering or the UI: fall back to the defaults
            // and keep the broken file for inspection.
            android.util.Log.w("ZShield", "cannot read app settings, using defaults", error)
            runCatching { file.renameTo(File(rootDir, "${AppSettings.STATE_FILE_NAME}.corrupt")) }
            AppSettingsData()
        }
    }

    fun write(data: AppSettingsData) {
        rootDir.mkdirs()
        writeAtomically(stateFile, data.toJson().toString().toByteArray(Charsets.UTF_8))
    }

    /** Same contract as [top.zztweb.zshield.filters.FilterStore.writeAtomically]. */
    fun writeAtomically(target: File, bytes: ByteArray) {
        target.parentFile?.mkdirs()
        val temp = File(target.parentFile, "${target.name}.${System.nanoTime()}.part")
        try {
            FileOutputStream(temp).use { stream ->
                stream.write(bytes)
                stream.flush()
                stream.fd.sync()
            }
            if (!temp.renameTo(target)) {
                throw IOException("cannot rename ${temp.name} -> ${target.name}")
            }
        } finally {
            if (temp.exists()) temp.delete()
            target.parentFile
                ?.listFiles { file ->
                    file.name.startsWith("${target.name}.") && file.name.endsWith(".part")
                }
                ?.forEach { stale -> stale.delete() }
        }
    }
}
