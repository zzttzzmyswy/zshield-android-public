package top.zztweb.zshield.vpn

import kotlinx.coroutines.flow.StateFlow

/** Lifecycle state of the tunnel, as seen by the UI. */
sealed interface VpnState {
    /** No tunnel; nothing is filtered. */
    data object Stopped : VpnState

    /** A tunnel is being established (permission, interface, native engine). */
    data object Starting : VpnState

    /** The tunnel is up and filtering. */
    data object Running : VpnState

    /** Start failed or the tunnel died; [message] explains why. */
    data class Error(val message: String) : VpnState
}

/**
 * System "Private DNS" (DNS-over-TLS) state, as reported by the active network's [android.net.LinkProperties].
 *
 * When the system resolver is DoT, every lookup is already encrypted before it reaches the tunnel's
 * virtual DNS address, so *name-based* filtering still works but the user cannot add their own
 * resolver, and the core sees only the queries the system chose to send us. The UI uses this to
 * suggest turning the strict mode off (`docs/DESIGN.md` §4); the tunnel itself does not act on it.
 */
data class PrivateDnsStatus(
    /** True when the platform reports private DNS in use. */
    val active: Boolean = false,
    /** The configured DoT hostname, or `null` in opportunistic mode / when not active. */
    val serverName: String? = null,
) {
    /** Strict (hostname-pinned) private DNS, which the card asks the UI to warn about. */
    val isStrict: Boolean get() = active && !serverName.isNullOrBlank()

    companion object {
        val OFF = PrivateDnsStatus(active = false, serverName = null)
    }
}

/** Counter snapshot shown in the UI. All counters are monotonic within one run. */
data class VpnStats(
    val dnsQueries: Long = 0,
    val dnsBlocked: Long = 0,
    val dnsErrors: Long = 0,
    val dnsCached: Long = 0,
    val upstreamLatencyMsP50: Long = 0,
    val cacheEntries: Long = 0,
    val rulesBlock: Long = 0,
    val rulesUnsupported: Long = 0,
    /** Forwarded TCP connections currently open. */
    val tcpActive: Long = 0,
    val tcpTotal: Long = 0,
    val udpActive: Long = 0,
    val bytesUp: Long = 0,
    val bytesDown: Long = 0,
    val blockedConnections: Long = 0,
    val quicDropped: Long = 0,
    val dnsHijacked: Long = 0,
    val encryptedDnsDropped: Long = 0,
    val echStripped: Long = 0,
    /** Plaintext HTTP requests judged since start (M2b). */
    val httpRequests: Long = 0,
    /** Of those, the ones answered with a synthesized response. */
    val httpBlocked: Long = 0,
    val httpRedirected: Long = 0,
    /** Connections whose HTTP filtering stopped part-way (non-HTTP, upgrade, oversized head). */
    val httpDegraded: Long = 0,
    /** Whether `engine.bin` was loaded; false means hostname-only filtering. */
    val httpEngineLoaded: Boolean = false,
    /** Requests held by the recent-request ring buffer (max 500). */
    val requestLogSize: Long = 0,
    /** Whether the core is decrypting HTTPS connections (M3a). */
    val httpsFiltering: Boolean = false,
    /** 443 connections decrypted and filtered. */
    val httpsIntercepted: Long = 0,
    /** 443 connections left alone (not selected, excluded, auto-bypassed, upstream invalid). */
    val httpsPassthrough: Long = 0,
    /** Connections that entered the auto-bypass table. */
    val httpsAutoBypassed: Long = 0,
    /** Connections whose upstream certificate failed verification. */
    val httpsUpstreamInvalid: Long = 0,
    /** Client-side TLS handshake failures. */
    val httpsHandshakeFailures: Long = 0,
    /** HTTP/2 requests judged on a decrypted connection. */
    val h2Streams: Long = 0,
    /** Of those, the ones answered locally. */
    val h2Blocked: Long = 0,
    /** Live auto-bypass entries. */
    val httpsBypassEntries: Long = 0,
) {
    /**
     * Everything blocked, across every layer — what the persistent notification reports.
     *
     * The same sum the home screen shows as "已拦截" (`HomeScreen.StatsCard`): DNS answers, refused
     * connections and blocked plaintext HTTP. It lives here rather than in the service so the
     * notification and the home screen cannot disagree about what "blocked" means; the field
     * deliberately matches that formula exactly rather than inventing a wider one.
     */
    val blockedTotal: Long
        get() = dnsBlocked + blockedConnections + httpBlocked
}

/**
 * The control plane the UI talks to (fixed by the M0 task card, see `docs/JNI.md`).
 *
 * Lifecycle is deliberately owned by the implementation singleton rather than an Activity, so a
 * configuration change cannot tear the tunnel down.
 */
interface VpnController {
    /** Current tunnel state. */
    val state: StateFlow<VpnState>

    /**
     * Filtering counters.
     *
     * Only polled while there is at least one subscriber **and** the screen is on, at most once per
     * second; see [ZShieldVpnController]. Collecting this flow does not wake the device.
     */
    val stats: StateFlow<VpnStats>

    /**
     * The recent-request log, newest last, optionally only entries newer than `sinceId`.
     *
     * Pull-based on purpose: the core serializes only when this is called, so a screen that is not
     * open costs nothing (`docs/DESIGN.md` decision 10). Returns an empty list while no tunnel runs
     * or when the handle is unknown. Safe to call from any thread.
     */
    /**
     * The HTTPS auto-bypass table: `(uid, host, expiresAtMs, reason)` for every application that
     * refused our certificate and is therefore passed through.
     *
     * Empty while no tunnel runs, when HTTPS filtering is off, or when nothing has been bypassed.
     * Safe to call from any thread.
     */
    fun httpsBypass(): List<top.zztweb.zshield.https.BypassEntry> =
        emptyList()

    fun recentRequests(sinceId: Long = 0): List<top.zztweb.zshield.core.RequestLogEntry>

    /**
     * System Private DNS (DoT) status, refreshed from the active [android.net.LinkProperties].
     * `OFF` while no tunnel is running.
     */
    val privateDns: StateFlow<PrivateDnsStatus>

    /**
     * Starts filtering.
     *
     * The caller (an Activity) is responsible for obtaining the VPN consent dialog via
     * `VpnService.prepare` first; this method assumes consent is already granted and reports
     * [VpnState.Error] if it is not.
     */
    fun start(context: android.content.Context)

    /** Stops filtering and removes the notification. Safe to call when already stopped. */
    fun stop(context: android.content.Context)

    /**
     * Rebuilds the tunnel (stop, then start) so a settings change takes effect.
     *
     * The UI only calls this; deciding *whether* a rebuild is needed is the controller's job and is
     * documented per field in [top.zztweb.zshield.settings.AppSettingsData].
     */
    fun restart(context: android.content.Context)
}
