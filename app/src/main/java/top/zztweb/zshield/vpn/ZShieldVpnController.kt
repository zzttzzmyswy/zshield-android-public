package top.zztweb.zshield.vpn

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.FlowCollector
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import top.zztweb.zshield.core.RequestLogEntry
import top.zztweb.zshield.core.Native
import top.zztweb.zshield.core.NativeStats
import top.zztweb.zshield.settings.AppSettings
import top.zztweb.zshield.settings.TunnelMode
import java.util.concurrent.atomic.AtomicInteger

/**
 * The single source of truth for tunnel state and counters.
 *
 * Process-wide singleton because the tunnel outlives any Activity: a rotation must not restart
 * filtering, and the notification and the debug screen must show the same numbers.
 *
 * Stats polling follows `docs/DESIGN.md` §10 (energy): the core is asked for `statsJson` only while
 * someone is collecting [stats] **and** the screen is interactive, and never more often than once
 * per second. With the screen off the poller idles, so a backgrounded tunnel costs no wakeups.
 */
object ZShieldVpnController : VpnController {

    /** Minimum interval between two `statsJson` pulls. */
    private const val POLL_INTERVAL_MS = 1_000L

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    private val mutableState = MutableStateFlow<VpnState>(VpnState.Stopped)
    override val state: StateFlow<VpnState> = mutableState.asStateFlow()

    private val mutableStats = MutableStateFlow(VpnStats())
    private val statsSubscribers = AtomicInteger(0)
    override val stats: StateFlow<VpnStats> =
        CountingStateFlow(mutableStats, statsSubscribers)

    private val mutablePrivateDns = MutableStateFlow(PrivateDnsStatus.OFF)
    override val privateDns: StateFlow<PrivateDnsStatus> = mutablePrivateDns.asStateFlow()

    /** Mode the tunnel was last started with, for diagnostics and the debug screen. */
    @Volatile
    var activeMode: TunnelMode = TunnelMode.FULL
        private set

    private var engineHandle: Long = 0L
    private var pollJob: Job? = null

    /** Registered once, so a network change refreshes [privateDns]; unregistered on stop. */
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    /** Set by the Activity so the poller knows about screen state without holding a Context. */
    @Volatile
    private var screenOnProvider: () -> Boolean = { true }

    /**
     * Called by the foreground service so a counter change reaches the persistent notification.
     *
     * The service registers it while its tunnel runs; it *re-posts an existing notification* and
     * never pulls stats itself, so the "no JNI call while the screen is off" rule still holds — the
     * callback only fires on a poll that already happened.
     */
    @Volatile
    private var statsObserver: ((VpnStats) -> Unit)? = null

    /** Last raw snapshot, for diagnostics (`docs/TESTING.md`) and notifications. */
    @Volatile
    var lastStats: NativeStats = NativeStats()
        private set

    /** True while the native engine is live. */
    val isEngineRunning: Boolean
        get() = engineHandle != 0L

    override fun start(context: Context) {
        when (mutableState.value) {
            is VpnState.Running, is VpnState.Starting -> {
                // Already up (or coming up): the user's intent is still "on", which matters after a
                // failed start, so record it even though there is nothing to start.
                recordUserIntent(context, wanted = true)
                return
            }
            else -> Unit
        }
        // Recorded *before* the start attempt: a caller that reaches this method is the user (the
        // UI switch, the notification, the tile), and `protectionWanted` is what every recovery path
        // reads. Writing it only on success would lose the intent of a start that failed because the
        // consent dialog was declined, and the app would then never recover on its own.
        recordUserIntent(context, wanted = true)
        if (VpnService.prepare(context) != null) {
            // The caller must show the system consent dialog; we cannot.
            mutableState.value = VpnState.Error("需要先授予 VPN 权限")
            return
        }
        mutableState.value = VpnState.Starting
        startServiceIntent(context)
    }

    /**
     * Starts filtering on behalf of an automatic recovery decision, without touching the persisted
     * intent.
     *
     * The difference from [start] is exactly the intent write: recovery runs because the intent is
     * already true, and a recovery start must never be able to *create* it (that would turn "the
     * tunnel came back once" into "protection is permanently on", including after the user paused
     * it). Called by [ProtectionRecovery] only, after [RecoveryPolicy] said
     * [RecoveryOutcome.RECOVER].
     */
    internal fun startForRecovery(context: Context) {
        when (mutableState.value) {
            is VpnState.Running, is VpnState.Starting -> return
            else -> Unit
        }
        // `prepare` is consulted here too: `RecoveryPolicy` already required consent, but it can be
        // revoked between the check and this call (another VPN app taking over), and starting a
        // service that cannot establish would surface as an error notification for no reason.
        if (VpnService.prepare(context) != null) {
            Log.i("ZShield", "recovery skipped: VPN consent is missing")
            return
        }
        mutableState.value = VpnState.Starting
        startServiceIntent(context)
    }

    /**
     * Writes [AppSettings.protectionWanted] because the user asked for it (M4a task card §1).
     *
     * Every user-facing toggle goes through here — the UI switch, the notification's pause action,
     * the quick-settings tile — and nothing else does. Automatic recovery deliberately has no way to
     * set it: a kill or a reboot is not the user changing their mind.
     */
    private fun recordUserIntent(context: Context, wanted: Boolean) {
        runCatching {
            AppSettings.initialize(context.applicationContext)
            if (AppSettings.current.protectionWanted != wanted) {
                AppSettings.setProtectionWanted(wanted)
            }
        }.onFailure { Log.w("ZShield", "cannot persist protection intent", it) }
    }

    /** Delivers one start command to the service, reporting a refusal as [VpnState.Error]. */
    private fun startServiceIntent(context: Context) {
        val intent = Intent(context, ZShieldVpnService::class.java)
            .setAction(ZShieldVpnService.ACTION_START)
        // `startForegroundService` throws `ForegroundServiceStartNotAllowedException` from API 31
        // when the app has no `ACTIVATE_VPN` app-op yet (i.e. the user has never granted the consent
        // dialog) and no foreground-start exemption. That is a *recoverable* state — the caller shows
        // the consent dialog and tries again — so it must become `VpnState.Error`, never an
        // uncaught exception on whatever thread called `start` (MYS-2716 §6).
        runCatching { context.startForegroundService(intent) }
            .onFailure { error ->
                // `ForegroundServiceStartNotAllowedException` only exists from API 31, and this app
                // runs on API 28+, so it is matched by name rather than by `is`: referencing the
                // class directly would need an API guard and buy nothing, because the only thing
                // the branch does is add a hint.
                val name = error::class.java.name
                val hint = if (name.endsWith("ForegroundServiceStartNotAllowedException")) {
                    "（首次使用需先打开一次应用授予 VPN 权限）"
                } else {
                    ""
                }
                mutableState.value =
                    VpnState.Error("无法启动 VPN 服务：${error.message}$hint")
            }
    }

    override fun stop(context: Context) {
        // A user-initiated stop is the *only* thing allowed to clear the intent (M4a task card §1):
        // every kill, reboot, upgrade and revocation leaves it true so recovery keeps trying.
        recordUserIntent(context, wanted = false)
        ZShieldVpnService.requestStop(context)
    }

    override fun restart(context: Context) {
        // A rebuild is stop-then-start through the service, which re-reads AppSettings on start. The
        // stop is asynchronous (it goes through the service), so the start is issued from the
        // service's own teardown path via ACTION_START; sending both in order is enough for the
        // serial command queue the service runs on.
        val intent = Intent(context, ZShieldVpnService::class.java)
            .setAction(ZShieldVpnService.ACTION_RESTART)
        when (mutableState.value) {
            is VpnState.Running, is VpnState.Starting ->
                runCatching { context.startForegroundService(intent) }
                    .onFailure { error ->
                        mutableState.value = VpnState.Error("无法重启 VPN 服务：${error.message}")
                    }
            else -> start(context)
        }
    }

    /** Records the mode a tunnel start used, for diagnostics and the debug screen. */
    internal fun onTunnelStarted(mode: TunnelMode) {
        activeMode = mode
    }

    /**
     * Registers for link-property changes and publishes the current Private DNS status.
     *
     * Called by the service once the tunnel is up: before that there is no reason to hold a network
     * callback, and holding one while stopped would be a battery cost with no benefit.
     */
    internal fun startPrivateDnsMonitoring(context: Context) {
        refreshPrivateDns(context)
        registerNetworkCallback(context.applicationContext)
    }

    /** Releases the network callback; called when the tunnel stops. */
    internal fun stopPrivateDnsMonitoring(context: Context) {
        unregisterNetworkCallback(context.applicationContext)
        mutablePrivateDns.value = PrivateDnsStatus.OFF
    }

    /**
     * Read the system Private DNS setting from the active network and publish it.
     *
     * The platform only exposes `isPrivateDnsActive` / `privateDnsServerName` through
     * [LinkProperties], so this needs a [ConnectivityManager] and the manifest's
     * `ACCESS_NETWORK_STATE`. It is called once at tunnel start and again on every link-property
     * change, so the UI never polls for it.
     */
    fun refreshPrivateDns(context: Context) {
        val manager = context.getSystemService(ConnectivityManager::class.java)
        val active: Network? = manager?.activeNetwork
        val properties: LinkProperties? = active?.let { manager?.getLinkProperties(it) }
        mutablePrivateDns.value = fromLinkProperties(properties)
    }

    private fun registerNetworkCallback(context: Context) {
        if (networkCallback != null) return
        val manager = context.getSystemService(ConnectivityManager::class.java) ?: return
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                mutablePrivateDns.value = fromLinkProperties(linkProperties)
            }

            override fun onLost(network: Network) {
                mutablePrivateDns.value = PrivateDnsStatus.OFF
            }
        }
        runCatching { manager.registerNetworkCallback(request, callback) }
            .onSuccess { networkCallback = callback }
            .onFailure { /* no permission or no manager: the status simply stays OFF */ }
    }

    private fun unregisterNetworkCallback(context: Context) {
        val callback = networkCallback ?: return
        networkCallback = null
        val manager = context.getSystemService(ConnectivityManager::class.java) ?: return
        runCatching { manager.unregisterNetworkCallback(callback) }
    }

    /** Registers the screen-state callback; the Activity passes `PowerManager::isInteractive`. */
    fun setScreenOnProvider(provider: () -> Boolean) {
        screenOnProvider = provider
    }

    /**
     * Registers (or with `null`, clears) the notification updater.
     *
     * Only the foreground service sets this, and it is the only consumer: the poller already runs
     * exclusively while a screen is on and collecting, so a callback from here cannot wake anything.
     */
    internal fun setStatsObserver(observer: ((VpnStats) -> Unit)?) {
        statsObserver = observer
    }

    // ---------------------------------------------------------------------------------------
    // Called by ZShieldVpnService
    // ---------------------------------------------------------------------------------------

    internal fun onStateChanged(newState: VpnState) {
        mutableState.value = newState
        when (newState) {
            is VpnState.Running -> ensurePolling()
            is VpnState.Stopped, is VpnState.Error -> {
                engineHandle = 0L
                mutablePrivateDns.value = PrivateDnsStatus.OFF
                stopPolling()
            }
            VpnState.Starting -> Unit
        }
    }

    internal fun onEngineStarted(handle: Long) {
        engineHandle = handle
        // A fresh engine starts from zero; clearing here means the screen never shows the previous
        // run's counters between "Running" and the first poll.
        lastStats = NativeStats()
        mutableStats.value = VpnStats()
    }

    /**
     * Called by the service *before* it calls `Native.stop`.
     *
     * Ordering matters: if the poller were allowed to run while the handle is being destroyed it
     * would ask for stats of a dead handle, get `{}` back, and overwrite the last real counter
     * snapshot with zeros. Clearing the handle first makes the poller skip its next tick instead.
     */
    internal fun onEngineStopping() {
        engineHandle = 0L
        stopPolling()
    }

    internal fun onError(message: String) {
        engineHandle = 0L
        mutableState.value = VpnState.Error(message)
        stopPolling()
    }

    /** Debug/test hook: the handle of the running tunnel, or `0`. */
    val engineHandleForDebug: Long get() = engineHandle

    override fun httpsBypass(): List<top.zztweb.zshield.https.BypassEntry> {
        val handle = engineHandle
        if (handle == 0L) return emptyList()
        // `Native.httpsBypassJson` is `String?`: a JVM allocation failure is reported as `null`, and
        // an empty table is the right thing to show for it (MYS-2716 §2).
        val json = Native.httpsBypassJson(handle) ?: return emptyList()
        return top.zztweb.zshield.https.BypassEntry.listFromJson(json)
    }

    /**
     * Empties the running core's HTTPS auto-bypass table, so every pair is decrypted again on its
     * next connection. A no-op while no tunnel runs. Used by the HTTPS page's "retry" action.
     */
    fun clearHttpsBypass() {
        top.zztweb.zshield.https.CertManager.clearBypass(engineHandle)
    }

    override fun recentRequests(sinceId: Long): List<RequestLogEntry> {
        val handle = engineHandle
        if (handle == 0L) return emptyList()
        val json = Native.recentRequestsJson(handle, sinceId) ?: return emptyList()
        return RequestLogEntry.listFromJson(json)
    }

    // ---------------------------------------------------------------------------------------
    // Stats polling
    // ---------------------------------------------------------------------------------------

    private fun ensurePolling() {
        if (pollJob?.isActive == true) return
        pollJob = scope.launch {
            while (true) {
                delay(POLL_INTERVAL_MS)
                val handle = engineHandle
                if (handle == 0L) continue
                // Both conditions are re-checked every tick: no subscriber or a dark screen means
                // no JNI call at all.
                if (statsSubscribers.get() <= 0) continue
                if (!screenOnProvider()) continue
                // `statsJson` is `String?` and this is where the process used to die: the old
                // non-null declaration turned the one return the Rust side cannot prevent — a JVM
                // allocation failure — into a `NullPointerException` on a background coroutine,
                // which takes the whole app down (MYS-2716 §2). `null` means "no snapshot this
                // tick"; the previous one stays on screen, which is the harmless answer.
                val json = Native.statsJson(handle) ?: continue
                if (json.isBlank()) continue
                val snapshot = NativeStats.fromJson(json)
                lastStats = snapshot
                val published = snapshot.toVpnStats()
                mutableStats.value = published
                // Only reached when a screen was already on and collecting, so telling the service
                // to re-post its notification adds no wakeup and no JNI call of its own.
                runCatching { statsObserver?.invoke(published) }
            }
        }
    }

    private fun stopPolling() {
        pollJob?.cancel()
        pollJob = null
    }

    /** Applies a raw snapshot without going through JNI; used by unit tests. */
    internal fun applyStatsForTest(snapshot: NativeStats) {
        lastStats = snapshot
        mutableStats.value = snapshot.toVpnStats()
    }

    /** Sets state without side effects; used by unit tests. */
    internal fun setStateForTest(newState: VpnState) {
        mutableState.value = newState
    }

    private fun NativeStats.toVpnStats(): VpnStats = VpnStats(
        dnsQueries = dnsQueries,
        dnsBlocked = dnsBlocked,
        dnsErrors = dnsErrors,
        dnsCached = dnsCached,
        upstreamLatencyMsP50 = upstreamLatencyMsP50,
        cacheEntries = cacheEntries,
        rulesBlock = rulesBlock,
        rulesUnsupported = rulesUnsupported,
        tcpActive = tcpActive,
        tcpTotal = tcpTotal,
        udpActive = udpActive,
        bytesUp = bytesUp,
        bytesDown = bytesDown,
        blockedConnections = blockedConnections,
        quicDropped = quicDropped,
        dnsHijacked = dnsHijacked,
        encryptedDnsDropped = encryptedDnsDropped,
        echStripped = echStripped,
        httpRequests = httpRequests,
        httpBlocked = httpBlocked,
        httpRedirected = httpRedirected,
        httpDegraded = httpDegraded,
        httpEngineLoaded = httpEngineLoaded,
        requestLogSize = requestLogSize,
        httpsFiltering = httpsFiltering,
        httpsIntercepted = httpsIntercepted,
        httpsPassthrough = httpsPassthrough,
        httpsAutoBypassed = httpsAutoBypassed,
        httpsUpstreamInvalid = httpsUpstreamInvalid,
        httpsHandshakeFailures = httpsHandshakeFailures,
        h2Streams = h2Streams,
        h2Blocked = h2Blocked,
        httpsBypassEntries = httpsBypassEntries,
    )

    /**
     * Maps [LinkProperties] to the UI's view of Private DNS.
     *
     * A standalone object cannot have a companion, so this is a member of the singleton — which is
     * also where the UI looks for it.
     */
    fun fromLinkProperties(properties: LinkProperties?): PrivateDnsStatus {
        if (properties == null) return PrivateDnsStatus.OFF
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return PrivateDnsStatus.OFF
        return PrivateDnsStatus(
            active = properties.isPrivateDnsActive,
            serverName = properties.privateDnsServerName,
        )
    }
}

/**
 * A [StateFlow] that counts active collectors, so [ZShieldVpnController] can honour the
 * "only poll while someone is watching" rule. `MutableStateFlow.subscriptionCount` is not part of
 * the stable API, which is why the count is kept here.
 */
internal class CountingStateFlow<T>(
    private val delegate: MutableStateFlow<T>,
    private val subscribers: AtomicInteger,
) : StateFlow<T> {
    override val value: T get() = delegate.value
    override val replayCache: List<T> get() = delegate.replayCache

    override suspend fun collect(collector: FlowCollector<T>): Nothing {
        subscribers.incrementAndGet()
        try {
            delegate.collect(collector)
        } finally {
            subscribers.decrementAndGet()
        }
    }
}
