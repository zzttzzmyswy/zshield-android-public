package top.zztweb.zshield.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import android.os.Looper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Watches the network *underneath* the tunnel and rebuilds the tunnel when IPv6 availability
 * changes.
 *
 * # Why the tunnel has to be rebuilt
 *
 * `VpnService.Builder` fixes the interface's addresses, routes and DNS servers when `establish`
 * runs; there is no way to add `::/0` to a live interface. A change in availability therefore has
 * to go through [ZShieldVpnController.restart] (the existing `ACTION_RESTART` path), which is also
 * what re-reads the settings.
 *
 * # Why it is debounced
 *
 * A link that is coming up reports several capability and link-property changes within a few
 * hundred milliseconds (addresses, then routes, then validation). Rebuilding on each of them would
 * tear the tunnel down repeatedly while the user's page is loading, so the decision is taken once
 * the link has been stable for [DEBOUNCE_MS].
 *
 * IPv6 availability itself is decided by [Ipv6Availability]; this class only turns "the value
 * changed" into one restart.
 */
class UnderlyingNetworkMonitor(
    private val scope: CoroutineScope,
    private val debounceMillis: Long = DEBOUNCE_MS,
    private val restart: () -> Unit,
    /**
     * Applies the tracked networks to `VpnService.setUnderlyingNetworks`; `null` means "let the
     * platform decide", which is what an empty set means.
     */
    private val applyUnderlying: (Array<Network>?) -> Unit = {},
) {

    /** The IPv6 setting the currently established tunnel was built with. */
    @Volatile
    private var tunnelIpv6: Boolean = true

    @Volatile
    private var pendingRestart: Job? = null

    private var manager: ConnectivityManager? = null
    private var callback: ConnectivityManager.NetworkCallback? = null

    /** Last value published by the platform, for a synchronous read at establish time. */
    @Volatile
    private var lastKnown: Boolean? = null

    /**
     * Networks the platform reports as carrying our traffic.
     *
     * Seeded from `ConnectivityManager` before the callback is registered (for the read at
     * `establish` time), then owned entirely by the callback: [refresh] drops the seed on the first
     * observation, so a network that vanished while the service was starting cannot pin the
     * answer.
     */
    private val trackedNetworks = LinkedHashMap<Network, LinkProperties>()

    /** True while [trackedNetworks] still holds the pre-registration seed. */
    private var seeded = false

    /**
     * Records the value the freshly established tunnel used, and drops any restart that was
     * scheduled against the previous tunnel.
     *
     * Called by the service right after `establish` so a restart in flight cannot rebuild the
     * interface a second time for a change the new tunnel already reflects.
     */
    fun onTunnelEstablished(ipv6: Boolean) {
        tunnelIpv6 = ipv6
        lastKnown = ipv6
        pendingRestart?.cancel()
        pendingRestart = null
    }

    /**
     * Feeds one availability observation in.
     *
     * A no-op when the live tunnel already matches, which is what keeps an ordinary link-property
     * change (a new DNS server, a changed MTU) from restarting the tunnel.
     *
     * @return true when a restart was scheduled, so tests can assert on it.
     */
    fun onAvailabilityChanged(available: Boolean): Boolean {
        lastKnown = available
        if (available == tunnelIpv6) {
            // The tunnel is already right for this link: cancel a restart scheduled by a previous
            // blip instead of rebuilding for a value the live interface already has.
            pendingRestart?.cancel()
            pendingRestart = null
            return false
        }
        if (pendingRestart?.isActive == true) return true
        pendingRestart = scope.launch {
            delay(debounceMillis)
            // Re-check after the quiet period: the link may have settled back to what the tunnel
            // already carries.
            if (lastKnown != null && lastKnown == tunnelIpv6) return@launch
            restart()
        }
        return true
    }

    /** Registers for underlying-network changes and publishes the first observation. */
    fun start(context: Context) {
        if (callback != null) return
        val manager = context.applicationContext
            .getSystemService(ConnectivityManager::class.java) ?: return
        this.manager = manager
        // NOT_VPN is what lets a VPN app see the networks underneath it at all; without it the
        // platform reports only our own VPN network back to us.
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                refresh(network, manager.getLinkProperties(network))
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                refresh(network, linkProperties)
            }

            override fun onCapabilitiesChanged(
                network: Network,
                capabilities: NetworkCapabilities,
            ) {
                refresh(network, manager.getLinkProperties(network))
            }

            override fun onLost(network: Network) {
                trackedNetworks.remove(network)
                publish()
            }

            override fun onUnavailable() {
                // API < 31 `registerNetworkCallback` reports this when no network matched at all;
                // availability then has no input, which [isAvailable] answers as false. The
                // service is rebuilt only if that differs from what the live tunnel carries.
                publish()
            }
        }
        val registered = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                // Only the network that would actually carry our traffic, which is the one whose
                // IPv6 reachability decides whether the tunnel may advertise IPv6.
                manager.registerBestMatchingNetworkCallback(request, callback, mainHandler())
            } else {
                // API 28–30 has no "best matching" variant. Every matching network is tracked and
                // availability requires all of them to have IPv6 (see `publish`), so a stale or
                // secondary IPv4-only link can never make the tunnel advertise IPv6 it cannot use.
                manager.registerNetworkCallback(request, callback)
            }
        }.isSuccess
        if (registered) {
            this.callback = callback
        }
        // Deliberately no `publish()` here: [trackedNetworks] only ever holds networks the platform
        // itself reported, and the tunnel was just built from `currentIpv6Available`, so the first
        // observation cannot disagree with it. Publishing an empty or seeded map instead would
        // schedule a pointless rebuild right after every start.
    }

    /** Releases the platform callback. Safe to call when [start] never ran. */
    fun stop() {
        val manager = this.manager ?: return
        val callback = this.callback ?: return
        this.callback = null
        trackedNetworks.clear()
        runCatching { manager.unregisterNetworkCallback(callback) }
    }

    /**
     * Points the VPN at the network(s) it actually runs on.
     *
     * `null` is the documented "let the platform decide" value and is what an empty tracking map
     * means; it must not be confused with "no network".
     */
    fun applyUnderlyingNetworks() {
        val networks = trackedNetworks.keys.toTypedArray()
        runCatching { applyUnderlying(networks.ifEmpty { null }) }
    }

    /**
     * The IPv6 availability the next tunnel should be built with.
     *
     * Before the first callback arrives this falls back to a synchronous look at the networks the
     * platform reports, so a tunnel established immediately after the service starts already has
     * the right shape instead of being rebuilt a second later. The seeded networks are kept, so the
     * `start` call that follows does not have to look them up again.
     */
    fun currentIpv6Available(context: Context): Boolean {
        lastKnown?.let { return it }
        val manager = context.applicationContext
            .getSystemService(ConnectivityManager::class.java) ?: return false
        seedTrackedNetworks(manager)
        return isAvailable(trackedNetworks.values.toList())
    }

    private fun refresh(network: Network, properties: LinkProperties?) {
        if (seeded) {
            // The platform is reporting now; its view replaces the seed wholesale.
            trackedNetworks.clear()
            seeded = false
        }
        if (properties == null) {
            trackedNetworks.remove(network)
        } else {
            trackedNetworks[network] = properties
        }
        applyUnderlyingNetworks()
        publish()
    }

    /** Fills [trackedNetworks] from the platform, so the first `publish` is not an empty map. */
    @Suppress("DEPRECATION")
    private fun seedTrackedNetworks(manager: ConnectivityManager) {
        // `allNetworks` is deprecated in favour of callback-based tracking, which is what this
        // class does from the second observation on; there is no synchronous replacement, and this
        // one call is what gives `establish` an answer before the first callback lands.
        manager.allNetworks
            .filter { network ->
                val capabilities = manager.getNetworkCapabilities(network) ?: return@filter false
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            }
            .forEach { network ->
                manager.getLinkProperties(network)?.let { trackedNetworks[network] = it }
            }
        seeded = trackedNetworks.isNotEmpty()
    }

    private fun publish() {
        onAvailabilityChanged(isAvailable(trackedNetworks.values.toList()))
    }

    /**
     * The main looper, which is where the platform delivers network callbacks by default.
     *
     * `registerBestMatchingNetworkCallback` requires an explicit handler, and passing the main one
     * keeps the callback thread identical to what `registerNetworkCallback` would have used.
     */
    private fun mainHandler(): Handler = Handler(Looper.getMainLooper())

    private companion object {

        /**
         * A link has to be stable this long before the tunnel is rebuilt. Long enough to swallow
         * the burst of changes that follows a Wi-Fi association, short enough that a user who just
         * switched networks does not notice.
         */
        const val DEBOUNCE_MS = 2_000L

        /**
         * Availability across the links that may carry our traffic.
         *
         * Every one of them must have IPv6: when the platform tracks several underlying networks
         * and only some have IPv6, an IPv6 destination can still be routed to a link that cannot
         * reach it, which is the same unreachable-connection failure this fix is about.
         */
        fun isAvailable(links: List<LinkProperties>): Boolean =
            links.isNotEmpty() && links.all { Ipv6Availability.fromLinkProperties(it) }
    }
}
