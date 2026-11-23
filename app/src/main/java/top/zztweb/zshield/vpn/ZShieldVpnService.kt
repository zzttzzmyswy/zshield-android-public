package top.zztweb.zshield.vpn

import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import top.zztweb.zshield.R
import top.zztweb.zshield.core.Native
import top.zztweb.zshield.core.NativeConfig
import top.zztweb.zshield.filters.FilterRepository
import top.zztweb.zshield.health.ProtectionHealth
import top.zztweb.zshield.https.CertManager
import top.zztweb.zshield.https.HttpsApps
import top.zztweb.zshield.settings.AppSettings
import top.zztweb.zshield.settings.AppSettingsData
import top.zztweb.zshield.settings.TunnelMode
import top.zztweb.zshield.ui.MainActivity
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The VpnService that owns the TUN device and the native engine.
 *
 * Two modes (`docs/DESIGN.md` fixed decision 4):
 * - **full** (default): `0.0.0.0/0` and `::/0` are routed into the tunnel, so every IPv4/IPv6
 *   connection goes through the userspace stack. That is what enables SNI/Host blocking, QUIC
 *   dropping and any-address DNS hijacking.
 * - **dns_only**: only the two virtual DNS addresses are routed — the M0/M1 behaviour, kept as the
 *   battery-friendly compatibility mode.
 *
 * **IPv6 is conditional** (MYS-2710): the `::/0` route, the TUN IPv6 address and the IPv6 DNS
 * server are only installed when the network underneath the tunnel actually has IPv6 (a global
 * unicast address and an IPv6 default route). Advertising IPv6 over a link that cannot carry it
 * makes dual-stack sites unreachable, because a client that connects over IPv6 is not required to
 * retry over IPv4 — see [Ipv6Availability]. [UnderlyingNetworkMonitor] rebuilds the interface when
 * availability changes.
 *
 * The app excludes itself (`addDisallowedApplication`), so the core's own upstream sockets never
 * re-enter the tunnel; that is what replaces a `protect()` callback. Additional packages the user
 * excluded are added the same way.
 */
class ZShieldVpnService : VpnService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var engineHandle: Long = 0L
    private val stopping = AtomicBoolean(false)

    /**
     * Watches the underlying network; created on the first tunnel start and stopped with the
     * service.
     *
     * A restart it schedules goes through [ZShieldVpnController.restart], which delivers
     * `ACTION_RESTART` to this service: rebuilding the interface from the monitor's coroutine
     * instead would race a UI-driven restart, and two concurrent `establish` calls would fight
     * over the same interface.
     */
    private val networkMonitor: UnderlyingNetworkMonitor by lazy {
        UnderlyingNetworkMonitor(
            scope = scope,
            restart = { ZShieldVpnController.restart(this) },
            applyUnderlying = { networks -> setUnderlyingNetworks(networks) },
        )
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
        Native.init(applicationContext)
        // Reading the settings here (not in the Activity) means a restart requested by the UI and a
        // system-initiated start both use the same persisted values.
        AppSettings.initialize(applicationContext)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel()
                return START_NOT_STICKY
            }
            // The notification's pause button. It comes straight here rather than through the
            // controller, so this is the one place where the service itself writes the user's
            // intent — it *is* a user action (the task card's "通知按钮"), and without the write a
            // pause from the notification would be undone by the next recovery check.
            ACTION_PAUSE -> {
                Log.i(LOG_TAG, "pause requested from the notification")
                recordIntent(wanted = false)
                stopTunnel()
                return START_NOT_STICKY
            }
            // Debug surface for the real-device performance runs in docs/TESTING.md: switching the
            // tunnel on and off by screen coordinates is fragile, and the throughput comparison needs
            // both states back to back.
            //
            // It records the persisted intent exactly like the UI switch does, because the device
            // tests use it *as* the user's toggle: the "user turned it off, then rebooted" scenario
            // asserts that nothing comes back, and a debug stop that left the intent on would make
            // that assertion test the wrong thing.
            ACTION_DEBUG_TOGGLE -> {
                if (engineHandle != 0L) {
                    recordIntent(wanted = false)
                    stopTunnel()
                    return START_NOT_STICKY
                }
                recordIntent(wanted = true)
                startTunnel()
            }
            // A settings change rebuilds the interface: the mode and the excluded-app list are
            // decided when `establish` runs, so there is no way to apply them to a live tunnel.
            ACTION_RESTART -> {
                tearDown(keepServiceAlive = true)
                stopping.set(false)
                startTunnel()
            }
            else -> {
                // A null intent is the platform re-creating the service after the process was
                // killed (`START_STICKY`), and that is recovery, not a user action: it must respect
                // the same intent/consent/always-on rules as every other recovery path, so a user
                // who paused protection does not get it back from a kill. The decision is taken here
                // rather than by calling `ProtectionRecovery.recover`, which would ask the
                // controller to start this very service again.
                if (intent == null) {
                    val outcome = ProtectionRecovery.decide(this, RecoveryTrigger.SERVICE_RESTART)
                    if (outcome == RecoveryOutcome.RECOVER) {
                        Log.i(LOG_TAG, "sticky restart: re-establishing the tunnel")
                        startTunnel()
                    } else {
                        Log.i(LOG_TAG, "sticky restart: not recovering ($outcome)")
                        // Nothing to do and no reason to hold a foreground service: a sticky start
                        // that decides against filtering must leave the process as it found it.
                        stopSelf()
                        return START_NOT_STICKY
                    }
                } else {
                    startTunnel()
                }
            }
        }
        // `START_STICKY` (M4a, docs/DESIGN.md §7 scenario 3): the point of this service is that
        // filtering outlives the process. A process the platform kills for memory is restarted with
        // a null intent, which the branch above decides on. A user-initiated stop must not be
        // resurrected, and it is not: the stop paths return `START_NOT_STICKY`, and even if the
        // platform restarted anyway, `protectionWanted` is false by then.
        return START_STICKY
    }

    /** Builds the TUN interface, starts the native engine and enters the foreground. */
    private fun startTunnel() {
        // A start while a tunnel is already up must rebuild cleanly rather than leak an interface.
        if (engineHandle != 0L) {
            tearDown(keepServiceAlive = true)
            stopping.set(false)
        }
        ZShieldVpnController.onStateChanged(VpnState.Starting)
        // Foreground first: A16 kills a VPN service that is not foregrounded promptly.
        startForegroundWithNotification()

        val settings = AppSettings.current
        // Read before `establish`: the interface's address family set is fixed at that point.
        val ipv6Available = networkMonitor.currentIpv6Available(this)
        Log.i(
            LOG_TAG,
            "underlying network IPv6: $ipv6Available (tunnel " +
                (if (ipv6Available) "carries" else "does not carry") + " IPv6)",
        )
        val descriptor = try {
            establish(settings, ipv6Available)
        } catch (error: Exception) {
            ZShieldVpnController.onError("无法建立 VPN 接口：${error.message}")
            stopSelf()
            return
        }
        if (descriptor == null) {
            // `establish` returns null when the VPN consent was revoked while starting, or when a
            // disallowed package does not exist (see `establish`).
            ZShieldVpnController.onError("VPN 授权无效，请重新授权")
            stopSelf()
            return
        }

        // The compiled artifacts are the fast path (docs/DESIGN.md decision 6): the core
        // deserializes `dns.bin` instead of parsing megabytes of list text on every start. The plain
        // rule files stay in the config as the documented fallback — the core falls back by itself
        // and reports why through lastError.
        FilterRepository.initialize(applicationContext)
        val compiledDir = FilterRepository.compiledDir
        val ruleFiles = RuleStorage.prepareRuleFiles(this)
        val encryptedDnsHosts = RuleStorage.prepareEncryptedDnsHosts(this)

        // HTTPS filtering (M3a). Three things have to agree before the core will decrypt: the user
        // wants it, the CA is installed in the system store, and the stored key is readable. The
        // first is a setting, the second is what Android will actually accept, and the third decides
        // whether `loadCa` can succeed. Any of them failing means the tunnel runs without
        // decryption, which still filters plaintext and hostnames — never a reason to refuse to
        // start.
        CertManager.initialize(applicationContext)
        CertManager.refreshInstalled()
        val caInstalled = (CertManager.current as? CertManager.CaState.Ready)?.installed == true
        val httpsFiltering = settings.httpsFiltering && caInstalled && CertManager.apply()
        if (settings.httpsFiltering && !caInstalled) {
            Log.i(LOG_TAG, "HTTPS filtering requested but the CA is not installed; not decrypting")
        }
        val httpsUids = if (httpsFiltering) {
            HttpsApps.selectedUids(applicationContext, settings.httpsUserApps)
        } else {
            emptyList()
        }
        val httpsExcludedHosts = RuleStorage.prepareHttpsExcludedHosts(this)
        val config = NativeConfig(
            ruleFiles = ruleFiles,
            compiledDir = compiledDir,
            mode = settings.mode,
            mtu = MTU,
            blockQuic = settings.blockQuic,
            blockEncryptedDnsBypass = settings.blockEncryptedDnsBypass,
            encryptedDnsHostsFile = encryptedDnsHosts,
            ipv6 = ipv6Available,
            httpsFiltering = httpsFiltering,
            httpsUids = httpsUids,
            httpsExcludedHosts = settings.httpsExcludedHosts,
            httpsExcludedHostsFile = httpsExcludedHosts,
        )
        val fd = descriptor.detachFd()
        // From here the core owns the fd; closing `descriptor` would close the tunnel.

        val handle = Native.start(fd, config.toJson())
        if (handle == 0L) {
            val reason = Native.lastError()?.ifBlank { null } ?: "未知错误"
            ZShieldVpnController.onError("启动过滤核心失败：$reason")
            stopSelf()
            return
        }
        engineHandle = handle
        Log.i(
            LOG_TAG,
            "https filtering: $httpsFiltering (ca installed $caInstalled, ${httpsUids.size} uids, " +
                "user hosts ${settings.httpsExcludedHosts.size})",
        )
        // The interface now carries exactly this IPv6 setting; a restart scheduled for a link
        // change the old tunnel did not reflect is obsolete.
        networkMonitor.onTunnelEstablished(ipv6Available)
        networkMonitor.start(this)
        networkMonitor.applyUnderlyingNetworks()
        // From now on a finished compile hot-swaps this tunnel's rules instead of restarting it.
        FilterRepository.attachTunnel(handle)
        ZShieldVpnController.onEngineStarted(handle)
        ZShieldVpnController.onStateChanged(VpnState.Running)
        ZShieldVpnController.onTunnelStarted(settings.mode)
        ZShieldVpnController.startPrivateDnsMonitoring(this)
        // The tunnel is up with whatever consent it had; the health snapshot decides the rest of the
        // checklist (always-on, battery optimisation, ...), so re-read it now rather than when the
        // user next opens the app.
        refreshHealth()
        // Refresh the count shown in the notification: the previous run's number must not survive a
        // restart, and the first notification was built before the engine existed. The observer keeps
        // it current afterwards, and it only ever fires on a stats poll that the controller had
        // already decided to make (screen on, someone collecting), so it adds no wakeup of its own.
        ZShieldVpnController.setStatsObserver { updateNotification() }
        updateNotification()
    }

    /**
     * Builds the tunnel for [settings], applying the mode's routes and the excluded packages.
     *
     * [ipv6Available] comes from [UnderlyingNetworkMonitor]: the IPv6 address, the IPv6 DNS server
     * and (in full mode) the `::/0` route are only installed when the link below really carries
     * IPv6. See the class comment for why advertising it otherwise breaks dual-stack sites.
     */
    private fun establish(settings: AppSettingsData, ipv6Available: Boolean): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(MTU)
            .addAddress(TUN_V4, TUN_V4_PREFIX)
            .addDnsServer(DNS_V4)
            // The core's own upstream sockets must not re-enter the tunnel. Excluding our package
            // is what replaces the `protect()` callback described in the design.
            .addDisallowedApplication(packageName)
            .setBlocking(true)

        if (ipv6Available) {
            builder.addAddress(TUN_V6, TUN_V6_PREFIX)
            builder.addDnsServer(DNS_V6)
        }

        when (settings.mode) {
            TunnelMode.FULL -> {
                // Everything goes through the userspace stack.
                builder.addRoute("0.0.0.0", 0)
                if (ipv6Available) {
                    builder.addRoute("::", 0)
                }
            }
            TunnelMode.DNS_ONLY -> {
                // Only the virtual DNS addresses are routed into the tunnel (M0/M1 behaviour).
                builder.addRoute(DNS_V4, 32)
                if (ipv6Available) {
                    builder.addRoute(DNS_V6, 128)
                }
            }
        }

        for (excluded in settings.excludedApps) {
            try {
                builder.addDisallowedApplication(excluded)
            } catch (error: PackageManager.NameNotFoundException) {
                // An uninstalled or misspelled package must not take the tunnel down: log it and
                // carry on with the rest of the list (task card §2).
                android.util.Log.w("ZShield", "excluded app not installed: $excluded", error)
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }
        return builder.establish()
    }

    /** Stops the tunnel and the service. */
    private fun stopTunnel() = tearDown(keepServiceAlive = false)

    /**
     * Removes the TUN interface and stops the native engine.
     *
     * `keepServiceAlive` leaves the foreground service running so a restart can immediately establish
     * a new interface; without it the service stops itself, which is what a user-initiated stop wants.
     */
    private fun tearDown(keepServiceAlive: Boolean) {
        if (!stopping.compareAndSet(false, true)) return
        ZShieldVpnController.stopPrivateDnsMonitoring(this)
        // The notification is what the observer updates; leaving it registered after the tunnel is
        // gone would keep a re-post path alive with nothing to re-post.
        ZShieldVpnController.setStatsObserver(null)
        // Stop watching the underlying network only when the service is really going away: a
        // restart re-establishes the interface a moment later and reusing the live tracking keeps
        // the platform callback count at one per tunnel lifetime instead of one per rebuild.
        if (!keepServiceAlive) {
            networkMonitor.stop()
        }
        // Tell the controller first: it owns the stats poller, which must not query a handle that
        // is about to be destroyed (that would zero the visible counters).
        ZShieldVpnController.onEngineStopping()
        // Detach before the handle dies: a compile finishing during teardown must not try to reload
        // a tunnel that is going away.
        FilterRepository.detachTunnel()
        if (engineHandle != 0L) {
            Native.stop(engineHandle)
            engineHandle = 0L
        }
        // The restart path re-enters the foreground immediately, so the notification is removed in
        // both cases rather than flashing "filtering" while nothing is filtered.
        stopForeground(STOP_FOREGROUND_REMOVE)
        ZShieldVpnController.onStateChanged(VpnState.Stopped)
        if (!keepServiceAlive) {
            stopSelf()
        }
    }

    /**
     * The VPN permission or the interface was taken away — most often another VPN app was preferred,
     * or the user revoked consent for this app.
     *
     * The persisted *intent* is deliberately left alone (M4a task card §1): the user still wants
     * protection, so the boot/upgrade/periodic recovery paths keep trying, and the next user tap on
     * "turn on" goes straight to the consent dialog. What is recorded separately is
     * `revokedBySystem`, which is what the self-check page shows so the user knows why nothing is
     * filtered.
     *
     * `ZShieldVpnService` is the only component the platform tells about a revocation, so this is
     * where it becomes visible to the rest of the app.
     */
    override fun onRevoke() {
        Log.i(LOG_TAG, "VPN revoked by the system")
        runCatching {
            AppSettings.initialize(applicationContext)
            AppSettings.setRevokedBySystem(true)
        }.onFailure { Log.w(LOG_TAG, "cannot record the revocation", it) }
        // Tear down immediately and tell the UI, so it does not claim to be filtering.
        stopTunnel()
        refreshHealth()
        super.onRevoke()
    }

    override fun onDestroy() {
        instance = null
        stopTunnel()
        scope.cancel()
        super.onDestroy()
    }

    /** Republishes the health snapshot; called wherever a health input can have changed. */
    private fun refreshHealth() {
        runCatching { ProtectionHealth.refresh(applicationContext) }
    }

    /**
     * Records the user's intent after a stop the service itself handled.
     *
     * The user-facing toggles normally go through [ZShieldVpnController.stop], which writes the intent
     * before sending the command. Two stop paths arrive here directly — the notification's pause
     * button and the debug toggle — and both are user actions, so they have to write it too: an
     * intent left on would be undone by the next recovery check, which is exactly the bug this
     * milestone exists to prevent.
     */
    private fun recordIntent(wanted: Boolean) {
        runCatching {
            AppSettings.initialize(applicationContext)
            if (AppSettings.current.protectionWanted != wanted) {
                AppSettings.setProtectionWanted(wanted)
            }
        }.onFailure { Log.w(LOG_TAG, "cannot persist protection intent", it) }
    }

    // ---------------------------------------------------------------------------------------
    // Foreground notification
    // ---------------------------------------------------------------------------------------

    private fun startForegroundWithNotification() {
        ensureChannel()
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    /**
     * Builds the persistent notification: "已拦截 N" plus a pause action (M4a task card §5).
     *
     * The count is read from the controller's *last published* snapshot, never pulled from the core
     * here: [ZShieldVpnController] only asks the core for stats while a screen is collecting them and
     * the display is on (`docs/DESIGN.md` decision 10), so a notification rebuild with the screen off
     * costs no JNI call and no wakeup. It shows the last number it had rather than forcing a fresh one.
     */
    private fun buildNotification(): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val pauseIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, ZShieldVpnService::class.java).setAction(ACTION_PAUSE),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val blocked = ZShieldVpnController.stats.value.blockedTotal
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(getString(R.string.notification_text_blocked, blocked))
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setOngoing(true)
            .setShowWhen(false)
            .setContentIntent(openIntent)
            .addAction(
                Notification.Action.Builder(
                    null,
                    getString(R.string.notification_action_pause),
                    pauseIntent,
                ).build(),
            )
            .build()
    }

    /** Re-posts the notification with the current counter, without touching the tunnel. */
    private fun updateNotification() {
        // Guarded on a live engine: a stats snapshot that arrives while the tunnel is being torn down
        // must not re-post the notification `tearDown` just removed, which would leave an "ongoing"
        // notification for a service that is gone.
        if (engineHandle == 0L) return
        runCatching {
            val manager = getSystemService(NotificationManager::class.java) ?: return
            manager.notify(NOTIFICATION_ID, buildNotification())
        }
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(NotificationManager::class.java) ?: return
        if (manager.getNotificationChannel(CHANNEL_ID) != null) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.notification_channel_description)
            setShowBadge(false)
        }
        manager.createNotificationChannel(channel)
    }

    companion object {
        private const val LOG_TAG = "ZShield"

        const val ACTION_START = "top.zztweb.zshield.action.START"
        const val ACTION_STOP = "top.zztweb.zshield.action.STOP"

        /**
         * The notification's pause button (M4a task card §5).
         *
         * A separate action from [ACTION_STOP] because it is the one stop that arrives at the service
         * without passing through the controller, so the service records the user's intent itself.
         */
        const val ACTION_PAUSE = "top.zztweb.zshield.action.PAUSE"

        /**
         * Rebuild the tunnel in place: the service tears the current interface down and establishes
         * a new one, re-reading `AppSettings`. One round trip through the service's command queue is
         * what makes the rebuild ordered, instead of the UI racing a stop against a start.
         */
        const val ACTION_RESTART = "top.zztweb.zshield.action.RESTART"

        /** Debug only: start the tunnel if stopped, stop it if running. */
        const val ACTION_DEBUG_TOGGLE = "top.zztweb.zshield.action.DEBUG_TOGGLE"

        /**
         * TUN addresses and the virtual DNS pair, fixed by `docs/DESIGN.md` §4.
         *
         * The IPv6 pair is only installed when the underlying network has IPv6 (MYS-2710).
         */
        const val TUN_V4 = "10.111.222.1"
        const val TUN_V4_PREFIX = 30
        const val DNS_V4 = "10.111.222.2"
        const val TUN_V6 = "fd00:7a73::1"
        const val TUN_V6_PREFIX = 126
        const val DNS_V6 = "fd00:7a73::2"

        /**
         * TUN MTU. 1500 matches the path MTU of essentially every mobile/Wi-Fi link; measurements on
         * the Pixel 5 show a larger MTU buys nothing (the radio is the bottleneck) and only adds
         * fragments, see `docs/PERF.md`.
         */
        const val MTU = NativeConfig.DEFAULT_MTU

        private const val CHANNEL_ID = "zshield_vpn"
        private const val NOTIFICATION_ID = 1001

        /** The running instance, so the controller can stop it. Main thread only. */
        @SuppressLint("StaticFieldLeak")
        @Volatile
        var instance: ZShieldVpnService? = null
            private set

        /** Asks the running service to stop; a no-op when it is not running. */
        internal fun requestStop(context: Context) {
            if (instance == null) {
                // Nothing running: make sure the controller does not keep showing "Running".
                ZShieldVpnController.onStateChanged(VpnState.Stopped)
                return
            }
            val intent = Intent(context, ZShieldVpnService::class.java).setAction(ACTION_STOP)
            runCatching { context.startService(intent) }
        }
    }
}
