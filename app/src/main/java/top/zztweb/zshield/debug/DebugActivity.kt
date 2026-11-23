package top.zztweb.zshield.debug

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.PowerManager
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.annotation.MainThread
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import top.zztweb.zshield.R
import top.zztweb.zshield.filters.FilterRepository
import top.zztweb.zshield.https.CertManager
import top.zztweb.zshield.settings.AppSettings
import top.zztweb.zshield.settings.TunnelMode
import top.zztweb.zshield.vpn.VpnState
import top.zztweb.zshield.vpn.ZShieldVpnController
import java.util.Locale

/**
 * Temporary debug screen for M0.
 *
 * Scope is deliberately minimal (task card: "一个 Activity，只有开关按钮 + 状态文本 + 计数，不做任何
 * 样式"): one toggle button, one status line, one counters block. The real UI, including theming and
 * navigation, is implemented by the tech lead and will replace this file.
 *
 * The layout is built in code rather than XML so there is no resource to throw away later.
 */
class DebugActivity : Activity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    private lateinit var toggleButton: Button
    private lateinit var stateView: TextView
    private lateinit var statsView: TextView
    private lateinit var filtersView: TextView
    private lateinit var updateButton: Button
    private lateinit var addRuleButton: Button
    private lateinit var clearRulesButton: Button
    private lateinit var customRulesView: TextView
    private lateinit var modeButton: Button
    private lateinit var excludeButton: Button
    private lateinit var tunnelView: TextView
    private lateinit var httpView: TextView
    private lateinit var requestLogButton: Button
    private lateinit var httpsView: TextView
    /**
     * The CA's fingerprint, expiry and install state.
     *
     * A `TextView` of its own, not a second writer of [httpsView]: that view carries the HTTPS
     * *counters* ([R.string.https_stats_format]) and is rewritten on every stats tick, which used to
     * erase the CA line within a second of the tunnel starting. The two lines answer different
     * questions and both have to be readable at once — `docs/TESTING.md` §9.6 and the effectiveness
     * harness both read the install state off this screen.
     */
    private lateinit var httpsCertView: TextView
    private lateinit var httpsCertButton: Button
    private lateinit var httpsExportButton: Button
    private lateinit var httpsInstallButton: Button
    private lateinit var httpsToggleButton: Button
    private lateinit var httpsBypassButton: Button

    /** Set while a system consent dialog is in flight, so the result can continue the start. */
    private var awaitingConsent = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ZShieldVpnController.setScreenOnProvider {
            val power = getSystemService(PowerManager::class.java)
            power?.isInteractive ?: true
        }
        setContentView(buildLayout())
        FilterRepository.initialize(applicationContext)
        observeState()
        observeStats()
        observeMode()
        observeFilters()
        observeHttps()
    }

    private fun buildLayout(): ScrollView {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(48, 96, 48, 48)
        }
        toggleButton = Button(this).apply {
            text = getString(R.string.debug_toggle_start)
            setOnClickListener { onToggleClicked() }
        }
        stateView = TextView(this).apply {
            textSize = 16f
            setPadding(0, 32, 0, 16)
        }
        statsView = TextView(this).apply {
            textSize = 14f
            setPadding(0, 16, 0, 0)
        }
        filtersView = TextView(this).apply {
            textSize = 13f
            setPadding(0, 24, 0, 0)
        }
        updateButton = Button(this).apply {
            text = getString(R.string.debug_update_all)
            setOnClickListener { onUpdateAllClicked() }
        }
        // Two buttons that exercise the hot-reload path without a restart: the acceptance criterion
        // is "VPN 运行中修改用户规则后 ≤ 5 s 内生效，tun0 未重建", and there is no rule editor in the
        // UI yet (that is the tech lead's), so the debug screen is where it gets driven.
        addRuleButton = Button(this).apply {
            text = getString(R.string.debug_reload_add_rule)
            setOnClickListener { onSetUserRules("||reload-test.example^\n") }
        }
        clearRulesButton = Button(this).apply {
            text = getString(R.string.debug_reload_clear_rules)
            setOnClickListener { onSetUserRules("") }
        }
        customRulesView = TextView(this).apply {
            textSize = 13f
            setPadding(0, 16, 0, 0)
        }
        // M2a control surface: switch full <-> dns_only without a reinstall, and show the tunnel
        // counters the acceptance criteria are written against. Styling is the tech lead's; this is
        // the minimum that makes the switches reachable from adb or a tap.
        modeButton = Button(this).apply {
            setOnClickListener { onModeToggleClicked() }
        }
        tunnelView = TextView(this).apply {
            textSize = 13f
            setPadding(0, 16, 0, 0)
        }
        // M2b: the plaintext HTTP counters and the recent-request log. The real log page is the tech
        // lead's UI; this makes the acceptance criterion ("被拦截请求在日志中可见") reachable from a tap
        // and from adb before that exists.
        httpView = TextView(this).apply {
            textSize = 13f
            setPadding(0, 16, 0, 0)
        }
        requestLogButton = Button(this).apply {
            text = getString(R.string.debug_http_log_empty)
            setOnClickListener { refreshRequestLog() }
        }
        // Per-app exclusion is a settings field with no UI yet (the real UI is the tech lead's), so
        // the acceptance test "put the test browser in excludedApps and its traffic stops being
        // tunnelled" needs a way in. This toggles the browser the device test uses.
        excludeButton = Button(this).apply {
            setOnClickListener { onExcludeToggleClicked() }
        }
        // M3a: the certificate lifecycle and the HTTPS counters. The real HTTPS screen is the tech
        // lead's; this makes every acceptance step of the milestone reachable by tap (generate,
        // export, open the system installer, toggle decryption) without a rule editor existing yet.
        httpsView = TextView(this).apply {
            textSize = 13f
            setPadding(0, 24, 0, 0)
        }
        httpsCertView = TextView(this).apply {
            textSize = 13f
            setPadding(0, 24, 0, 0)
        }
        httpsCertButton = Button(this).apply {
            setOnClickListener { onGenerateCertClicked() }
        }
        httpsExportButton = Button(this).apply {
            text = getString(R.string.https_export)
            setOnClickListener { onExportCertClicked() }
        }
        httpsInstallButton = Button(this).apply {
            text = getString(R.string.https_open_settings)
            setOnClickListener { CertManager.openInstallSettings(this@DebugActivity) }
        }
        httpsToggleButton = Button(this).apply {
            setOnClickListener { onHttpsToggleClicked() }
        }
        httpsBypassButton = Button(this).apply {
            text = getString(R.string.https_bypass_empty)
            setOnClickListener { refreshBypassTable() }
        }
        // Long-press clears the table: the same action the UI needs after the user installs the CA,
        // and the one that makes "install then test" reproducible on a device.
        httpsBypassButton.setOnLongClickListener {
            CertManager.clearBypass(ZShieldVpnController.engineHandleForDebug)
            refreshBypassTable()
            true
        }
        root.addView(toggleButton)
        root.addView(stateView)
        root.addView(statsView)
        root.addView(tunnelView)
        root.addView(httpView)
        root.addView(httpsView)
        root.addView(httpsCertView)
        root.addView(httpsCertButton)
        root.addView(httpsExportButton)
        root.addView(httpsInstallButton)
        root.addView(httpsToggleButton)
        root.addView(httpsBypassButton)
        root.addView(requestLogButton)
        root.addView(modeButton)
        root.addView(excludeButton)
        root.addView(filtersView)
        root.addView(updateButton)
        root.addView(addRuleButton)
        root.addView(clearRulesButton)
        root.addView(customRulesView)
        return ScrollView(this).apply { addView(root) }
    }

    private fun observeState() {
        scope.launch {
            ZShieldVpnController.state.collectLatest { state ->
                val running = state is VpnState.Running
                stateView.text = when (state) {
                    VpnState.Stopped -> getString(R.string.debug_state_stopped)
                    VpnState.Starting -> getString(R.string.debug_state_starting)
                    VpnState.Running -> getString(
                        R.string.debug_state_running,
                        if (ZShieldVpnController.activeMode == TunnelMode.FULL) "完整隧道" else "仅 DNS",
                    )
                    is VpnState.Error -> getString(
                        R.string.debug_state_error,
                        state.message,
                    )
                }
                toggleButton.text = getString(
                    if (running) {
                        R.string.debug_toggle_stop
                    } else {
                        R.string.debug_toggle_start
                    },
                )
                toggleButton.isEnabled = state !is VpnState.Starting
            }
        }
    }

    private fun observeStats() {
        scope.launch {
            ZShieldVpnController.stats.collectLatest { stats ->
                statsView.text = String.format(
                    Locale.US,
                    getString(R.string.debug_stats_format),
                    stats.dnsQueries,
                    stats.dnsBlocked,
                    stats.dnsErrors,
                    stats.dnsCached,
                    stats.upstreamLatencyMsP50,
                    stats.cacheEntries,
                    stats.rulesBlock,
                    stats.rulesUnsupported,
                )
                tunnelView.text = String.format(
                    Locale.US,
                    getString(R.string.debug_tunnel_format),
                    stats.tcpActive,
                    stats.tcpTotal,
                    stats.udpActive,
                    humanBytes(stats.bytesUp),
                    humanBytes(stats.bytesDown),
                    stats.blockedConnections,
                    stats.quicDropped,
                    stats.dnsHijacked,
                    stats.encryptedDnsDropped,
                    stats.echStripped,
                )
                httpsView.text = String.format(
                    Locale.US,
                    getString(R.string.https_stats_format),
                    stats.httpsIntercepted,
                    stats.httpsPassthrough,
                    stats.httpsAutoBypassed,
                    stats.httpsUpstreamInvalid,
                    stats.httpsHandshakeFailures,
                    stats.h2Streams,
                    stats.h2Blocked,
                    stats.httpsBypassEntries,
                )
                httpView.text = String.format(
                    Locale.US,
                    getString(R.string.debug_http_format),
                    stats.httpRequests,
                    stats.httpBlocked,
                    stats.httpRedirected,
                    stats.httpDegraded,
                    getString(
                        if (stats.httpEngineLoaded) {
                            R.string.debug_http_engine_loaded
                        } else {
                            R.string.debug_http_engine_missing
                        },
                    ),
                    stats.requestLogSize,
                )
            }
        }
    }

    /**
     * Renders the CA state and the HTTPS toggle.
     *
     * `installed` comes from [CertManager.refreshInstalled], which reads the system's user CA store:
     * Android has no callback for a certificate install, so the state is refreshed on resume and
     * whenever the toggle is tapped.
     */
    private fun observeHttps() {
        // Both flows matter: the certificate state decides the fingerprint/install lines, and the
        // settings flow decides the toggle's label. Watching only the certificate left the button
        // saying "关闭 HTTPS 过滤" after the user had just turned it off — the label is state, so it
        // has to follow the state that changed.
        scope.launch {
            combine(CertManager.state, AppSettings.state) { ca, settings -> ca to settings }
                .collectLatest { (state, settings) ->
                httpsCertView.text = when (state) {
                    CertManager.CaState.NotGenerated -> getString(R.string.https_state_none)
                    is CertManager.CaState.Ready -> getString(
                        R.string.https_state_format,
                        state.fingerprintSha256.take(8),
                        CertManager.expiryText(state.notAfterMs),
                        getString(
                            if (state.installed) {
                                R.string.https_installed_yes
                            } else {
                                R.string.https_installed_no
                            },
                        ),
                    )
                }
                httpsCertButton.text = getString(
                    if (state is CertManager.CaState.NotGenerated) {
                        R.string.https_generate
                    } else {
                        R.string.https_regenerate
                    },
                )
                httpsToggleButton.text = getString(
                    if (settings.httpsFiltering) {
                        R.string.https_toggle_off
                    } else {
                        R.string.https_toggle_on
                    },
                )
                // Exporting is only meaningful once there is a certificate.
                httpsExportButton.isEnabled = state is CertManager.CaState.Ready
            }
        }
    }

    private fun onGenerateCertClicked() {
        scope.launch {
            CertManager.generate()
                .onSuccess {
                    // A new certificate is never installed: tell the user where to go.
                    CertManager.openInstallSettings(this@DebugActivity)
                }
                .onFailure { error ->
                    toast(getString(R.string.https_error, error.message ?: "unknown"))
                }
        }
    }

    private fun onExportCertClicked() {
        scope.launch {
            CertManager.exportToDownloads()
                .onSuccess { uri -> toast(getString(R.string.https_exported, uri.toString())) }
                .onFailure { error ->
                    toast(getString(R.string.https_error, error.message ?: "unknown"))
                }
        }
    }

    /**
     * Turns HTTPS filtering on or off and rebuilds the tunnel.
     *
     * A rebuild (not a hot reload) because enabling it decides the TUN routes' peer set and the uid
     * selection at `start`; the policy can be hot-updated later, but the first enable has to go
     * through `establish`. Turning it on without an installed certificate is allowed and simply does
     * not decrypt — the service logs why, which is more useful than a button that refuses to move.
     */
    private fun onHttpsToggleClicked() {
        val enabled = !AppSettings.current.httpsFiltering
        if (enabled) {
            CertManager.refreshInstalled()
            val installed = (CertManager.current as? CertManager.CaState.Ready)?.installed == true
            if (!installed) {
                toast(getString(R.string.https_install_hint))
            }
        }
        AppSettings.setHttpsFiltering(enabled)
        if (ZShieldVpnController.state.value is VpnState.Running) {
            ZShieldVpnController.restart(this)
        }
    }

    /** Pulls the auto-bypass table, newest last, and shows the first few entries. */
    private fun refreshBypassTable() {
        val entries = ZShieldVpnController.httpsBypass()
        httpsBypassButton.text = if (entries.isEmpty()) {
            getString(R.string.https_bypass_empty)
        } else {
            getString(
                R.string.https_bypass_format,
                entries.take(BYPASS_PREVIEW).joinToString("\n") { entry ->
                    String.format(
                        Locale.US,
                        "%d ｜ %s ｜ %s",
                        entry.uid,
                        entry.host,
                        entry.reason,
                    )
                },
            )
        }
    }

    private fun toast(message: String) {
        android.widget.Toast.makeText(this, message, android.widget.Toast.LENGTH_LONG).show()
    }

    /** The install state seen on the previous resume, so a change can be detected. */
    private var lastInstalled: Boolean? = null

    override fun onResume() {
        super.onResume()
        // The user may have just installed the certificate in the system settings.
        val before = (CertManager.current as? CertManager.CaState.Ready)?.installed
        CertManager.refreshInstalled()
        val after = (CertManager.current as? CertManager.CaState.Ready)?.installed
        if (after == true && before != true) {
            // Every pair that failed while the certificate was missing is in the auto-bypass table
            // and would stay passed through for 24 h; drop the table so the install takes effect.
            CertManager.clearBypass(ZShieldVpnController.engineHandleForDebug)
        }
        lastInstalled = after
    }

    /**
     * Pulls the recent-request log from the core.
     *
     * Pull rather than push, so nothing is serialized until someone asks (`docs/DESIGN.md`
     * decision 10). Sorted newest first here because a person reads the top of a list.
     */
    private fun refreshRequestLog() {
        val entries = ZShieldVpnController.recentRequests().takeLast(LOG_PREVIEW)
        requestLogButton.text = if (entries.isEmpty()) {
            getString(R.string.debug_http_log_empty)
        } else {
            getString(
                R.string.debug_http_log_format,
                entries.asReversed().joinToString("\n") { entry ->
                    String.format(
                        Locale.US,
                        "%s %s %s [%s]%s",
                        entry.outcome.wireName,
                        entry.method,
                        entry.host,
                        entry.kind,
                        entry.rule?.let { " $it" } ?: "",
                    )
                },
            )
        }
    }

    /** Shows the persisted mode and flips it, restarting the tunnel so the route table follows. */
    private fun observeMode() {
        AppSettings.initialize(applicationContext)
        scope.launch {
            AppSettings.state.collectLatest { data ->
                modeButton.text = getString(
                    if (data.mode == TunnelMode.FULL) {
                        R.string.debug_mode_switch_to_dns_only
                    } else {
                        R.string.debug_mode_switch_to_full
                    },
                )
                modeButton.isEnabled = ZShieldVpnController.state.value !is VpnState.Starting
            }
        }
        scope.launch {
            AppSettings.state.collectLatest { data ->
                val excluded = TEST_BROWSER_PACKAGE in data.excludedApps
                excludeButton.text = getString(
                    if (excluded) {
                        R.string.debug_exclude_browser_off
                    } else {
                        R.string.debug_exclude_browser_on
                    },
                )
            }
        }
        scope.launch {
            ZShieldVpnController.privateDns.collectLatest { status ->
                if (status.isStrict) {
                    customRulesView.text = getString(
                        R.string.debug_private_dns_warning,
                        status.serverName ?: "",
                    )
                }
            }
        }
    }

    /** Adds or removes the test browser from `excludedApps`, rebuilding the tunnel either way. */
    private fun onExcludeToggleClicked() {
        val current = AppSettings.current.excludedApps
        val next = if (TEST_BROWSER_PACKAGE in current) {
            current - TEST_BROWSER_PACKAGE
        } else {
            current + TEST_BROWSER_PACKAGE
        }
        AppSettings.setExcludedApps(next)
        ZShieldVpnController.restart(this)
    }

    private fun onModeToggleClicked() {
        val next = if (AppSettings.current.mode == TunnelMode.FULL) {
            TunnelMode.DNS_ONLY
        } else {
            TunnelMode.FULL
        }
        AppSettings.setMode(next)
        // The routes are decided when the interface is created, so a live tunnel has to be rebuilt.
        ZShieldVpnController.restart(this)
    }

    /**
     * M1 debug surface (task card §5): list count, rule count, compile time, and a "update all"
     * button. Deliberately unstyled — the real filter UI is the tech lead's.
     */
    private fun observeFilters() {
        scope.launch {
            combine(
                FilterRepository.lists,
                FilterRepository.compileState,
            ) { lists, compile -> lists to compile }
                .collectLatest { (lists, compile) ->
                    filtersView.text = describeFilters(lists, compile)
                }
        }
    }

    private fun describeFilters(
        lists: List<top.zztweb.zshield.filters.FilterListState>,
        compile: top.zztweb.zshield.filters.CompileState,
    ): String {
        if (lists.isEmpty()) return getString(R.string.debug_filters_idle)
        val enabled = lists.count { it.enabled }
        val ruleCount = lists.sumOf { it.ruleCount }
        val unsupported = lists.sumOf { it.unsupportedCount }
        val stats = (compile as? top.zztweb.zshield.filters.CompileState.Done)?.stats
        val body = if (stats == null) {
            getString(R.string.debug_filters_idle)
        } else {
            String.format(
                Locale.US,
                getString(R.string.debug_filters_format),
                lists.size,
                enabled,
                stats.dnsBlockRules,
                stats.dnsExceptionRules,
                stats.unsupported,
                stats.elapsedMs,
                humanBytes(stats.dnsBytes),
                humanBytes(stats.engineBytes),
                stats.networkOnly,
            )
        }
        val compileLine = when (compile) {
            top.zztweb.zshield.filters.CompileState.Running -> getString(R.string.debug_compile_running)
            is top.zztweb.zshield.filters.CompileState.Failed ->
                getString(R.string.debug_compile_failed, compile.message)
            else -> ""
        }
        val failed = lists.mapNotNull { list -> list.error?.let { "${list.name}: $it" } }
        return buildString {
            append(body)
            if (compileLine.isNotEmpty()) append('\n').append(compileLine)
            append("\n规则合计 ").append(ruleCount).append(" ｜ 不支持 ").append(unsupported)
            failed.forEach { append('\n').append(it) }
        }
    }

    private fun humanBytes(bytes: Long): String = when {
        bytes >= 1024 * 1024 -> String.format(Locale.US, "%.1f MB", bytes / 1048576.0)
        bytes >= 1024 -> String.format(Locale.US, "%.0f KB", bytes / 1024.0)
        else -> "$bytes B"
    }

    private fun onSetUserRules(rules: String) {
        scope.launch {
            FilterRepository.setUserRules(rules)
            customRulesView.text = getString(
                R.string.debug_custom_rules_format,
                FilterRepository.userRules.value.ifBlank { "（空）" },
            )
        }
    }

    private fun onUpdateAllClicked() {
        updateButton.isEnabled = false
        updateButton.text = getString(R.string.debug_updating)
        scope.launch {
            try {
                FilterRepository.updateAll(force = true)
            } finally {
                updateButton.isEnabled = true
                updateButton.text = getString(R.string.debug_update_all)
            }
        }
    }

    @MainThread
    private fun onToggleClicked() {
        when (ZShieldVpnController.state.value) {
            VpnState.Running, VpnState.Starting -> ZShieldVpnController.stop(this)
            else -> requestStart()
        }
    }

    /** Runs the system consent dialog first; `start` assumes consent is already granted. */
    private fun requestStart() {
        val consent = VpnService.prepare(this)
        if (consent == null) {
            ZShieldVpnController.start(this)
            return
        }
        awaitingConsent = true
        startActivityForResult(consent, REQUEST_VPN_CONSENT)
    }

    @Deprecated("VpnService.prepare returns a plain Intent with no result contract")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode != REQUEST_VPN_CONSENT) {
            super.onActivityResult(requestCode, resultCode, data)
            return
        }
        awaitingConsent = false
        if (resultCode == RESULT_OK) {
            ZShieldVpnController.start(this)
        } else {
            stateView.text = getString(R.string.debug_state_error, "用户拒绝 VPN 授权")
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private companion object {
        const val REQUEST_VPN_CONSENT = 1001

        /** The browser `docs/TESTING.md` names for real-device verification. */
        const val TEST_BROWSER_PACKAGE = "org.mozilla.firefox"

        /** How many recent requests the debug surface lists. */
        const val LOG_PREVIEW = 10

        /** How many auto-bypass entries the debug button shows. */
        const val BYPASS_PREVIEW = 8
    }
}
