package top.zztweb.zshield.filters

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Debug-only hook for driving the filter system from `adb` and from integration tests.
 *
 * ```
 * adb shell am broadcast -a top.zztweb.zshield.action.DEBUG_SET_RULES \
 *     -n top.zztweb.zshield/.filters.DebugCommandReceiver \
 *     --es rules '||example.org^'
 * ```
 *
 * Exists because the hot-reload acceptance criterion ("change a user rule while the tunnel runs and
 * see it take effect within 5 s") has to be reproducible without tapping a screen, and because the
 * real rule editor is the tech lead's work — this receiver is the seam to exercise the same code
 * path ([FilterRepository.setUserRules] → debounced compile → `Native.reload`).
 */
class DebugCommandReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val pending = goAsync()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        scope.launch {
            try {
                FilterRepository.initialize(context.applicationContext)
                when (intent.action) {
                    ACTION_SET_RULES -> {
                        val rules = intent.getStringExtra(EXTRA_RULES) ?: return@launch
                        FilterRepository.setUserRules(rules)
                    }
                    ACTION_SET_ALLOWLIST -> {
                        // Comma-separated so one `am broadcast` can express a small list without a
                        // second argument type.
                        val raw = intent.getStringExtra(EXTRA_DOMAINS).orEmpty()
                        FilterRepository.setAllowlist(raw.split(','))
                    }
                    ACTION_COMPILE -> FilterRepository.reloadNow()
                    ACTION_HTTPS_UIDS -> {
                        // M3a device test hook: put an arbitrary uid into (or out of) the decrypted
                        // set without a rule editor existing yet. The task card's own acceptance
                        // step is "temporarily add the shell uid to the list and use curl", which is
                        // exactly this. The core hot-reloads the policy, so the running tunnel is
                        // unaffected otherwise.
                        val raw = intent.getStringExtra(EXTRA_UIDS).orEmpty()
                        val uids = raw.split(',')
                            .mapNotNull { it.trim().toIntOrNull() }
                        val handle = top.zztweb.zshield.vpn.ZShieldVpnController.engineHandleForDebug
                        if (handle == 0L) {
                            android.util.Log.w("ZShield", "https uids: no tunnel is running")
                        } else {
                            // `excludedHosts` is deliberately omitted: absent means "keep the
                            // built-in banking/pinning list", and a debug uid change must not wipe it.
                            val payload = org.json.JSONObject()
                                .put("enabled", true)
                                .put("uids", org.json.JSONArray(uids))
                            val ok = top.zztweb.zshield.core.Native.updateHttpsPolicy(
                                handle,
                                payload.toString(),
                            )
                            android.util.Log.i(
                                "ZShield",
                                "https uids -> $uids: " +
                                    (if (ok) "applied" else top.zztweb.zshield.core.Native.lastError().orEmpty()),
                            )
                        }
                    }
                    ACTION_CLEAR_BYPASS -> {
                        val handle = top.zztweb.zshield.vpn.ZShieldVpnController.engineHandleForDebug
                        top.zztweb.zshield.https.CertManager.clearBypass(handle)
                    }
                    ACTION_TOGGLE_VPN -> {
                        // Goes through the *same* entry point as the notification and the UI, not
                        // straight to the service. That matters for two reasons, both of which made
                        // the broadcast look like it "sometimes did nothing" on a fresh install
                        // (MYS-2716 §6):
                        //
                        // 1. `startForegroundService` from a broadcast receiver is only allowed when
                        //    the app holds the `ACTIVATE_VPN` app-op, i.e. after the user has granted
                        //    the VPN consent dialog at least once. Before that the platform throws
                        //    `ForegroundServiceStartNotAllowedException`, which the old code let
                        //    escape from a coroutine and killed the process — the tunnel never came
                        //    up and nothing explained why.
                        // 2. `VpnService.prepare` has to be consulted, or the service starts on an
                        //    interface `establish()` refuses, which reports a permission error far
                        //    from the command that caused it.
                        //
                        // `ZShieldVpnController.start` does both and reports the failure as
                        // `VpnState.Error` instead of throwing.
                        val controller = top.zztweb.zshield.vpn.ZShieldVpnController
                        when (controller.state.value) {
                            is top.zztweb.zshield.vpn.VpnState.Running,
                            is top.zztweb.zshield.vpn.VpnState.Starting ->
                                controller.stop(context.applicationContext)
                            else -> controller.start(context.applicationContext)
                        }
                        // Logged so `adb logcat` answers "did my broadcast do anything, and if not
                        // why" without opening the app: the controller reports a missing VPN consent
                        // as `VpnState.Error` and there is no other visible surface for it.
                        android.util.Log.i(
                            "ZShield",
                            "debug toggle -> ${controller.state.value}",
                        )
                    }
                    else -> Unit
                }
            } finally {
                pending.finish()
            }
        }
    }

    companion object {
        const val ACTION_SET_RULES = "top.zztweb.zshield.action.DEBUG_SET_RULES"
        const val ACTION_SET_ALLOWLIST = "top.zztweb.zshield.action.DEBUG_SET_ALLOWLIST"
        const val ACTION_COMPILE = "top.zztweb.zshield.action.DEBUG_COMPILE"
        const val ACTION_TOGGLE_VPN = "top.zztweb.zshield.action.DEBUG_TOGGLE_VPN"
        const val EXTRA_RULES = "rules"
        const val EXTRA_DOMAINS = "domains"
        const val ACTION_HTTPS_UIDS = "top.zztweb.zshield.action.DEBUG_HTTPS_UIDS"
        const val ACTION_CLEAR_BYPASS = "top.zztweb.zshield.action.DEBUG_CLEAR_BYPASS"
        const val EXTRA_UIDS = "uids"
    }
}
