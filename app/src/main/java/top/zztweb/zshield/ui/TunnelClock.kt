package top.zztweb.zshield.ui

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import top.zztweb.zshield.vpn.VpnState
import top.zztweb.zshield.vpn.ZShieldVpnController

/**
 * Wall-clock time at which the current tunnel started, so request-log offsets (`atMs`, milliseconds
 * since tunnel start) can be shown as a time of day.
 *
 * Only known when this process saw the tunnel go from not-running to running. If the UI attaches
 * while a tunnel is already up, [startedAtMs] stays `null` and the log shows `+mm:ss` offsets
 * instead of guessing.
 */
object TunnelClock {
    @Volatile
    var startedAtMs: Long? = null
        private set

    private var attached = false

    fun attach() {
        synchronized(this) {
            if (attached) return
            attached = true
        }
        CoroutineScope(SupervisorJob() + Dispatchers.Default).launch {
            var wasRunning = ZShieldVpnController.state.value == VpnState.Running
            ZShieldVpnController.state.collect { state ->
                val running = state == VpnState.Running
                if (running && !wasRunning) startedAtMs = System.currentTimeMillis()
                if (!running && state != VpnState.Starting) startedAtMs = null
                wasRunning = running
            }
        }
    }
}
