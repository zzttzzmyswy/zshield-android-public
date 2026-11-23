package top.zztweb.zshield.ui

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.PowerManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.mutableStateOf
import top.zztweb.zshield.debug.DebugActivity
import top.zztweb.zshield.ui.theme.ZShieldTheme
import top.zztweb.zshield.vpn.VpnState
import top.zztweb.zshield.vpn.ZShieldVpnController

/**
 * The launcher entry and the only Activity of the real UI.
 *
 * It owns the two things a Composable cannot: the VPN consent round-trip and the screen-state hook
 * the stats poller uses to stay silent while the display is off (`docs/DESIGN.md` decision 10).
 */
class MainActivity : ComponentActivity() {

    /** Shown on the home screen when the user declines the system VPN dialog. */
    private val consentDenied = mutableStateOf(false)

    private val consentLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            consentDenied.value = false
            ZShieldVpnController.start(this)
        } else {
            consentDenied.value = true
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        val power = getSystemService(PowerManager::class.java)
        ZShieldVpnController.setScreenOnProvider { power?.isInteractive ?: true }
        TunnelClock.attach()

        setContent {
            ZShieldTheme {
                AppRoot(
                    actions = AppActions(
                        toggleProtection = ::toggleProtection,
                        startProtection = ::startProtection,
                        restartIfRunning = ::restartIfRunning,
                        openDiagnostics = {
                            startActivity(Intent(this, DebugActivity::class.java))
                        },
                    ),
                    consentDenied = consentDenied.value,
                )
            }
        }
    }

    private fun toggleProtection() {
        when (ZShieldVpnController.state.value) {
            VpnState.Running, VpnState.Starting -> ZShieldVpnController.stop(this)
            else -> {
                val consent = VpnService.prepare(this)
                if (consent == null) {
                    consentDenied.value = false
                    ZShieldVpnController.start(this)
                } else {
                    consentLauncher.launch(consent)
                }
            }
        }
    }

    /** Turn protection on if it is not already; the self-check page's "turn on" action. */
    private fun startProtection() {
        when (ZShieldVpnController.state.value) {
            VpnState.Running, VpnState.Starting -> Unit
            else -> toggleProtection()
        }
    }

    /**
     * Every tunnel setting is read when the interface is built, so a change only takes effect after
     * a rebuild; a stopped tunnel simply picks it up on its next start.
     */
    private fun restartIfRunning() {
        when (ZShieldVpnController.state.value) {
            VpnState.Running, VpnState.Starting -> ZShieldVpnController.restart(this)
            else -> Unit
        }
    }
}

/** Side effects the screens may trigger; implemented by [MainActivity]. */
data class AppActions(
    val toggleProtection: () -> Unit,
    val startProtection: () -> Unit,
    val restartIfRunning: () -> Unit,
    val openDiagnostics: () -> Unit,
)
