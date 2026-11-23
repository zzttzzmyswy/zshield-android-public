package top.zztweb.zshield.vpn

import android.content.Context
import android.net.VpnService
import android.provider.Settings
import android.util.Log
import top.zztweb.zshield.health.ProtectionHealth
import top.zztweb.zshield.settings.AppSettings

/**
 * Brings the tunnel back after a kill, a reboot or an upgrade — the decision half of
 * `docs/DESIGN.md` §7, with the table itself in [RecoveryPolicy].
 *
 * Kept out of [ZShieldVpnService] on purpose: the service is started *by* recovery, so it cannot be
 * the only thing that decides whether recovery should happen. It is also the one place that reads the
 * persisted intent and the platform state together, which means every recovery trigger (boot
 * broadcast, upgrade broadcast, periodic job, sticky restart) gets the identical decision instead of
 * each implementing its own subset.
 */
object ProtectionRecovery {

    private const val LOG_TAG = "ZShield"

    /**
     * The always-on VPN setting, holding the package name of the selected VPN.
     *
     * This is a `Settings.Secure` key the platform does not document for third-party reads; the
     * Pixel 5 (A16) answers it, and a build that refuses throws, which this reports as `null`
     * ("unknown") rather than as "not always-on". `docs/KEEPALIVE.md` records the finding.
     */
    private const val SETTING_ALWAYS_ON_VPN_APP = "always_on_vpn_app"

    /**
     * Works out what this trigger should do, and starts filtering when the answer is
     * [RecoveryOutcome.RECOVER].
     *
     * Used by the boot/upgrade receiver and by the periodic job. Never throws: it runs from a
     * broadcast receiver and from a job, where an escaping exception would take the process down
     * with no user-visible reason.
     */
    fun recover(context: Context, trigger: RecoveryTrigger): RecoveryOutcome {
        val outcome = decide(context, trigger)
        if (outcome == RecoveryOutcome.RECOVER) {
            ZShieldVpnController.startForRecovery(context.applicationContext)
        }
        Log.i(
            LOG_TAG,
            "recovery trigger=$trigger outcome=$outcome (wanted=${protectionWanted(context)})",
        )
        // The health snapshot includes `vpnPermission` and `revokedBySystem`, both of which a
        // recovery attempt can change; refresh so a self-check page opened right after a boot does
        // not show the pre-boot answer.
        runCatching { ProtectionHealth.refresh(context.applicationContext) }
        return outcome
    }

    /**
     * The decision alone, with no side effects.
     *
     * Split out so the service can use it for a `START_STICKY` restart, where the platform has
     * already started the service and there is nothing to start from here — only a tunnel to
     * establish or a service to give up on.
     */
    fun decide(context: Context, trigger: RecoveryTrigger): RecoveryOutcome {
        val app = context.applicationContext
        return runCatching {
            AppSettings.initialize(app)
            val input = RecoveryInput(
                protectionWanted = AppSettings.current.protectionWanted,
                vpnPermission = vpnPermission(app),
                // Deliberately the *controller* state and not `ZShieldVpnService.instance`: the
                // service sets `instance` in `onCreate`, so including it would make a sticky restart
                // (whose caller is that very service) conclude "a tunnel is already up" and give up.
                // Measured on the Pixel 5 before this was fixed: the sticky start logged
                // `ALREADY_RUNNING` and only the periodic check brought the tunnel back.
                tunnelRunning = ZShieldVpnController.state.value is VpnState.Running ||
                    ZShieldVpnController.state.value is VpnState.Starting,
                alwaysOn = alwaysOn(app),
                trigger = trigger,
            )
            RecoveryPolicy.decide(input)
        }.getOrElse { error ->
            // A failed read is not a reason to claim protection: report the honest outcome, which
            // is "nothing was started" (docs/KEEPALIVE.md, 故障时的行为).
            Log.w(LOG_TAG, "recovery check failed ($trigger)", error)
            RecoveryOutcome.NO_VPN_PERMISSION
        }
    }

    /** `VpnService.prepare(context) == null`, reported as `false` if the call itself fails. */
    fun vpnPermission(context: Context): Boolean =
        runCatching { VpnService.prepare(context.applicationContext) == null }.getOrDefault(false)

    /**
     * Whether ZShield is the system's always-on VPN: `true` / `false` when the setting is readable,
     * `null` when it is not.
     *
     * A `null` is deliberately not treated as "yes": refusing to recover whenever the answer is
     * unknown would leave the app permanently off on builds that hide the key, which is a worse
     * failure than one redundant `establish` — and the service serialises starts anyway.
     */
    fun alwaysOn(context: Context): Boolean? = runCatching {
        Settings.Secure.getString(
            context.applicationContext.contentResolver,
            SETTING_ALWAYS_ON_VPN_APP,
        )
    }.getOrNull()?.let { app -> app == context.packageName }

    /** The persisted intent, for logging and diagnostics. */
    fun protectionWanted(context: Context): Boolean = runCatching {
        AppSettings.initialize(context.applicationContext)
        AppSettings.current.protectionWanted
    }.getOrDefault(false)
}
