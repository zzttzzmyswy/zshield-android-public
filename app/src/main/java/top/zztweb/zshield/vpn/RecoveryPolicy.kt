package top.zztweb.zshield.vpn

/**
 * What asked the tunnel to come back, without the user acting.
 *
 * A user tap does not appear here on purpose: it goes through `ZShieldVpnController.start`, which
 * always starts filtering and is the only thing allowed to *write* the persisted intent. These
 * triggers, by contrast, only ever *read* it — which is why the distinction exists at all.
 */
enum class RecoveryTrigger {
    /** `START_STICKY`: the process was killed and the system restarted the service. */
    SERVICE_RESTART,

    /** `BOOT_COMPLETED` after a reboot. */
    BOOT,

    /** `MY_PACKAGE_REPLACED` after an in-place upgrade. */
    PACKAGE_REPLACED,

    /** The periodic `JobScheduler` self-check found the tunnel missing. */
    PERIODIC_CHECK,
}

/**
 * Everything the recovery decision depends on, as plain values.
 *
 * Kept free of Android types so the whole decision table can be exercised on the JVM
 * (`RecoveryPolicyTest`); [ProtectionRecovery] is the thin Android-facing wrapper that reads them.
 */
data class RecoveryInput(
    /** `AppSettings.protectionWanted`: the user's last explicit intent. */
    val protectionWanted: Boolean,
    /** `VpnService.prepare(context) == null`: consent has been granted at least once and not revoked. */
    val vpnPermission: Boolean,
    /** The tunnel is already up in this process. */
    val tunnelRunning: Boolean,
    /**
     * Whether this app is the system's always-on VPN. `null` when the setting cannot be read
     * (the secure setting is not readable for a non-system app on some builds), which is treated
     * as "unknown, not confirmed always-on" — recovery is still attempted, because refusing to
     * recover on a `null` would leave the app permanently off on exactly those builds.
     */
    val alwaysOn: Boolean?,
    val trigger: RecoveryTrigger,
)

/** Why recovery did or did not run. */
enum class RecoveryOutcome {
    /** Start the tunnel. */
    RECOVER,

    /** Protection is off because the user turned it off; nothing to do. */
    USER_TURNED_OFF,

    /** A tunnel is already up; establishing a second interface would fight the first one. */
    ALREADY_RUNNING,

    /** No VPN consent: only the system dialog can fix that, so recovery would just fail. */
    NO_VPN_PERMISSION,

    /** The system owns the tunnel's lifecycle (always-on VPN); starting it ourselves would race it. */
    MANAGED_BY_SYSTEM,
}

/**
 * The decision table for automatic recovery (`docs/DESIGN.md` §7, `docs/KEEPALIVE.md`).
 *
 * Two rules are load-bearing and each has a test:
 *
 * 1. **Intent beats everything.** Automatic recovery only ever runs when
 *    [RecoveryInput.protectionWanted] is true. That value is written by user actions alone, so
 *    "the user paused protection" survives a kill, a reboot and an upgrade without any of them
 *    being able to start filtering again behind the user's back.
 * 2. **The system's always-on VPN wins.** When the user has configured ZShield as the always-on
 *    VPN, the platform starts the service itself, including at boot. Racing it would establish two
 *    interfaces, and the loser of that race is the interface the user's traffic is on.
 *
 * Every other combination recovers: a missing tunnel with a live intent is exactly the failure this
 * milestone exists to fix, and the remaining inputs only make the attempt cheaper or pointless.
 */
object RecoveryPolicy {

    /**
     * Decides whether this trigger should establish the tunnel.
     *
     * The order of the checks is the precedence: intent, then "already done", then consent, then the
     * system's ownership. Checking consent before "already running" would report a stale reason for
     * a tunnel that is up and working, which is what the UI shows.
     */
    fun decide(input: RecoveryInput): RecoveryOutcome = when {
        !input.protectionWanted -> RecoveryOutcome.USER_TURNED_OFF
        input.tunnelRunning -> RecoveryOutcome.ALREADY_RUNNING
        !input.vpnPermission -> RecoveryOutcome.NO_VPN_PERMISSION
        input.alwaysOn == true -> RecoveryOutcome.MANAGED_BY_SYSTEM
        else -> RecoveryOutcome.RECOVER
    }
}
