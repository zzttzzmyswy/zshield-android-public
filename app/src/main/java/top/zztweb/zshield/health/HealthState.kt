package top.zztweb.zshield.health

/**
 * One system-level guarantee the user can act on.
 *
 * [ProtectionHealth.intentFor] turns each of these into the system settings page that fixes it; the
 * UI lists them as a checklist, so the names are the identity the UI keys on and are therefore part
 * of the contract (M4a task card §4).
 */
enum class HealthItem {
    /** The VPN consent dialog has been accepted and not revoked. */
    VPN_PERMISSION,

    /** ZShield is the system's "always-on VPN". */
    ALWAYS_ON,

    /** "Block connections without VPN" (lockdown) is on. */
    LOCKDOWN,

    /** The app is exempt from battery optimizations. */
    BATTERY_OPTIMIZATIONS,

    /** Notifications are allowed, which is what keeps the foreground service visible. */
    NOTIFICATIONS,

    /** The user did not restrict background work for this app. */
    BACKGROUND_RESTRICTIONS,

    /** The app is not in a low standby bucket that would defer its jobs. */
    STANDBY_BUCKET,

    /** System Private DNS is not in strict mode, which would bypass the tunnel's resolver. */
    PRIVATE_DNS,

    /** The system withdrew the VPN; the consent dialog has to be shown again. */
    REVOKED_BY_SYSTEM,
}

/**
 * The subset of system state that decides whether protection can actually run, as plain values.
 *
 * Every field is nullable-free here on purpose: this is the *probe*, whose methods may fail, and
 * [HealthReader] is what turns a failure into the `null` the UI sees. Keeping the two apart is what
 * makes "a failing system read must not crash the app" testable on the JVM.
 */
interface HealthProbe {
    /** True when `VpnService.prepare` has nothing to ask: consent is granted. */
    fun vpnPermission(): Boolean

    /** True/false when the always-on VPN setting is readable; `null` when it is not. */
    fun alwaysOn(): Boolean?

    /** True/false when the lockdown setting is readable; `null` when it is not. */
    fun lockdown(): Boolean?

    fun ignoringBatteryOptimizations(): Boolean

    fun notificationsAllowed(): Boolean

    fun backgroundRestricted(): Boolean

    fun standbyBucket(): Int?

    fun privateDnsStrict(): Boolean
}

/**
 * Snapshot of the protection health, as the UI consumes it (M4a task card §4 — the shape is fixed).
 *
 * A value the platform refuses to answer is `null`, never an exception and never a guess that would
 * make the UI nag: `null` means "unknown, go look", `false` means "the platform said no".
 */
data class HealthState(
    /** `VpnService.prepare(context) == null`. */
    val vpnPermission: Boolean = false,
    /** Whether this app is the system's always-on VPN; `null` when the setting is unreadable. */
    val alwaysOn: Boolean? = null,
    /** Whether "block connections without VPN" is on; `null` when unreadable. */
    val lockdown: Boolean? = null,
    val ignoringBatteryOptimizations: Boolean = false,
    val notificationsAllowed: Boolean = true,
    /** `ActivityManager.isBackgroundRestricted`. */
    val backgroundRestricted: Boolean = false,
    /** `UsageStatsManager.getAppStandbyBucket`; `null` when the platform refuses. */
    val standbyBucket: Int? = null,
    /** System Private DNS in strict mode, which resolves names outside the tunnel and bypasses it. */
    val privateDnsStrict: Boolean = false,
    /** The system withdrew the VPN (e.g. another VPN app took over); see `AppSettingsData`. */
    val revokedBySystem: Boolean = false,
) {
    /**
     * Everything the user must fix before protection can be trusted to run — the checklist the
     * self-check page shows, in the order the fixes matter.
     *
     * `null` values are *not* listed: an unreadable setting is not an action item, and prompting the
     * user to change something the app cannot even see would be noise.
     */
    val problems: List<HealthItem>
        get() = buildList {
            if (revokedBySystem) add(HealthItem.REVOKED_BY_SYSTEM)
            if (!vpnPermission) add(HealthItem.VPN_PERMISSION)
            if (alwaysOn == false) add(HealthItem.ALWAYS_ON)
            if (lockdown == false) add(HealthItem.LOCKDOWN)
            if (!ignoringBatteryOptimizations) add(HealthItem.BATTERY_OPTIMIZATIONS)
            if (!notificationsAllowed) add(HealthItem.NOTIFICATIONS)
            if (backgroundRestricted) add(HealthItem.BACKGROUND_RESTRICTIONS)
            if (standbyBucket != null && standbyBucket >= STANDBY_BUCKET_RARE) {
                add(HealthItem.STANDBY_BUCKET)
            }
            if (privateDnsStrict) add(HealthItem.PRIVATE_DNS)
        }

    /** True when nothing on the checklist is outstanding. */
    val healthy: Boolean get() = problems.isEmpty()

    companion object {
        /**
         * `UsageStatsManager.STANDBY_BUCKET_RARE` (40). A persisted constant rather than the real one
         * so [HealthState] stays a plain value type with no Android dependency.
         *
         * The comparison is `>=` because the bucket scale is ordered by *how much the app is
         * favoured*, not by severity: `EXEMPTED` (5) and `ACTIVE` (10) are the best answers and must
         * not be flagged, while `RARE` (40), `RESTRICTED` (45) and `NEVER` (50) are the ones that
         * defer the periodic self-check to roughly once a day.
         */
        const val STANDBY_BUCKET_RARE = 40
    }
}

/**
 * Runs every probe, converting failures into the documented "unknown" answer.
 *
 * The rule from the task card is "a value that cannot be read is `null`, never an exception": this
 * app's health screen must be able to say "I cannot tell" on an OEM build that hides a setting,
 * instead of crashing the page that is supposed to help the user fix things. Each catch below
 * therefore has a chosen fallback, and each fallback is the answer that makes the UI say the least
 * wrong thing:
 *
 * - a failed VPN-permission read reports `false`: the consent dialog is the safe next step;
 * - failed "do I nag about this" reads report the non-nagging value (`notificationsAllowed = true`,
 *   `backgroundRestricted = false`, `privateDnsStrict = false`);
 * - failed settings reads report `null` where the type allows it.
 */
object HealthReader {

    fun read(probe: HealthProbe, revokedBySystem: Boolean): HealthState = HealthState(
        vpnPermission = runCatching { probe.vpnPermission() }.getOrDefault(false),
        alwaysOn = runCatching { probe.alwaysOn() }.getOrNull(),
        lockdown = runCatching { probe.lockdown() }.getOrNull(),
        ignoringBatteryOptimizations =
            runCatching { probe.ignoringBatteryOptimizations() }.getOrDefault(false),
        notificationsAllowed = runCatching { probe.notificationsAllowed() }.getOrDefault(true),
        backgroundRestricted = runCatching { probe.backgroundRestricted() }.getOrDefault(false),
        standbyBucket = runCatching { probe.standbyBucket() }.getOrNull(),
        privateDnsStrict = runCatching { probe.privateDnsStrict() }.getOrDefault(false),
        revokedBySystem = revokedBySystem,
    )
}
