package top.zztweb.zshield.health

import android.app.ActivityManager
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.PowerManager
import android.provider.Settings
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import top.zztweb.zshield.settings.AppSettings

/**
 * Protection health as a process-wide singleton (M4a task card §4).
 *
 * The signature is fixed by the task card because the self-check page is written against it: a
 * [StateFlow] of [HealthState], a [refresh], and [intentFor] mapping each [HealthItem] to the system
 * page that fixes it.
 *
 * Everything it reads is cheap and local — a `VpnService.prepare`, a few `Settings.Secure` reads, one
 * `UsageStatsManager` bucket lookup — so [refresh] is safe to call from a screen's `onResume` and
 * from the service after a tunnel start. It never starts work by itself: no polling, no timer, no
 * receiver. A health check that ran on its own schedule would be exactly the kind of background
 * wakeup `docs/DESIGN.md` decision 10 rules out.
 *
 * Reads that the platform refuses become `null` (see [HealthReader]) rather than exceptions; nothing
 * here throws for a missing permission, a hidden setting or an OEM build that answers differently.
 */
object ProtectionHealth {

    private const val LOG_TAG = "ZShield"

    /**
     * The always-on VPN settings are `Settings.Secure` keys the platform does not document as
     * readable by ordinary apps. On the Pixel 5 (A16) they read back fine; on builds where they do
     * not, both getters report `null` and the UI simply shows "unknown" instead of asserting
     * something wrong. See `docs/KEEPALIVE.md`.
     */
    private const val SETTING_ALWAYS_ON_VPN_APP = "always_on_vpn_app"
    private const val SETTING_ALWAYS_ON_VPN_LOCKDOWN = "always_on_vpn_lockdown"

    private val mutableState = MutableStateFlow(HealthState())

    /** Latest snapshot; the self-check page collects it. Empty defaults before the first refresh. */
    val state: StateFlow<HealthState> = mutableState.asStateFlow()

    /** Current snapshot without collecting. */
    val current: HealthState get() = mutableState.value

    /**
     * Re-reads every item and publishes the result.
     *
     * Called by the UI when a health screen appears and by the VPN service after it starts or is
     * revoked, so the snapshot is never stale by more than one user-visible event. Never throws: a
     * probe failure lands in the snapshot as the documented fallback.
     */
    fun refresh(context: Context) {
        val app = context.applicationContext
        AppSettings.initialize(app)
        val probe = AndroidHealthProbe(app)
        val next = HealthReader.read(probe, AppSettings.current.revokedBySystem)
        mutableState.value = next
    }

    /**
     * The system page that lets the user fix [item], or `null` when no such page exists on this
     * device.
     *
     * "Best effort" is the contract: the intents below are the documented ones, but an OEM may have
     * removed the activity behind one, and a caller that finds `null` (or an intent that will not
     * resolve) should fall back to [settingsRoot] rather than crash. Every returned intent carries
     * `FLAG_ACTIVITY_NEW_TASK`, because the caller may not be an Activity.
     */
    @Suppress("BatteryLife")
    fun intentFor(item: HealthItem, context: Context): Intent? {
        val packageUri = Uri.fromParts("package", context.packageName, null)
        val intent = when (item) {
            // The consent dialog is not reachable through an Intent; the caller has to run
            // `VpnService.prepare` and start the returned Intent. Pointing at the VPN page is the
            // closest a plain Intent gets, and it is where the user can also drop another VPN app
            // that holds the interface.
            HealthItem.VPN_PERMISSION, HealthItem.ALWAYS_ON, HealthItem.LOCKDOWN,
            HealthItem.REVOKED_BY_SYSTEM,
            -> Intent(Settings.ACTION_VPN_SETTINGS)

            // `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` is what shows the system's own "let this app
            // run in the background?" dialog instead of dropping the user into a list to hunt
            // through. Play restricts the permission to apps whose core function needs it; ZShield
            // is not distributed through Play (docs/DESIGN.md §3) and a VPN that Doze suspends is a
            // VPN that protects nothing. The user still has to confirm — the app cannot exempt
            // itself. `docs/KEEPALIVE.md` records the reasoning and the Play-policy caveat.
            HealthItem.BATTERY_OPTIMIZATIONS ->
                Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).setData(packageUri)

            // `ACTION_APP_NOTIFICATION_SETTINGS` and `EXTRA_APP_PACKAGE` are API 26; the app's
            // minSdk is 28, so there is no older branch to keep.
            HealthItem.NOTIFICATIONS ->
                Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                    .putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)

            HealthItem.BACKGROUND_RESTRICTIONS, HealthItem.STANDBY_BUCKET ->
                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).setData(packageUri)

            HealthItem.PRIVATE_DNS -> privateDnsSettings(context)
        }
        return intent
            ?.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            ?.takeIf { it.resolveActivity(context.packageManager) != null }
    }

    /**
     * The Private DNS page.
     *
     * Android has no public constant for it, so the platform action string is used first and the
     * documented wireless-settings page is the fallback. Both go through [intentFor]'s
     * `resolveActivity` check, so a build without either yields `null` and the UI can say "open
     * Settings yourself" honestly instead of launching nothing.
     */
    private fun privateDnsSettings(context: Context): Intent =
        Intent("android.settings.PRIVATE_DNS_SETTINGS")
            .takeIf { it.resolveActivity(context.packageManager) != null }
            ?: Intent(Settings.ACTION_WIRELESS_SETTINGS)

    /**
     * Root settings page, for a caller whose specific intent did not resolve.
     *
     * Kept here so the UI has one fallback that is known to exist rather than each screen inventing
     * its own.
     */
    fun settingsRoot(): Intent =
        Intent(Settings.ACTION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

    /** The Android-backed [HealthProbe] used by [refresh]. */
    private class AndroidHealthProbe(private val context: Context) : HealthProbe {

        override fun vpnPermission(): Boolean = VpnService.prepare(context) == null

        /**
         * `true` when the setting names this package, `false` when it names another or nothing at
         * all, `null` only when the platform refuses to answer.
         *
         * "The key is absent" is a real answer — no always-on VPN is configured — and must not be
         * confused with "this build hides the key": the first means the user still has to fix it, the
         * second means the UI cannot tell. `Settings.Secure.getString` returns `null` for an absent
         * key without throwing, so success-with-null maps to `false` and only a throw maps to `null`.
         */
        override fun alwaysOn(): Boolean? =
            runCatching { Settings.Secure.getString(context.contentResolver, SETTING_ALWAYS_ON_VPN_APP) }
                .getOrElse { return null }
                ?.let { app -> app == context.packageName }
                ?: false

        /** Same absent-vs-unreadable distinction as [alwaysOn]; an absent key means "off". */
        override fun lockdown(): Boolean? = try {
            Settings.Secure.getInt(context.contentResolver, SETTING_ALWAYS_ON_VPN_LOCKDOWN) != 0
        } catch (missing: Settings.SettingNotFoundException) {
            false
        } catch (error: Exception) {
            null
        }

        override fun ignoringBatteryOptimizations(): Boolean {
            val power = context.getSystemService(PowerManager::class.java) ?: return false
            return power.isIgnoringBatteryOptimizations(context.packageName)
        }

        override fun notificationsAllowed(): Boolean {
            val manager = context.getSystemService(NotificationManager::class.java) ?: return true
            return manager.areNotificationsEnabled()
        }

        override fun backgroundRestricted(): Boolean {
            val manager = context.getSystemService(ActivityManager::class.java) ?: return false
            return manager.isBackgroundRestricted
        }

        override fun standbyBucket(): Int? {
            val manager = context.getSystemService(android.app.usage.UsageStatsManager::class.java)
                ?: return null
            val bucket = manager.appStandbyBucket
            // `STANDBY_BUCKET_EXEMPTED` is 5 and `NEVER` is 50; both are real answers.
            return bucket.takeIf { it > 0 }
        }

        override fun privateDnsStrict(): Boolean {
            // `private_dns_mode` is `Settings.Global`; reading it needs no permission, and
            // `hostname` is the only mode that pins a resolver and so bypasses the tunnel's own.
            // A read that fails reports "not strict", which is the non-nagging answer.
            val mode = runCatching {
                Settings.Global.getString(context.contentResolver, "private_dns_mode")
            }.getOrNull()
            return mode == "hostname"
        }
    }
}
