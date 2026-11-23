package top.zztweb.zshield.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Restores protection after a reboot or an in-place upgrade (M4a, `docs/DESIGN.md` §7 scenarios 4
 * and 5).
 *
 * # Why these three actions
 *
 * - `BOOT_COMPLETED`: the device finished booting and the user is at the lock screen. This is the
 *   documented window in which a background app may start a foreground service.
 * - `LOCKED_BOOT_COMPLETED`: sent earlier, while the credential-encrypted storage is still locked.
 *   ZShield's settings live in `filesDir` (credential-encrypted), so a start attempt here would read
 *   defaults and could decide "protection was not wanted". It is therefore *not* handled; waiting for
 *   `BOOT_COMPLETED` costs a few seconds and reads the real intent. `docs/KEEPALIVE.md` records the
 *   finding and what direct boot would require.
 * - `MY_PACKAGE_REPLACED`: our own package was replaced, which on Android stops the running service
 *   for the same uid. Without this the tunnel stays down until the user opens the app.
 *
 * # Why a foreground service type is allowed from here
 *
 * The Android 15+ restriction on launching foreground services from a `BOOT_COMPLETED` receiver
 * covers `dataSync`, `camera`, `mediaPlayback`, `phoneCall`, `mediaProjection` and `microphone`.
 * `systemExempted` — the type this app declares — is not on that list, and the "Background start
 * restrictions" exemption list names `BOOT_COMPLETED`, `LOCKED_BOOT_COMPLETED` and
 * `MY_PACKAGE_REPLACED` explicitly. The Pixel 5 (A16) logs in `docs/KEEPALIVE.md` confirm it.
 *
 * # Why it does not start the tunnel itself
 *
 * The decision belongs to [ProtectionRecovery]: a broadcast must respect the same intent, consent
 * and always-on rules as every other recovery path, and in particular must do nothing when the user
 * switched protection off before the reboot.
 */
class BootRestoreReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        val trigger = when (action) {
            Intent.ACTION_BOOT_COMPLETED -> RecoveryTrigger.BOOT
            Intent.ACTION_MY_PACKAGE_REPLACED -> RecoveryTrigger.PACKAGE_REPLACED
            else -> {
                // Not ours (the manifest filter is the only guard) — say so and stop, rather than
                // falling through to a start nothing asked for.
                Log.i(LOG_TAG, "boot receiver ignoring $action")
                return
            }
        }
        // The check reads settings and maybe sends one start intent; it must never take the process
        // down inside a broadcast callback, and `recover` already guarantees that. The receiver
        // itself returns immediately: `goAsync` would only be needed for work that outlives
        // `onReceive`, and the tunnel start is asynchronous on its own.
        Log.i(LOG_TAG, "restore after $action")
        ProtectionRecovery.recover(context, trigger)
        // A persisted job survives a reboot, but the platform forgets it when the app is force-
        // stopped or when the data directory is cleared; re-registering is idempotent and makes the
        // self-check independent of that bookkeeping.
        runCatching { KeepAliveJobService.schedule(context) }
    }

    private companion object {
        const val LOG_TAG = "ZShield"
    }
}
