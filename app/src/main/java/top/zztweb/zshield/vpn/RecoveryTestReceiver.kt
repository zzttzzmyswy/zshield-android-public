package top.zztweb.zshield.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Process
import android.util.Log

/**
 * Test seam for `docs/DESIGN.md` §7 scenario 3: "`am kill` / low-memory kill, then automatic
 * recovery, with the recovery time recorded".
 *
 * # Why this exists
 *
 * Scenario 3 asks for a *process death* on a device whose adb shell cannot produce one:
 *
 * - `adb shell am kill <pkg>` only kills **background** processes, so a process holding a foreground
 *   service is skipped by design (verified on the Pixel 5: `pidof` is unchanged afterwards);
 * - `adb shell kill -9 <pid>` is refused (`Operation not permitted`) because the shell uid is not the
 *   app's uid;
 * - enabling root debugging to get around that restarts `adbd`, which on this device **would drop the
 *   Wi-Fi adb connection** — the one thing `AGENTS.md` forbids.
 *
 * So the app signals its own death with [Process.killProcess], which sends the same `SIGKILL` to the
 * same pid. From ActivityManager's point of view that is indistinguishable from a low-memory kill: a
 * process death with no Java exception, so the `START_STICKY` restart path runs exactly as it would
 * in production — no "app crashed" dialog, no bad-process marking.
 *
 * # Why it is safe to ship
 *
 * Guarded by `android.permission.DUMP`, the same signature|privileged|development permission the
 * existing `DebugCommandReceiver` uses: the adb shell holds it and no ordinary third-party app can
 * obtain it, so this cannot be used to kill the process of a running protector. It also cannot turn
 * protection *off*: killing the process leaves `protectionWanted` untouched, and that is the point.
 */
class RecoveryTestReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            ACTION_KILL -> {
                // The settings must be on disk before the process dies: the recovery decision reads
                // them in a fresh process, and an unflushed write would look like "the user turned
                // protection off".
                val wanted = ProtectionRecovery.protectionWanted(context)
                Log.i(
                    LOG_TAG,
                    "SIGKILL on request (protectionWanted=$wanted, pid=${Process.myPid()}); " +
                        "START_STICKY should restore the tunnel",
                )
                Process.killProcess(Process.myPid())
            }

            ACTION_CHECK -> {
                // Runs the periodic decision now, so a device test does not have to wait up to
                // 15 minutes for the JobScheduler window. Exactly the code path
                // `KeepAliveJobService.onStartJob` takes.
                val outcome = ProtectionRecovery.recover(context, RecoveryTrigger.PERIODIC_CHECK)
                Log.i(LOG_TAG, "periodic check on request -> $outcome")
            }
        }
    }

    companion object {
        private const val LOG_TAG = "ZShield"

        /** `adb shell am broadcast -a top.zztweb.zshield.action.DEBUG_SUICIDE -n <pkg>/.vpn.RecoveryTestReceiver` */
        const val ACTION_KILL = "top.zztweb.zshield.action.DEBUG_SUICIDE"

        /** Runs one periodic self-check immediately (`docs/TESTING.md` §11). */
        const val ACTION_CHECK = "top.zztweb.zshield.action.DEBUG_KEEPALIVE_CHECK"
    }
}
