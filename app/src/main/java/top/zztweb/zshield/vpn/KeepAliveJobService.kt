package top.zztweb.zshield.vpn

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.util.Log

/**
 * The periodic protection self-check (M4a: "JobScheduler 周期自检，只在应开未开时拉起").
 *
 * # Why a job and not a timer
 *
 * The platform batches [JobScheduler] work with everything else it has to do anyway and will not run
 * it inside Doze, so a 15-minute period costs one deferred check per window instead of a wakeup
 * every 15 minutes (`docs/DESIGN.md` decision 10). A `Handler`/`AlarmManager` loop would do the
 * opposite: it would run while the device is idle and hold a wakeup for a decision that is almost
 * always "nothing to do".
 *
 * # What it does
 *
 * Nothing but a [ProtectionRecovery] check. It returns `false` from [onStartJob] because there is no
 * work to continue on another thread — the decision reads a few settings and, in the one case that
 * matters, sends one start intent. It never downloads, never compiles, never touches the network.
 *
 * The job is persisted so it survives a reboot; [schedule] is idempotent, so the application, the
 * recovery receiver and the settings screen can all call it.
 */
class KeepAliveJobService : JobService() {

    override fun onStartJob(params: JobParameters?): Boolean {
        try {
            ProtectionRecovery.recover(applicationContext, RecoveryTrigger.PERIODIC_CHECK)
        } catch (error: Throwable) {
            // Recovery already swallows its own failures; this is the last line before the process
            // would die inside a platform callback.
            Log.w(LOG_TAG, "periodic keep-alive check failed", error)
        }
        // `true` would mean "work continues in the background"; it does not, so tell the platform
        // the job is done rather than making it hold a wakelock for nothing.
        jobFinished(params, false)
        return false
    }

    override fun onStopJob(params: JobParameters?): Boolean {
        // The system took the job back before it ran (constraints unmet, or a replacement). Ask for
        // a retry: the check is cheap, and missing a window is exactly the "protection stayed off"
        // outcome this job exists to prevent.
        return true
    }

    companion object {
        private const val LOG_TAG = "ZShield"

        /** Stable id, so rescheduling replaces the job instead of registering a second one. */
        const val JOB_ID = 4_202

        /**
         * How often the self-check runs.
         *
         * 15 minutes is the platform minimum for a periodic job; asking for less is silently
         * clamped, so this is both the floor and the intended value. `docs/KEEPALIVE.md` records
         * that the platform may stretch it under Doze — which is fine, because a tunnel that died
         * during a Doze window cannot be used by anything either.
         */
        const val PERIOD_MINUTES = 15L

        /**
         * Registers the check, replacing any previous registration.
         *
         * No network constraint: the check does not use the network, and a `NETWORK_TYPE_ANY`
         * constraint would only delay it for no benefit. Not `setExpedited` either — an expedited
         * job earns a quota, and there is nothing here urgent enough to spend it on.
         */
        fun schedule(context: Context) {
            val scheduler = context.applicationContext
                .getSystemService(JobScheduler::class.java) ?: return
            val component = ComponentName(
                context.applicationContext.packageName,
                KeepAliveJobService::class.java.name,
            )
            val job = JobInfo.Builder(JOB_ID, component)
                .setPeriodic(PERIOD_MINUTES * 60_000L)
                .setPersisted(true)
                .build()
            // Same contract as AutoUpdateScheduler: a scheduler that refuses must degrade to "no
            // periodic check", never to a crash in Application.onCreate.
            val result = runCatching { scheduler.schedule(job) }.getOrElse { error ->
                Log.w(LOG_TAG, "cannot schedule keep-alive check", error)
                return
            }
            if (result != JobScheduler.RESULT_SUCCESS) {
                Log.w(LOG_TAG, "cannot schedule keep-alive check: result=$result")
            }
        }

        /** Cancels the check; used by `scripts/build.sh`-driven tests and by the debug screen. */
        fun cancel(context: Context) {
            context.applicationContext.getSystemService(JobScheduler::class.java)?.cancel(JOB_ID)
        }

        /** Whether the check is currently registered. Used by the device tests in `docs/TESTING.md`. */
        fun isScheduled(context: Context): Boolean =
            context.applicationContext.getSystemService(JobScheduler::class.java)
                ?.allPendingJobs
                ?.any { it.id == JOB_ID } == true
    }
}
