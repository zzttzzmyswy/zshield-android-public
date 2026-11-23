package top.zztweb.zshield.filters

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.os.Build
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Periodic filter-list updates on the platform [JobScheduler].
 *
 * Why JobScheduler and not WorkManager (`docs/DESIGN.md` fixed decision 8): the app ships no
 * AndroidX WorkManager, no Room and no Play Services, and this job needs nothing WorkManager adds —
 * it is one periodic wakeup that runs a download. JobScheduler also has the property we want from a
 * battery standpoint: the system batches it with other jobs and will not run it while the device is
 * in Doze, so a 24 h interval costs essentially nothing.
 *
 * The job is persisted (`setPersisted(true)`) so it survives a reboot without a boot receiver.
 */
class FilterUpdateJobService : JobService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onStartJob(params: JobParameters?): Boolean {
        // Return `true`: the work continues on another thread and the system keeps the wakelock
        // until `jobFinished`.
        scope.launch {
            try {
                FilterRepository.initialize(applicationContext)
                FilterRepository.updateAll(force = false)
            } catch (error: Exception) {
                android.util.Log.w("ZShield", "periodic filter update failed", error)
            } finally {
                jobFinished(params, false)
            }
        }
        return true
    }

    override fun onStopJob(params: JobParameters?): Boolean {
        // The system is taking the job back (constraints no longer met, or a newer job replaced it).
        // Nothing was persisted per-list until it finished, so returning `true` to ask for a retry is
        // correct and cheap: the next run simply resumes where this one stopped.
        scope.cancel()
        return true
    }
}

/**
 * Registers and updates the periodic update job.
 *
 * All of it is in one object so the schedule lives in exactly one place: the repository saves the
 * user's interval and calls [schedule], and nothing else ever builds a [JobInfo].
 */
object AutoUpdateScheduler {

    /** Job id. Stable so rescheduling replaces the previous job instead of adding a second one. */
    const val JOB_ID = 4_201

    /**
     * (Re)schedule the periodic update.
     *
     * @param intervalHours the user's choice, in hours.
     * @param unmeteredOnly when true the job only runs on unmetered networks.
     */
    fun schedule(context: Context, intervalHours: Int, unmeteredOnly: Boolean) {
        val scheduler = context.getSystemService(JobScheduler::class.java) ?: return
        scheduler.cancel(JOB_ID)

        val intervalMs = intervalHours.coerceIn(
            FilterState.MIN_INTERVAL_HOURS,
            FilterState.MAX_INTERVAL_HOURS,
        ) * 60L * 60L * 1000L

        val component = ComponentName(context, FilterUpdateJobService::class.java)
        val builder = JobInfo.Builder(JOB_ID, component)
            .setRequiredNetworkType(
                if (unmeteredOnly) {
                    JobInfo.NETWORK_TYPE_UNMETERED
                } else {
                    JobInfo.NETWORK_TYPE_ANY
                }
            )
            // A periodic job's minimum period on Android is 15 minutes; anything shorter is
            // silently clamped by the framework, so clamp here to keep the two in agreement.
            .setPeriodic(intervalMs.coerceAtLeast(JobInfo.getMinPeriodMillis()))
            .setPersisted(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            // A filter-list download is not urgent; running it in the background job bucket is
            // exactly what the platform's grouping is for.
            builder.setPrefetch(false)
        }
        // Scheduling must never take the app down: this runs from `Application.onCreate`, so an
        // exception here would kill the process. The two realistic failures are a missing
        // RECEIVE_BOOT_COMPLETED permission (persisted job) and an OEM scheduler that refuses —
        // both degrade to "no periodic update", which is far better than a crash loop.
        val result = runCatching { scheduler.schedule(builder.build()) }.getOrElse { error ->
            android.util.Log.w("ZShield", "cannot schedule filter update job", error)
            return
        }
        if (result != JobScheduler.RESULT_SUCCESS) {
            android.util.Log.w("ZShield", "cannot schedule filter update job: result=$result")
        }
    }

    /** Cancel the periodic update (used when the user turns automatic updates off). */
    fun cancel(context: Context) {
        context.getSystemService(JobScheduler::class.java)?.cancel(JOB_ID)
    }

    /** Whether a job with our id is currently registered. Used by the debug screen. */
    fun isScheduled(context: Context): Boolean =
        context.getSystemService(JobScheduler::class.java)
            ?.allPendingJobs
            ?.any { it.id == JOB_ID } == true
}
