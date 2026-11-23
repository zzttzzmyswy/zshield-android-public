package top.zztweb.zshield

import android.app.Application
import top.zztweb.zshield.core.Native
import top.zztweb.zshield.filters.AutoUpdateScheduler
import top.zztweb.zshield.filters.FilterRepository
import top.zztweb.zshield.health.ProtectionHealth
import top.zztweb.zshield.https.CertManager
import top.zztweb.zshield.https.OwnerResolver
import top.zztweb.zshield.settings.AppSettings
import top.zztweb.zshield.vpn.KeepAliveJobService

/**
 * Application entry point.
 *
 * It does as little as possible: the native certificate verifier is initialised here so the very
 * first TLS connection can validate against the Android trust store, and the core is told to
 * release any engine when the process is being torn down. There is no analytics, no crash reporter
 * and no third-party SDK in this app (`docs/DESIGN.md` §3, §11).
 */
class ZShieldApp : Application() {

    private var startedActivities = 0

    override fun onCreate() {
        super.onCreate()
        // Cheap and idempotent; safe to call before any tunnel exists.
        Native.init(this)

        // A VPN foreground service can keep onTrimMemory(UI_HIDDEN) pending indefinitely.
        // Count our visible activities instead, so ordinary Home/Back releases unused pages.
        registerActivityLifecycleCallbacks(object : ActivityLifecycleCallbacks {
            override fun onActivityStarted(activity: android.app.Activity) {
                startedActivities++
            }

            override fun onActivityStopped(activity: android.app.Activity) {
                startedActivities--
                if (startedActivities == 0 && !activity.isChangingConfigurations) {
                    Native.trimMemory()
                }
            }

            override fun onActivityCreated(activity: android.app.Activity, state: android.os.Bundle?) = Unit
            override fun onActivityResumed(activity: android.app.Activity) = Unit
            override fun onActivityPaused(activity: android.app.Activity) = Unit
            override fun onActivitySaveInstanceState(activity: android.app.Activity, state: android.os.Bundle) = Unit
            override fun onActivityDestroyed(activity: android.app.Activity) = Unit
        })

        // Load the catalog and persisted filter state, and schedule the periodic update job. Both
        // are cheap (one asset read, one small JSON file) and must happen before the VPN service can
        // be started, so the first tunnel already has a `compiledDir` to load from.
        // Both steps are wrapped: a failure to load the catalog or schedule the job must degrade to
        // "filtering with whatever rules exist", never to a process that cannot start.
        runCatching { FilterRepository.initialize(this) }
            .onFailure { android.util.Log.e("ZShield", "filter repository init failed", it) }
        // Tunnel settings are read by the VPN service and written by the UI; loading them once here
        // means both see the same StateFlow from the very start of the process.
        runCatching { AppSettings.initialize(this) }
            .onFailure { android.util.Log.e("ZShield", "settings init failed", it) }
        // The HTTPS decision needs the owning application of a connection, which is answered through
        // this resolver from a tokio worker thread (`docs/JNI.md` §7). It needs the app context, so it
        // is set here rather than lazily on the first lookup.
        runCatching { OwnerResolver.initialize(this) }
            .onFailure { android.util.Log.e("ZShield", "owner resolver init failed", it) }
        // Loading the CA here means the UI can show its fingerprint and install state before the
        // tunnel is ever started.
        runCatching { CertManager.initialize(this) }
            .onFailure { android.util.Log.e("ZShield", "cert manager init failed", it) }
        runCatching {
            AutoUpdateScheduler.schedule(
                this,
                FilterRepository.autoUpdateHours(),
                FilterRepository.autoUpdateUnmeteredOnly(),
            )
        }.onFailure { android.util.Log.e("ZShield", "cannot schedule auto update", it) }
        // The periodic protection self-check (M4a). Idempotent, cheap, and the only thing that brings
        // filtering back if a kill or a reboot is followed by no boot broadcast — see
        // `KeepAliveJobService`.
        runCatching { KeepAliveJobService.schedule(this) }
            .onFailure { android.util.Log.e("ZShield", "cannot schedule keep-alive check", it) }
        // Give the self-check page its first snapshot before any screen asks for one. Cheap local
        // reads only; a failure leaves the documented defaults in place.
        runCatching { ProtectionHealth.refresh(this) }
            .onFailure { android.util.Log.e("ZShield", "health refresh failed", it) }
    }

    override fun onTerminate() {
        Native.releaseAll()
        super.onTerminate()
    }
}
