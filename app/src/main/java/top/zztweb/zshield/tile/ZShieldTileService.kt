package top.zztweb.zshield.tile

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Log
import top.zztweb.zshield.R
import top.zztweb.zshield.settings.AppSettings
import top.zztweb.zshield.ui.MainActivity
import top.zztweb.zshield.vpn.VpnState
import top.zztweb.zshield.vpn.ZShieldVpnController

/**
 * Quick Settings tile: shows whether filtering is running and toggles it (M4a task card §3).
 *
 * # What it is for
 *
 * The tile is the shortest way for the user to express intent in either direction without opening
 * the app, which is what makes `AppSettings.protectionWanted` trustworthy: a user who wants
 * protection off can say so in one tap, and a user whose tunnel was killed can ask for it back in
 * one tap. A tap is also a user action, which is what makes starting a foreground service from the
 * background legitimate on Android 12+ (`docs/KEEPALIVE.md`).
 *
 * # States
 *
 * - filtering running → `ACTIVE`;
 * - otherwise → `INACTIVE`. There is deliberately no "on but not running" state: a tile that looks
 *   on while nothing is filtered is the exact dishonesty this milestone exists to remove, and the
 *   self-check page (`ProtectionHealth`) is where the reason is shown in detail.
 *
 * # Permission and lock screen
 *
 * Tapping without VPN consent opens the app, because the consent dialog can only be shown by an
 * Activity. On a locked device the work is deferred through [unlockAndRun] instead of failing
 * quietly — a tile tap on the lock screen is a normal thing to do.
 */
class ZShieldTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        AppSettings.initialize(applicationContext)
        render()
    }

    override fun onClick() {
        super.onClick()
        AppSettings.initialize(applicationContext)
        if (isLocked) {
            unlockAndRun { toggle() }
            return
        }
        toggle()
    }

    private fun toggle() {
        when (ZShieldVpnController.state.value) {
            is VpnState.Running, is VpnState.Starting -> {
                // A user action, so this is one of the places allowed to clear the intent:
                // `ZShieldVpnController.stop` records "protection off" before stopping the service.
                ZShieldVpnController.stop(this)
                Log.i(LOG_TAG, "tile: paused protection")
            }
            else -> {
                if (!hasVpnPermission()) {
                    openApp()
                    return
                }
                ZShieldVpnController.start(this)
                Log.i(LOG_TAG, "tile: requested protection")
            }
        }
        // Starting and stopping both go through the service asynchronously; render what is known
        // now, and `onStartListening` re-renders on the next pull-down.
        render()
    }

    /**
     * Whether `VpnService.prepare` has nothing left to ask.
     *
     * Calling `prepare` from the tile is safe — it only builds a consent Intent when consent is
     * missing — and a non-null result means the tile cannot do the job itself.
     */
    private fun hasVpnPermission(): Boolean =
        runCatching { VpnService.prepare(this) == null }.getOrDefault(false)

    /** Opens the app, which is where the consent dialog lives. */
    private fun openApp() {
        val launch = {
            runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    startActivityAndCollapse(
                        PendingIntent.getActivity(
                            this,
                            0,
                            activityIntent(),
                            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                        ),
                    )
                } else {
                    startActivityAndCollapseLegacy()
                }
            }
        }
        if (isLocked) unlockAndRun { launch() } else launch()
    }

    private fun activityIntent(): Intent =
        Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

    /**
     * The pre-34 way to open the app from a tile.
     *
     * The `Intent` overload is deprecated from API 34 in favour of the `PendingIntent` one, which
     * does not exist below it, so the two cannot be collapsed into one call. The suppression is
     * limited to this method: on the releases it is called for, it is the only API there is.
     */
    @Suppress("DEPRECATION", "StartActivityAndCollapseDeprecated")
    private fun startActivityAndCollapseLegacy() {
        startActivityAndCollapse(activityIntent())
    }

    private fun render() {
        val tile = qsTile ?: return
        tile.state = if (ZShieldVpnController.state.value is VpnState.Running) {
            Tile.STATE_ACTIVE
        } else {
            Tile.STATE_INACTIVE
        }
        tile.label = getString(R.string.tile_label)
        // `subtitle` exists from API 29; below that the label alone is shown.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = getString(
                if (tile.state == Tile.STATE_ACTIVE) {
                    R.string.tile_subtitle_on
                } else {
                    R.string.tile_subtitle_off
                },
            )
        }
        tile.icon = Icon.createWithResource(this, R.drawable.ic_tile_shield)
        runCatching { tile.updateTile() }
            .onFailure { Log.w(LOG_TAG, "cannot update tile", it) }
    }

    private companion object {
        const val LOG_TAG = "ZShield"
    }
}
